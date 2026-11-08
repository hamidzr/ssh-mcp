import { describe, it, expect, beforeAll } from 'vitest';
import { spawn } from 'child_process';
import { join } from 'path';
import { SSHConnectionManager, execSshCommandWithConnection } from '../src/index';

// Very small, focused tests for the sudo-exec MCP tool. This file is intentionally
// small and straightforward (no heavy debug plumbing) — the integration surface
// is: start the MCP server in test mode, send an initialize request, then call
// the sudo-exec tool and assert the returned JSON-RPC response.

const testServerPath = join(process.cwd(), 'build', 'index.js');
const START_TIMEOUT = 10000;  // 10 seconds for server startup with su elevation

beforeAll(() => {
  process.env.SSH_MCP_TEST = '1';
});

function runMcpCommand(command: string, extraArgs: string[] = [], toolName = 'sudo-exec'): Promise<any> {
  const args = [
    testServerPath,
    '--host=127.0.0.1',
    '--port=2222',
    '--user=test',
    '--password=secret',
    '--timeout=60000',
    ...extraArgs,
  ];

  return new Promise((resolve, reject) => {
    const child = spawn('node', args, { stdio: ['pipe', 'pipe', 'pipe'], env: { ...process.env, SSH_MCP_TEST: '1' } });
    let buffer = '';
    const startup = setTimeout(() => {
      child.kill();
      reject(new Error('Server start timeout'));
    }, START_TIMEOUT);

    const initMsg = { jsonrpc: '2.0', id: 0, method: 'initialize', params: { capabilities: {}, clientInfo: { name: 't', version: '1' }, protocolVersion: '0.1.0' } };
    const toolCall = { jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name: toolName, arguments: { command } } };

    child.stdout.on('data', (d) => {
      buffer += d.toString();
      const lines = buffer.split('\n');
      buffer = lines.pop() || '';
      for (const line of lines) {
        try {
          const msg = JSON.parse(line);
          if (msg.id === 0) {
            child.stdin.write(JSON.stringify(toolCall) + '\n');
          } else if (msg.id === 1) {
            clearTimeout(startup);
            resolve(msg);
            child.kill();
            return;
          }
        } catch (e) {
          // ignore non-json
        }
      }
    });

    child.stderr.on('data', () => { /* ignore */ });
    child.on('error', (err) => { clearTimeout(startup); reject(err); });

    // Give the server a moment to initialize before sending messages
    setTimeout(() => {
      child.stdin.write(JSON.stringify(initMsg) + '\n');
    }, 100);
  });
}

// Helper that runs a command using the server's `--suPassword` option.
// It establishes an elevated su session at connection time so all commands run as root.
function runSuMcpCommand(command: string, suPassword = 'secret', extraArgs: string[] = []): Promise<any> {
  return runMcpCommand(command, [`--suPassword=${suPassword}`, ...extraArgs], 'exec');
}

describe('sudo-exec tool authentication', () => {
  // Set up the su environment before running tests that need it
  beforeAll(async () => {
    // First make su setuid root
    const suSetup = await runMcpCommand('chmod u+s /bin/su', ['--sudoPassword=secret']);
    expect(suSetup.error).toBeUndefined();

    // Then set the root password to 'secret'
    const passwdSetup = await runMcpCommand('echo "secret" | passwd --stdin', ['--sudoPassword=secret']);
    expect(passwdSetup.error).toBeUndefined();
  });

  it('should execute commands with su elevation after sudo setup', async () => {
    // First verify we can use su now by checking if we can become root
    const whoami = await runMcpCommand('whoami && echo "secret" | su -c whoami', ['--sudoPassword=secret']);
    expect(whoami.error).toBeUndefined();
    const output = (whoami.result?.content?.[0]?.text || '').toLowerCase();
    expect(output).toContain('root');
    
    // Now try creating a root-owned directory
    const mkdir = await runMcpCommand('echo "secret" | su -c "mkdir -p /root/test_dir"', ['--sudoPassword=secret']);
    expect(mkdir.error).toBeUndefined();
    
    // Verify we can access it
    const ls = await runMcpCommand('ls -la /root/test_dir', ['--sudoPassword=secret']);
    expect(ls.error).toBeUndefined();
    expect(ls.result?.content?.[0]?.text).toBeTruthy();

    // Clean up
    const cleanup = await runMcpCommand('rm -rf /root/test_dir', ['--sudoPassword=secret']);
    expect(cleanup.error).toBeUndefined();
  }, 60000); // Increased timeout for su operations

  it('executes su when provided --suPassword', async () => {
    const res = await runSuMcpCommand('whoami', 'secret');
    expect(res.error).toBeUndefined();
    // exact match: no pty echo or prompt noise in the output
    expect(res.result?.content?.[0]?.text).toBe('root\n');
  }, 60000);

  // regression: the su pty echoed the marker printf, which used to stall marker parsing until timeout
  it('runs several commands in one su shell with clean output and exit codes', async () => {
    const manager = new SSHConnectionManager({
      host: '127.0.0.1', port: 2222, username: 'test', password: 'secret', suPassword: 'secret',
    });
    try {
      await manager.connect();
      await manager.ensureElevated();

      const whoami = await manager.executeCommand('whoami', undefined, 5000);
      expect(whoami).toEqual({ stdout: 'root\n', stderr: '', code: 0 });

      const noNewline = await manager.executeCommand("printf 'a b'", undefined, 5000);
      expect(noNewline).toEqual({ stdout: 'a b', stderr: '', code: 0 });

      const multiLine = await execSshCommandWithConnection(manager, 'echo one\necho two', undefined, 5000);
      expect((multiLine.content[0] as any).text).toBe('one\ntwo\n');

      const failed = await manager.executeCommand('false', undefined, 5000);
      expect(failed.code).toBe(1);

      // same shell as exec mode, not root's interactive login shell
      const shell = await manager.executeCommand('echo "${BASH_VERSION:+bash}"', undefined, 5000);
      expect(shell.stdout).toBe('bash\n');

      // the raw pty has no canonical-mode line length limit (~4 KB)
      const long = await manager.executeCommand(`echo ${'x'.repeat(5000)} | wc -c`, undefined, 5000);
      expect(long.stdout.trim()).toBe('5001');
    } finally {
      manager.close();
    }
  }, 30000);

  it('re-elevates after the root shell exits instead of falling back to the login user', async () => {
    const manager = new SSHConnectionManager({
      host: '127.0.0.1', port: 2222, username: 'test', password: 'secret', suPassword: 'secret',
    });
    try {
      await manager.connect();
      await manager.ensureElevated();
      await expect(manager.executeCommand('exit 0', undefined, 5000)).rejects.toThrow(/su shell closed/);

      await manager.ensureElevated();
      const whoami = await manager.executeCommand('whoami', undefined, 5000);
      expect(whoami.stdout).toBe('root\n');
    } finally {
      manager.close();
    }
  }, 30000);

  it('rejects a wrong su password without leaking it', async () => {
    const manager = new SSHConnectionManager({
      host: '127.0.0.1', port: 2222, username: 'test', password: 'secret', suPassword: 'wrong-pass-123',
    });
    try {
      await manager.connect();
      const err = await manager.ensureElevated().then(() => null, (e: Error) => e);
      expect(err?.message).toMatch(/su failed|closed/i);
      expect(err?.message).not.toContain('wrong-pass-123');

      const whoami = await manager.executeCommand('whoami', undefined, 5000);
      expect(whoami.stdout).toBe('test\n');
    } finally {
      manager.close();
    }
  }, 30000);

  it('fails when sudo requires password but none provided', async () => {
    const res = await runMcpCommand('whoami');
    const text = (res.result?.content?.[0]?.text || '').toLowerCase();
    expect(text).toContain('sudo: a password is required');
  });

  it('reports empty command as invalid', async () => {
    const res = await runMcpCommand('', ['--sudoPassword=secret']);
    const text = (res.result?.content?.[0]?.text || '').toLowerCase();
    expect(text).toContain('command cannot be empty');
  });

  it('rejects wrong sudo password', async () => {
    const res = await runMcpCommand('whoami', ['--sudoPassword=wrongpass']);
    const text = (res.result?.content?.[0]?.text || '').toLowerCase();
    // The sshd/sudo stack may return different messages across platforms; look for common indicator
    expect(text).toMatch(/sorry|incorrect|authentication/);
  });

  it('executes with correct sudo password', async () => {
    const res = await runMcpCommand('id', ['--sudoPassword=secret']);
    expect(res.error).toBeUndefined();
    const out = (res.result?.content?.[0]?.text || '').toLowerCase();
    expect(out).toContain('uid=0');
  });
});