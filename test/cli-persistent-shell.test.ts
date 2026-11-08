import { describe, it, expect } from 'vitest';
import { spawn } from 'child_process';
import { join } from 'path';

// regression: in persistent-shell mode main() preconnects right after the stdio transport starts,
// so the first tool call used to open channels mid-handshake ("Bad packet length")

const serverPath = join(process.cwd(), 'build', 'index.js');

function callExecViaCli(command: string): Promise<{ response: any; stderr: string }> {
  // run the real CLI path, not the SSH_MCP_TEST shortcut the vitest env would otherwise select
  const env = { ...process.env };
  delete env.SSH_MCP_DISABLE_MAIN;
  delete env.SSH_MCP_TEST;

  const child = spawn('node', [
    serverPath,
    '--host=127.0.0.1',
    '--port=2222',
    '--user=test',
    '--password=secret',
    '--executionMode=persistent-shell',
  ], { stdio: ['pipe', 'pipe', 'pipe'], env });

  return new Promise((resolve, reject) => {
    let buffer = '';
    let stderr = '';
    const timer = setTimeout(() => {
      child.kill();
      reject(new Error(`no tools/call response; stderr:\n${stderr}`));
    }, 15000);

    child.stderr.on('data', (d) => { stderr += d.toString(); });
    child.on('error', (err) => { clearTimeout(timer); reject(err); });
    child.on('exit', (code) => {
      clearTimeout(timer);
      reject(new Error(`server exited (${code}) before responding; stderr:\n${stderr}`));
    });

    child.stdout.on('data', (d) => {
      buffer += d.toString();
      const lines = buffer.split('\n');
      buffer = lines.pop() || '';
      for (const line of lines) {
        let msg: any;
        try { msg = JSON.parse(line); } catch { continue; }
        if (msg.id === 1) {
          clearTimeout(timer);
          child.removeAllListeners('exit');
          child.kill();
          resolve({ response: msg, stderr });
        }
      }
    });

    // send both requests back to back so the tool call races the eager preconnect
    child.stdin.write(JSON.stringify({
      jsonrpc: '2.0', id: 0, method: 'initialize',
      params: { capabilities: {}, clientInfo: { name: 't', version: '1' }, protocolVersion: '2025-06-18' },
    }) + '\n');
    child.stdin.write(JSON.stringify({
      jsonrpc: '2.0', id: 1, method: 'tools/call',
      params: { name: 'exec', arguments: { command } },
    }) + '\n');
  });
}

describe('CLI persistent-shell mode', () => {
  it('answers the first tool call while the startup preconnect is in flight', async () => {
    const { response } = await callExecViaCli('echo persistent-ok');
    expect(response.error).toBeUndefined();
    expect(response.result?.isError).toBeFalsy();
    expect(response.result?.content?.[0]?.text?.trim()).toBe('persistent-ok');
  }, 30000);
});
