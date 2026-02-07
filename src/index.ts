#!/usr/bin/env node

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { McpError, ErrorCode } from "@modelcontextprotocol/sdk/types.js";
import { Client, ClientChannel } from 'ssh2';
import { z } from 'zod';
import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';

// Example usage: node build/index.js --host=1.2.3.4 --port=22 --user=root --password=pass --key=path/to/key --timeout=5000 --executionMode=persistent-shell --disableSudo
function parseArgv() {
  const args = process.argv.slice(2);
  const config: Record<string, string | null> = {};
  for (const arg of args) {
    if (arg.startsWith('--')) {
      const equalIndex = arg.indexOf('=');
      if (equalIndex === -1) {
        // Flag without value
        config[arg.slice(2)] = null;
      } else {
        // Key=value pair
        config[arg.slice(2, equalIndex)] = arg.slice(equalIndex + 1);
      }
    }
  }
  return config;
}
const isTestMode = process.env.SSH_MCP_TEST === '1';
const isCliEnabled = process.env.SSH_MCP_DISABLE_MAIN !== '1';
const argvConfig = (isCliEnabled || isTestMode) ? parseArgv() : {} as Record<string, string>;

const HOST = argvConfig.host;
const PORT = argvConfig.port ? parseInt(argvConfig.port) : 22;
const USER = argvConfig.user;
const PASSWORD = argvConfig.password;
const SUPASSWORD = argvConfig.suPassword;
const SUDOPASSWORD = argvConfig.sudoPassword;
const DISABLE_SUDO = argvConfig.disableSudo !== undefined;
const KEY = argvConfig.key;
const DEFAULT_TIMEOUT = argvConfig.timeout ? parseInt(argvConfig.timeout) : 60000; // 60 seconds default timeout
// Max characters configuration:
// - Default: 1000 characters
// - When set via --maxChars:
//   * a positive integer enforces that limit
//   * 0 or a negative value disables the limit (no max)
//   * the string "none" (case-insensitive) disables the limit (no max)
const MAX_CHARS_RAW = argvConfig.maxChars;
const MAX_CHARS = (() => {
  if (typeof MAX_CHARS_RAW === 'string') {
    const lowered = MAX_CHARS_RAW.toLowerCase();
    if (lowered === 'none') return Infinity;
    const parsed = parseInt(MAX_CHARS_RAW);
    if (isNaN(parsed)) return 1000;
    if (parsed <= 0) return Infinity;
    return parsed;
  }
  return 1000;
})();

export type SSHExecutionMode = 'exec' | 'persistent-shell';

function parseExecutionMode(rawMode: string | null | undefined): SSHExecutionMode {
  if (rawMode === undefined) return 'exec';
  if (rawMode === null) {
    throw new Error('Invalid --executionMode: value is required (exec, shell, persistent-shell)');
  }
  const normalized = rawMode.trim().toLowerCase();
  if (normalized === 'exec') return 'exec';
  if (normalized === 'shell' || normalized === 'persistent' || normalized === 'persistent-shell') {
    return 'persistent-shell';
  }
  throw new Error(`Invalid --executionMode: ${rawMode}. Valid values: exec, shell, persistent-shell`);
}

const EXECUTION_MODE = parseExecutionMode(argvConfig.executionMode);

function validateConfig(config: Record<string, string | null>) {
  const errors = [];
  if (!config.host) errors.push('Missing required --host');
  if (!config.user) errors.push('Missing required --user');
  if (config.port && isNaN(Number(config.port))) errors.push('Invalid --port');
  if (config.executionMode) {
    try {
      parseExecutionMode(config.executionMode);
    } catch (err) {
      errors.push((err as Error).message);
    }
  }
  if (errors.length > 0) {
    throw new Error('Configuration error:\n' + errors.join('\n'));
  }
}

if (isCliEnabled) {
  validateConfig(argvConfig);
}

// Command sanitization and validation
export function sanitizeCommand(command: string): string {
  if (typeof command !== 'string') {
    throw new McpError(ErrorCode.InvalidParams, 'Command must be a string');
  }

  const trimmedCommand = command.trim();
  if (!trimmedCommand) {
    throw new McpError(ErrorCode.InvalidParams, 'Command cannot be empty');
  }

  // Length check
  if (Number.isFinite(MAX_CHARS) && trimmedCommand.length > (MAX_CHARS as number)) {
    throw new McpError(
      ErrorCode.InvalidParams,
      `Command is too long (max ${MAX_CHARS} characters)`
    );
  }

  return trimmedCommand;
}

function sanitizePassword(password: string | undefined): string | undefined {
  if (typeof password !== 'string') return undefined;
  // minimal check, do not log or modify content
  if (password.length === 0) return undefined;
  return password;
}

// Escape command for use in shell contexts (like pkill)
export function escapeCommandForShell(command: string): string {
  // Replace single quotes with escaped single quotes
  return command.replace(/'/g, "'\"'\"'");
}

// SSH Connection Manager to maintain persistent connection
export interface SSHConfig {
  host: string;
  port: number;
  username: string;
  password?: string;
  privateKey?: string;
  suPassword?: string;
  sudoPassword?: string;
  executionMode?: SSHExecutionMode;
}

interface CommandExecutionResult {
  stdout: string;
  stderr: string;
  code: number | null;
}

export class SSHConnectionManager {
  private conn: Client | null = null;
  private sshConfig: SSHConfig;
  private isConnecting = false;
  private connectionPromise: Promise<void> | null = null;
  private suShell: ClientChannel | null = null;
  private suPromise: Promise<void> | null = null;
  private isElevated = false;
  private persistentShell: ClientChannel | null = null;
  private persistentShellPromise: Promise<ClientChannel> | null = null;
  private shellQueue: Promise<void> = Promise.resolve();
  private persistentStdoutCarry = '';
  private suStdoutCarry = '';

  constructor(config: SSHConfig) {
    this.sshConfig = {
      ...config,
      executionMode: config.executionMode ?? 'exec',
    };
  }

  private getConnectConfig() {
    return {
      host: this.sshConfig.host,
      port: this.sshConfig.port,
      username: this.sshConfig.username,
      password: this.sshConfig.password,
      privateKey: this.sshConfig.privateKey,
    };
  }

  private isChannelAlive(channel: ClientChannel | null): channel is ClientChannel {
    if (!channel) return false;
    return !(channel as any).destroyed && !(channel as any).closed;
  }

  private resetShellState(): void {
    this.suShell = null;
    this.suPromise = null;
    this.isElevated = false;
    this.persistentShell = null;
    this.persistentShellPromise = null;
    this.persistentStdoutCarry = '';
    this.suStdoutCarry = '';
  }

  private closeSuShell(): void {
    if (this.suShell) {
      try { this.suShell.end(); } catch (_e) { /* ignore */ }
      this.suShell = null;
    }
    this.isElevated = false;
    this.suPromise = null;
    this.suStdoutCarry = '';
  }

  private closePersistentShell(): void {
    if (this.persistentShell) {
      try { this.persistentShell.end(); } catch (_e) { /* ignore */ }
      this.persistentShell = null;
    }
    this.persistentShellPromise = null;
    this.persistentStdoutCarry = '';
  }

  private makeShellMarker(): string {
    return `__SSH_MCP_DONE_${Date.now()}_${Math.random().toString(16).slice(2)}__`;
  }

  private extractShellMarker(
    buffer: string,
    marker: string
  ): { done: false } | { done: true; output: string; code: number; remainder: string } {
    const markerPrefix = `${marker}:`;
    const markerIndex = buffer.indexOf(markerPrefix);
    if (markerIndex === -1) return { done: false };

    const afterMarker = buffer.slice(markerIndex + markerPrefix.length);
    const newlineIndex = afterMarker.indexOf('\n');
    if (newlineIndex === -1) return { done: false };

    const codeRaw = afterMarker.slice(0, newlineIndex).trim();
    const code = Number.parseInt(codeRaw, 10);
    if (Number.isNaN(code)) return { done: false };

    return {
      done: true,
      output: buffer.slice(0, markerIndex),
      code,
      remainder: afterMarker.slice(newlineIndex + 1),
    };
  }

  private enqueueShellCommand<T>(task: () => Promise<T>): Promise<T> {
    const queuedTask = this.shellQueue.then(task, task);
    this.shellQueue = queuedTask.then(() => undefined, () => undefined);
    return queuedTask;
  }

  private async ensurePersistentShell(): Promise<ClientChannel> {
    if (this.isChannelAlive(this.persistentShell)) {
      return this.persistentShell;
    }
    if (this.persistentShellPromise) {
      return this.persistentShellPromise;
    }

    this.persistentShellPromise = new Promise((resolve, reject) => {
      const conn = this.getConnection();
      conn.exec('/bin/sh', (err: Error | undefined, stream: ClientChannel) => {
        if (err) {
          this.persistentShellPromise = null;
          reject(new McpError(ErrorCode.InternalError, `Failed to start persistent shell: ${err.message}`));
          return;
        }

        const cleanup = () => {
          if (this.persistentShell === stream) {
            this.persistentShell = null;
          }
          this.persistentShellPromise = null;
          this.persistentStdoutCarry = '';
        };

        stream.on('close', cleanup);
        stream.on('end', cleanup);
        stream.on('error', cleanup);

        this.persistentShell = stream;
        this.persistentShellPromise = null;
        resolve(stream);
      });
    });

    return this.persistentShellPromise;
  }

  private trimInteractiveCommandEcho(output: string, command: string): string {
    const normalized = output.replace(/\r/g, '');
    const lines = normalized.split('\n');
    if (lines.length > 0 && lines[0].includes(command)) {
      lines.shift();
    }
    return lines.join('\n');
  }

  private async executeWithPersistentShell(command: string, timeoutMs: number): Promise<CommandExecutionResult> {
    return this.enqueueShellCommand(async () => {
      const shell = await this.ensurePersistentShell();
      return new Promise((resolve, reject) => {
        const marker = this.makeShellMarker();
        let stdoutBuffer = this.persistentStdoutCarry;
        this.persistentStdoutCarry = '';
        let stderr = '';
        let settled = false;

        const cleanup = () => {
          clearTimeout(timeoutId);
          shell.removeListener('data', onStdout);
          shell.removeListener('close', onClose);
          shell.removeListener('error', onError);
          try { (shell as any).stderr?.removeListener('data', onStderr); } catch (_e) { /* ignore */ }
        };

        const finishWithError = (error: McpError) => {
          if (settled) return;
          settled = true;
          cleanup();
          reject(error);
        };

        const finishWithResult = (result: CommandExecutionResult) => {
          if (settled) return;
          settled = true;
          cleanup();
          resolve(result);
        };

        const onStdout = (chunk: Buffer) => {
          stdoutBuffer += chunk.toString();
          const parsed = this.extractShellMarker(stdoutBuffer, marker);
          if (!parsed.done) return;

          this.persistentStdoutCarry = parsed.remainder;
          finishWithResult({
            stdout: parsed.output,
            stderr,
            code: parsed.code,
          });
        };

        const onStderr = (chunk: Buffer) => {
          stderr += chunk.toString();
        };

        const onClose = () => {
          finishWithError(new McpError(ErrorCode.InternalError, 'Persistent shell closed unexpectedly'));
        };

        const onError = (err: Error) => {
          finishWithError(new McpError(ErrorCode.InternalError, `Persistent shell error: ${err.message}`));
        };

        const timeoutId = setTimeout(() => {
          this.closePersistentShell();
          finishWithError(new McpError(ErrorCode.InternalError, `Command execution timed out after ${timeoutMs}ms`));
        }, timeoutMs);

        shell.on('data', onStdout);
        shell.on('close', onClose);
        shell.on('error', onError);
        try { (shell as any).stderr?.on('data', onStderr); } catch (_e) { /* ignore */ }

        const payload = `${command}\nprintf '${marker}:%s\\n' "$?"\n`;
        try {
          shell.write(payload);
        } catch (err: any) {
          finishWithError(new McpError(ErrorCode.InternalError, `Failed writing to persistent shell: ${err?.message || err}`));
        }
      });
    });
  }

  private async executeWithSuShell(command: string, timeoutMs: number): Promise<CommandExecutionResult> {
    return this.enqueueShellCommand(async () => {
      if (!this.isChannelAlive(this.suShell)) {
        throw new McpError(ErrorCode.InternalError, 'su shell is not available');
      }

      const shell = this.suShell;
      return new Promise((resolve, reject) => {
        const marker = this.makeShellMarker();
        let buffer = this.suStdoutCarry;
        this.suStdoutCarry = '';
        let settled = false;

        const cleanup = () => {
          clearTimeout(timeoutId);
          shell.removeListener('data', onData);
          shell.removeListener('close', onClose);
          shell.removeListener('error', onError);
        };

        const finishWithError = (error: McpError) => {
          if (settled) return;
          settled = true;
          cleanup();
          reject(error);
        };

        const finishWithResult = (result: CommandExecutionResult) => {
          if (settled) return;
          settled = true;
          cleanup();
          resolve(result);
        };

        const onData = (chunk: Buffer) => {
          buffer += chunk.toString();
          const parsed = this.extractShellMarker(buffer, marker);
          if (!parsed.done) return;

          this.suStdoutCarry = parsed.remainder;
          finishWithResult({
            stdout: this.trimInteractiveCommandEcho(parsed.output, command),
            stderr: '',
            code: parsed.code,
          });
        };

        const onClose = () => {
          this.closeSuShell();
          finishWithError(new McpError(ErrorCode.InternalError, 'su shell closed unexpectedly'));
        };

        const onError = (err: Error) => {
          this.closeSuShell();
          finishWithError(new McpError(ErrorCode.InternalError, `su shell error: ${err.message}`));
        };

        const timeoutId = setTimeout(() => {
          this.closeSuShell();
          finishWithError(new McpError(ErrorCode.InternalError, `Command execution timed out after ${timeoutMs}ms`));
        }, timeoutMs);

        shell.on('data', onData);
        shell.on('close', onClose);
        shell.on('error', onError);

        const payload = `${command}\nprintf '${marker}:%s\\n' "$?"\n`;
        try {
          shell.write(payload);
        } catch (err: any) {
          finishWithError(new McpError(ErrorCode.InternalError, `Failed writing to su shell: ${err?.message || err}`));
        }
      });
    });
  }

  private async executeWithExec(command: string, stdin: string | undefined, timeoutMs: number): Promise<CommandExecutionResult> {
    return new Promise((resolve, reject) => {
      const conn = this.getConnection();
      let settled = false;

      const timeoutId = setTimeout(() => {
        if (settled) return;
        settled = true;
        reject(new McpError(ErrorCode.InternalError, `Command execution timed out after ${timeoutMs}ms`));
      }, timeoutMs);

      conn.exec(command, (err: Error | undefined, stream: ClientChannel) => {
        if (err) {
          if (settled) return;
          settled = true;
          clearTimeout(timeoutId);
          reject(new McpError(ErrorCode.InternalError, `SSH exec error: ${err.message}`));
          return;
        }

        let stdout = '';
        let stderr = '';

        if (stdin && stdin.length > 0) {
          try {
            stream.write(stdin);
          } catch (_e) {
            // ignore
          }
        }
        try { stream.end(); } catch (_e) { /* ignore */ }

        stream.on('data', (data: Buffer) => {
          stdout += data.toString();
        });

        stream.stderr.on('data', (data: Buffer) => {
          stderr += data.toString();
        });

        stream.on('error', (streamErr: Error) => {
          if (settled) return;
          settled = true;
          clearTimeout(timeoutId);
          reject(new McpError(ErrorCode.InternalError, `SSH exec stream error: ${streamErr.message}`));
        });

        stream.on('close', (code: number | undefined) => {
          if (settled) return;
          settled = true;
          clearTimeout(timeoutId);
          resolve({
            stdout,
            stderr,
            code: typeof code === 'number' ? code : null,
          });
        });
      });
    });
  }

  async connect(): Promise<void> {
    if (this.conn && this.isConnected()) {
      return; // Already connected
    }

    if (this.isConnecting && this.connectionPromise) {
      return this.connectionPromise; // Wait for ongoing connection
    }

    this.isConnecting = true;
    this.connectionPromise = new Promise((resolve, reject) => {
      this.conn = new Client();

      const timeoutId = setTimeout(() => {
        this.conn?.end();
        this.conn = null;
        this.isConnecting = false;
        this.connectionPromise = null;
        reject(new McpError(ErrorCode.InternalError, 'SSH connection timeout'));
      }, 30000); // 30 seconds connection timeout

      this.conn.on('ready', () => {
        clearTimeout(timeoutId);
        this.isConnecting = false;

        const onReady = async () => {
          if (this.sshConfig.suPassword && !process.env.SSH_MCP_TEST) {
            try {
              await this.ensureElevated();
            } catch (_err) {
              // continue without su shell, command execution will fallback
            }
          }

          if (this.sshConfig.executionMode === 'persistent-shell' && !this.isElevated) {
            await this.ensurePersistentShell();
          }
        };

        onReady()
          .then(() => resolve())
          .catch((err: any) => {
            this.conn?.end();
            this.conn = null;
            this.isConnecting = false;
            this.connectionPromise = null;
            reject(new McpError(ErrorCode.InternalError, `SSH post-connect setup failed: ${err?.message || err}`));
          });
      });

      this.conn.on('error', (err: Error) => {
        clearTimeout(timeoutId);
        this.conn = null;
        this.isConnecting = false;
        this.connectionPromise = null;
        reject(new McpError(ErrorCode.InternalError, `SSH connection error: ${err.message}`));
      });

      this.conn.on('end', () => {
        console.error('SSH connection ended');
        this.resetShellState();
        this.conn = null;
        this.isConnecting = false;
        this.connectionPromise = null;
      });

      this.conn.on('close', () => {
        console.error('SSH connection closed');
        this.resetShellState();
        this.conn = null;
        this.isConnecting = false;
        this.connectionPromise = null;
      });

      this.conn.connect(this.getConnectConfig());
    });

    return this.connectionPromise;
  }

  isConnected(): boolean {
    return this.conn !== null && (this.conn as any)._sock && !(this.conn as any)._sock.destroyed;
  }

  getSudoPassword(): string | undefined {
    return this.sshConfig.sudoPassword;
  }

  setSudoPassword(pwd?: string): void {
    this.sshConfig.sudoPassword = pwd;
  }

  getSuPassword(): string | undefined {
    return this.sshConfig.suPassword;
  }

  async setSuPassword(pwd?: string): Promise<void> {
    this.sshConfig.suPassword = pwd;
    if (pwd) {
      try {
        await this.ensureElevated();
      } catch (err) {
        console.error('setSuPassword: failed to elevate to su shell:', err);
      }
    } else {
      // If clearing suPassword, drop any existing suShell
      if (this.suShell) {
        this.closeSuShell();
      }
    }
  }

  async ensureElevated(): Promise<void> {
    if (this.isElevated && this.suShell) return;
    if (!this.sshConfig.suPassword) return;

    if (this.suPromise) return this.suPromise;

    this.suPromise = new Promise((resolve, reject) => {
      const conn = this.getConnection();

      // Add a safety timeout so elevation doesn't hang forever
      const timeoutId = setTimeout(() => {
        this.suPromise = null;
        reject(new McpError(ErrorCode.InternalError, 'su elevation timed out'));
      }, 10000);  // 10 second timeout for elevation

      conn.shell({ term: 'xterm', cols: 80, rows: 24 }, (err: Error | undefined, stream: ClientChannel) => {
        if (err) {
          clearTimeout(timeoutId);
          this.suPromise = null;
          reject(new McpError(ErrorCode.InternalError, `Failed to start interactive shell for su: ${err.message}`));
          return;
        }

        let buffer = '';
        let passwordSent = false;
        const cleanup = () => {
          try { stream.removeAllListeners('data'); } catch (e) { /* ignore */ }
        };

        const onData = (data: Buffer) => {
          const text = data.toString();
          buffer += text;

          // If we haven't sent the password yet, look for the password prompt
          if (!passwordSent && /password[: ]/i.test(buffer)) {
            passwordSent = true;
            stream.write(this.sshConfig.suPassword + '\n');
            // Don't return; keep looking for root prompt
          }

          // After password is sent, look for any root indicator
          // Look for '#' which indicates root prompt (may be followed by spaces, escape codes, etc)
          if (passwordSent) {
            if (/#/.test(buffer)) {
              clearTimeout(timeoutId);
              cleanup();
              this.suShell = stream;
              this.isElevated = true;
              this.suPromise = null;
              this.suStdoutCarry = '';
              resolve();
              return;
            }
          }

          // Detect authentication failure messages
          if (/authentication failure|incorrect password|su: .*failed|su: failure/i.test(buffer)) {
            clearTimeout(timeoutId);
            cleanup();
            this.suPromise = null;
            reject(new McpError(ErrorCode.InternalError, `su authentication failed: ${buffer}`));
            return;
          }
        };

        stream.on('data', onData);

        stream.on('close', () => {
          clearTimeout(timeoutId);
          if (!this.isElevated) {
            this.suPromise = null;
            reject(new McpError(ErrorCode.InternalError, 'su shell closed before elevation completed'));
          }
        });

        // Kick off the su command
        stream.write('su -\n');
      });
    });

    return this.suPromise;
  }

  async ensureConnected(): Promise<void> {
    if (!this.isConnected()) {
      await this.connect();
    }

    if (this.sshConfig.executionMode === 'persistent-shell' && !this.isElevated) {
      await this.ensurePersistentShell();
    }
  }

  async executeCommand(command: string, stdin?: string, timeoutMs = DEFAULT_TIMEOUT): Promise<CommandExecutionResult> {
    await this.ensureConnected();

    if (this.isElevated && this.isChannelAlive(this.suShell)) {
      return this.executeWithSuShell(command, timeoutMs);
    }

    if (this.sshConfig.executionMode === 'persistent-shell') {
      return this.executeWithPersistentShell(command, timeoutMs);
    }

    return this.executeWithExec(command, stdin, timeoutMs);
  }

  getConnection(): Client {
    if (!this.conn) {
      throw new McpError(ErrorCode.InternalError, 'SSH connection not established');
    }
    return this.conn;
  }

  close(): void {
    this.closeSuShell();
    this.closePersistentShell();
    if (!this.conn) return;
    this.conn.end();
    this.conn = null;
  }
}

let connectionManager: SSHConnectionManager | null = null;
let cachedPrivateKey: string | null = null;

async function buildSshConfigFromCli(): Promise<SSHConfig> {
  if (!HOST || !USER) {
    throw new McpError(ErrorCode.InvalidParams, 'Missing required host or username');
  }

  const sshConfig: SSHConfig = {
    host: HOST,
    port: PORT || 22,
    username: USER,
    executionMode: EXECUTION_MODE,
  };

  if (PASSWORD) {
    sshConfig.password = PASSWORD;
  } else if (KEY) {
    if (cachedPrivateKey === null) {
      const fs = await import('fs/promises');
      cachedPrivateKey = await fs.readFile(KEY, 'utf8');
    }
    sshConfig.privateKey = cachedPrivateKey;
  }

  if (SUPASSWORD !== null && SUPASSWORD !== undefined) {
    sshConfig.suPassword = sanitizePassword(SUPASSWORD);
  }
  if (SUDOPASSWORD !== null && SUDOPASSWORD !== undefined) {
    sshConfig.sudoPassword = sanitizePassword(SUDOPASSWORD);
  }

  return sshConfig;
}

async function getOrCreateConnectionManager(): Promise<SSHConnectionManager> {
  if (connectionManager) return connectionManager;
  connectionManager = new SSHConnectionManager(await buildSshConfigFromCli());
  return connectionManager;
}

const server = new McpServer({
  name: 'SSH MCP Server',
  version: '1.5.0',
  capabilities: {
    resources: {},
    tools: {},
  },
});

server.tool(
  "exec",
  "Execute a shell command on the remote SSH server and return the output.",
  {
    command: z.string().describe("Shell command to execute on the remote SSH server"),
    description: z.string().optional().describe("Optional description of what this command will do"),
  },
  async ({ command, description }) => {
    // Sanitize command input
    const sanitizedCommand = sanitizeCommand(command);

    try {
      const manager = await getOrCreateConnectionManager();
      await manager.ensureConnected();

      // If a suPassword was provided, explicitly wait for elevation before executing.
      // This is critical: ensureElevated is idempotent and will return immediately if
      // already elevated, so this ensures we have a su shell before we try to use it.
      if (manager.getSuPassword()) {
        try {
          const elevationPromise = manager.ensureElevated();
          // Add a short timeout for elevation to complete
          await Promise.race([
            elevationPromise,
            new Promise((_, reject) => setTimeout(() => reject(new Error('Elevation timeout')), 5000))
          ]);
        } catch (err) {
          // Log but don't fail; fall back to non-elevated execution if elevation times out
        }
      }

      // Append description as comment if provided
      const commandWithDescription = description
        ? `${sanitizedCommand} # ${description.replace(/#/g, '\\#')}`
        : sanitizedCommand;

      const result = await execSshCommandWithConnection(manager, commandWithDescription);
      return result;
    } catch (err: any) {
      // Wrap unexpected errors
      if (err instanceof McpError) throw err;
      throw new McpError(ErrorCode.InternalError, `Unexpected error: ${err?.message || err}`);
    }
  }
);

// Expose sudo-exec tool unless explicitly disabled
if (!DISABLE_SUDO) {
  server.tool(
    "sudo-exec",
    "Execute a shell command on the remote SSH server using sudo. Will use sudo password if provided, otherwise assumes passwordless sudo.",
    {
      command: z.string().describe("Shell command to execute with sudo on the remote SSH server"),
      description: z.string().optional().describe("Optional description of what this command will do"),
    },
    async ({ command, description }) => {
      const sanitizedCommand = sanitizeCommand(command);

      try {
        const manager = await getOrCreateConnectionManager();
        await manager.ensureConnected();

        // If suPassword or sudoPassword were provided on this call but the
        // existing connection manager was created earlier without them,
        // update the manager's values so the subsequent sudo-exec call uses
        // the latest passwords.
        if (SUPASSWORD !== null && SUPASSWORD !== undefined) {
          await manager.setSuPassword(sanitizePassword(SUPASSWORD));
        }
        if (SUDOPASSWORD !== null && SUDOPASSWORD !== undefined) {
          manager.setSudoPassword(sanitizePassword(SUDOPASSWORD));
        }

        let wrapped: string;
        const sudoPassword = manager.getSudoPassword();

        // Append description as comment if provided
        const commandWithDescription = description
          ? `${sanitizedCommand} # ${description.replace(/#/g, '\\#')}`
          : sanitizedCommand;

        if (!sudoPassword) {
          // No password provided, use -n to fail if sudo requires a password
          wrapped = `sudo -n sh -c '${commandWithDescription.replace(/'/g, "'\\''")}'`;
        } else {
          // Password provided — pipe it into sudo using printf. This avoids complex
          // PTY/stdin handling on the SSH channel and is simpler and more reliable.
          const pwdEscaped = sudoPassword.replace(/'/g, "'\\''");
          wrapped = `printf '%s\\n' '${pwdEscaped}' | sudo -p "" -S sh -c '${commandWithDescription.replace(/'/g, "'\\''")}'`;
        }

        return await execSshCommandWithConnection(manager, wrapped);
      } catch (err: any) {
        if (err instanceof McpError) throw err;
        throw new McpError(ErrorCode.InternalError, `Unexpected error: ${err?.message || err}`);
      }
    }
  );
}

// New function that uses persistent connection
export async function execSshCommandWithConnection(manager: SSHConnectionManager, command: string, stdin?: string): Promise<{ [x: string]: unknown; content: ({ [x: string]: unknown; type: "text"; text: string; } | { [x: string]: unknown; type: "image"; data: string; mimeType: string; } | { [x: string]: unknown; type: "audio"; data: string; mimeType: string; } | { [x: string]: unknown; type: "resource"; resource: any; })[] }> {
  const result = await manager.executeCommand(command, stdin, DEFAULT_TIMEOUT);
  const hasErrorOutput = result.stderr.trim().length > 0;
  const nonZeroExitCode = typeof result.code === 'number' && result.code !== 0;

  if (hasErrorOutput || nonZeroExitCode) {
    const details = result.stderr || result.stdout;
    throw new McpError(ErrorCode.InternalError, `Error (code ${result.code ?? 'unknown'}):\n${details}`);
  }

  return {
    content: [{
      type: 'text',
      text: result.stdout,
    }],
  };
}

// Keep the old function for backward compatibility (used in tests)
export async function execSshCommand(sshConfig: any, command: string, stdin?: string): Promise<{ [x: string]: unknown; content: ({ [x: string]: unknown; type: "text"; text: string; } | { [x: string]: unknown; type: "image"; data: string; mimeType: string; } | { [x: string]: unknown; type: "audio"; data: string; mimeType: string; } | { [x: string]: unknown; type: "resource"; resource: any; })[] }> {
  return new Promise((resolve, reject) => {
    const conn = new Client();
    let timeoutId: NodeJS.Timeout;
    let isResolved = false;

    // Set up timeout
    timeoutId = setTimeout(() => {
      if (!isResolved) {
        isResolved = true;
        // Try to abort the running command before closing connection
        const abortTimeout = setTimeout(() => {
          // If abort command itself times out, force close connection
          conn.end();
        }, 5000); // 5 second timeout for abort command

        conn.exec('timeout 3s pkill -f \'' + escapeCommandForShell(command) + '\' 2>/dev/null || true', (err: Error | undefined, abortStream: ClientChannel | undefined) => {
          if (abortStream) {
            abortStream.on('close', () => {
              clearTimeout(abortTimeout);
              conn.end();
            });
          } else {
            clearTimeout(abortTimeout);
            conn.end();
          }
        });
        reject(new McpError(ErrorCode.InternalError, `Command execution timed out after ${DEFAULT_TIMEOUT}ms`));
      }
    }, DEFAULT_TIMEOUT);

    conn.on('ready', () => {
      conn.exec(command, (err: Error | undefined, stream: ClientChannel) => {
        if (err) {
          if (!isResolved) {
            isResolved = true;
            clearTimeout(timeoutId);
            reject(new McpError(ErrorCode.InternalError, `SSH exec error: ${err.message}`));
          }
          conn.end();
          return;
        }
        // If stdin provided, write it to the stream and end stdin
        if (stdin && stdin.length > 0) {
          try {
            stream.write(stdin);
          } catch (e) {
            // ignore
          }
        }
        try { stream.end(); } catch (e) { /* ignore */ }
        let stdout = '';
        let stderr = '';
        stream.on('close', (code: number, signal: string) => {
          if (!isResolved) {
            isResolved = true;
            clearTimeout(timeoutId);
            conn.end();
            if (stderr) {
              reject(new McpError(ErrorCode.InternalError, `Error (code ${code}):\n${stderr}`));
            } else {
              resolve({
                content: [{
                  type: 'text',
                  text: stdout,
                }],
              });
            }
          }
        });
        stream.on('data', (data: Buffer) => {
          stdout += data.toString();
        });
        stream.stderr.on('data', (data: Buffer) => {
          stderr += data.toString();
        });
      });
    });
    conn.on('error', (err: Error) => {
      if (!isResolved) {
        isResolved = true;
        clearTimeout(timeoutId);
        reject(new McpError(ErrorCode.InternalError, `SSH connection error: ${err.message}`));
      }
    });
    conn.connect(sshConfig);
  });
}

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error("SSH MCP Server running on stdio");

  if (EXECUTION_MODE === 'persistent-shell') {
    const manager = await getOrCreateConnectionManager();
    await manager.ensureConnected();
    console.error("persistent shell mode enabled, SSH session preconnected");
  }

  // Handle graceful shutdown
  const cleanup = () => {
    console.error("Shutting down SSH MCP Server...");
    if (connectionManager) {
      connectionManager.close();
      connectionManager = null;
    }
    process.exit(0);
  };

  process.on('SIGINT', cleanup);
  process.on('SIGTERM', cleanup);
  process.on('exit', () => {
    if (connectionManager) {
      connectionManager.close();
    }
  });
}

// Initialize server in test mode for automated tests
if (isTestMode) {
  const transport = new StdioServerTransport();
  server.connect(transport)
    .then(async () => {
      if (EXECUTION_MODE !== 'persistent-shell') return;
      const manager = await getOrCreateConnectionManager();
      await manager.ensureConnected();
    })
    .catch(error => {
      console.error("Fatal error connecting server:", error);
      process.exit(1);
    });
}
// Start server in CLI mode
else if (isCliEnabled) {
  main().catch((error) => {
    console.error("Fatal error in main():", error);
    if (connectionManager) {
      connectionManager.close();
    }
    process.exit(1);
  });
}

export { parseArgv, validateConfig };
