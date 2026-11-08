import { describe, it, expect } from 'vitest';
import { execFileSync } from 'child_process';
import { existsSync } from 'fs';
import { SuSession, buildMarkedShellPayload, extractShellMarker, parseShellProbe, shellQuote, wrapWithShell } from '../src/index.js';

describe('parseShellProbe', () => {
  it('returns the probed path', () => {
    expect(parseShellProbe('/usr/bin/bash\n')).toBe('/usr/bin/bash');
  });

  it('ignores login shell noise and escape codes', () => {
    expect(parseShellProbe('motd line\n\x1b[?25h/bin/sh\r\n\x1b[?25h')).toBe('/bin/sh');
  });

  it('returns null when no path is printed', () => {
    expect(parseShellProbe('')).toBeNull();
    expect(parseShellProbe("'command' is not recognized\r\n")).toBeNull();
  });
});

describe('wrapWithShell', () => {
  it('keeps the command unchanged without a shell', () => {
    expect(wrapWithShell('echo hi', null)).toBe('echo hi');
  });

  it('quotes single quotes', () => {
    expect(shellQuote("it's")).toBe(`'it'\\''s'`);
    expect(wrapWithShell("echo 'a b'", '/bin/bash')).toBe(`/bin/bash -c 'echo '\\''a b'\\'''`);
  });

  // zsh login shells keep unquoted $var as one word; the wrapper must restore bash splitting
  it.skipIf(!existsSync('/bin/zsh') || !existsSync('/bin/bash'))('word-splits under a zsh login shell', () => {
    const command = `spec="-p tcp --dport 22"; printf '<%s>' $spec; echo " $(echo "q'uote")"`;
    expect(execFileSync('/bin/zsh', ['-c', command]).toString()).toBe("<-p tcp --dport 22> q'uote\n");
    expect(execFileSync('/bin/zsh', ['-c', wrapWithShell(command, '/bin/bash')]).toString()).toBe(
      "<-p><tcp><--dport><22> q'uote\n",
    );
  });
});

describe('extractShellMarker', () => {
  const marker = '__SSH_MCP_DONE_1_abc__';

  it('ignores a terminal echo of the payload and reads the real exit code', () => {
    // shape of a real su pty transcript: prompt, echoed payload lines, output, marker
    const payload = buildMarkedShellPayload('whoami', marker);
    const echoed = payload.split('\n').filter(Boolean).map((line) => `host:~# ${line}\r\n`).join('');
    const buffer = `${echoed}${marker}_START\r\nroot\r\n${marker}:0\r\nhost:~# `;
    expect(extractShellMarker(buffer, marker)).toEqual({
      done: true, output: 'root\r\n', code: 0, remainder: 'host:~# ',
    });
  });

  it('waits while only the echoed payload has arrived', () => {
    const echoed = buildMarkedShellPayload('whoami', marker).replace(/\n/g, '\r\n');
    expect(extractShellMarker(echoed, marker)).toEqual({ done: false });
  });

  it('handles output without a trailing newline and no start marker', () => {
    expect(extractShellMarker(`a b${marker}:2\n`, marker)).toEqual({
      done: true, output: 'a b', code: 2, remainder: '',
    });
  });
});

describe('buildMarkedShellPayload', () => {
  const marker = '__SSH_MCP_DONE_1_abc__';

  it('runs the command in a brace group with stdin from /dev/null', () => {
    expect(buildMarkedShellPayload('echo hi', marker)).toBe(
      `printf '%s_START\\n' '${marker}'\n{\necho hi\n} </dev/null\nprintf '%s:%s\\n' '${marker}' "$?"\n`,
    );
  });

  it('feeds stdin through a quoted here-doc', () => {
    expect(buildMarkedShellPayload('cat', marker, 'a $HOME')).toContain(`} <<'${marker}_IN'\na $HOME\n${marker}_IN\n`);
  });
});

describe('SuSession', () => {
  const marker = '__SSH_MCP_DONE_1_abc__';
  const newSession = () => new SuSession(marker, 'hunter2', '/bin/bash');

  it('ignores a banner with a password prompt and a # before its own marker', () => {
    const su = newSession();
    expect(su.start()).toBe(`printf '%s_SU\\n' '${marker}'; exec su -\n`);
    expect(su.push('# Welcome\r\nChange your Password: now\r\nhost:~# ')).toEqual({});
    // terminal echo of the start line does not contain `<marker>_SU`
    expect(su.push(`${su.start().trim()}\r\n`)).toEqual({});
  });

  it('sends the password once, then switches to a raw non-interactive shell, then checks uid 0', () => {
    const su = newSession();
    expect(su.push(`${marker}_SU\r\nPass`)).toEqual({});
    expect(su.push('word: ')).toEqual({ send: 'hunter2\n' });
    const setup = su.push('\r\nhost:~# \x1b[6n');
    expect(setup.send).toMatch(/^stty raw -echo && exec \/bin\/bash -c '.*exec \/bin\/bash \/dev\/stdin'\n$/);
    expect(setup.send).not.toContain(`${marker}_READY`);
    expect(su.push(`${marker}_READY:0\n`)).toEqual({ done: true });
  });

  it('rejects a shell that is not root', () => {
    const su = newSession();
    su.push(`${marker}_SU\r\nhost:~$ `);
    expect(su.push(`${marker}_READY:1000\n`)).toEqual({ fail: 'su did not produce a root shell (uid 1000)' });
  });

  it('reports su errors without echoing the password', () => {
    const su = newSession();
    su.push(`${marker}_SU\r\nPassword: `);
    const step = su.push('\r\nsu: Authentication failure\r\n');
    expect(step).toEqual({ fail: 'su failed: su: Authentication failure' });
    expect(step.fail).not.toContain('hunter2');
  });

  it('treats su warnings as non-fatal', () => {
    const su = newSession();
    su.push(`${marker}_SU\r\nPassword: `);
    expect(su.push('\r\nsu: warning: cannot change directory to /root\r\n')).toEqual({});
    expect(su.push('root@host:/# ').send).toContain('stty raw -echo');
  });
});
