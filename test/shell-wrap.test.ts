import { describe, it, expect } from 'vitest';
import { execFileSync } from 'child_process';
import { existsSync } from 'fs';
import { buildMarkedShellPayload, extractShellMarker, parseShellProbe, shellQuote, wrapWithShell } from '../src/index.js';

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
