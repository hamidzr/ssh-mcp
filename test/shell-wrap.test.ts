import { describe, it, expect } from 'vitest';
import { execFileSync } from 'child_process';
import { existsSync } from 'fs';
import { parseShellProbe, shellQuote, wrapWithShell } from '../src/index.js';

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
