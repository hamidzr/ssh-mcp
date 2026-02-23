import { describe, it, expect } from 'vitest';
import { parseSshConfig } from '../src/index.js';

const BASIC_CONFIG = `
Host bastion
  HostName bastion.example.com
  Port 2222
  User deploy
  IdentityFile ~/.ssh/id_ed25519
  # MCP yes

Host dev
  HostName dev.example.com
  User alice
  # MCP yes
  # MCP-timeout 30000
  # MCP-maxChars none
  # MCP-disableSudo

Host prod
  HostName prod.example.com
  User root
  # MCP yes
  # MCP-key /home/user/.ssh/prod_key
  # MCP-executionMode persistent-shell

Host ignored
  HostName ignored.example.com
  User nobody
`;

describe('parseSshConfig', () => {
  it('returns only MCP-enabled hosts', () => {
    const entries = parseSshConfig(BASIC_CONFIG);
    expect(entries.map(e => e.alias)).toEqual(['bastion', 'dev', 'prod']);
  });

  it('parses basic SSH fields', () => {
    const entries = parseSshConfig(BASIC_CONFIG);
    const bastion = entries.find(e => e.alias === 'bastion')!;
    expect(bastion.hostname).toBe('bastion.example.com');
    expect(bastion.port).toBe(2222);
    expect(bastion.user).toBe('deploy');
    expect(bastion.identityFile).toBe('~/.ssh/id_ed25519');
  });

  it('defaults port to 22 when not specified', () => {
    const entries = parseSshConfig(BASIC_CONFIG);
    const dev = entries.find(e => e.alias === 'dev')!;
    expect(dev.port).toBe(22);
  });

  it('parses MCP-timeout', () => {
    const entries = parseSshConfig(BASIC_CONFIG);
    const dev = entries.find(e => e.alias === 'dev')!;
    expect(dev.mcpTimeout).toBe(30000);
  });

  it('parses MCP-maxChars none as Infinity', () => {
    const entries = parseSshConfig(BASIC_CONFIG);
    const dev = entries.find(e => e.alias === 'dev')!;
    expect(dev.mcpMaxChars).toBe(Infinity);
  });

  it('parses MCP-disableSudo', () => {
    const entries = parseSshConfig(BASIC_CONFIG);
    const dev = entries.find(e => e.alias === 'dev')!;
    expect(dev.mcpDisableSudo).toBe(true);
  });

  it('parses MCP-key', () => {
    const entries = parseSshConfig(BASIC_CONFIG);
    const prod = entries.find(e => e.alias === 'prod')!;
    expect(prod.mcpKey).toBe('/home/user/.ssh/prod_key');
  });

  it('parses MCP-executionMode', () => {
    const entries = parseSshConfig(BASIC_CONFIG);
    const prod = entries.find(e => e.alias === 'prod')!;
    expect(prod.mcpExecutionMode).toBe('persistent-shell');
  });

  it('excludes non-MCP hosts', () => {
    const entries = parseSshConfig(BASIC_CONFIG);
    expect(entries.find(e => e.alias === 'ignored')).toBeUndefined();
  });

  it('handles multiple aliases on one Host line, uses first as alias', () => {
    const config = `
Host web1 web web-server
  HostName web.example.com
  User ubuntu
  # MCP yes
`;
    const entries = parseSshConfig(config);
    expect(entries).toHaveLength(1);
    expect(entries[0].alias).toBe('web1');
    expect(entries[0].aliases).toEqual(['web1', 'web', 'web-server']);
  });

  it('skips wildcard Host * blocks', () => {
    const config = `
Host *
  ServerAliveInterval 60
  # MCP yes

Host real
  HostName real.example.com
  User admin
  # MCP yes
`;
    const entries = parseSshConfig(config);
    expect(entries.map(e => e.alias)).toEqual(['real']);
  });

  it('returns empty array when no hosts are MCP-enabled', () => {
    const config = `
Host myhost
  HostName myhost.example.com
  User someone
`;
    const entries = parseSshConfig(config);
    expect(entries).toHaveLength(0);
  });

  it('uses alias as hostname fallback when HostName is missing', () => {
    const config = `
Host myhost
  User admin
  # MCP yes
`;
    const entries = parseSshConfig(config);
    expect(entries[0].hostname).toBe('myhost');
  });

  it('MCP-maxChars with a number', () => {
    const config = `
Host limited
  HostName limited.example.com
  User u
  # MCP yes
  # MCP-maxChars 500
`;
    const entries = parseSshConfig(config);
    expect(entries[0].mcpMaxChars).toBe(500);
  });

  it('does not enable host with unrecognized MCP directive only', () => {
    const config = `
Host meh
  HostName meh.example.com
  User u
  # MCP-timeout 5000
`;
    // MCP-timeout alone without # MCP yes should NOT enable the host
    const entries = parseSshConfig(config);
    expect(entries).toHaveLength(0);
  });

  describe('global MCP defaults (pre-Host directives)', () => {
    const GLOBAL_CONFIG = `
# MCP-timeout 30000
# MCP-maxChars none

Host hostA
  HostName a.example.com
  User alice
  # MCP yes

Host hostB
  HostName b.example.com
  User bob
  # MCP yes
  # MCP-timeout 5000

Host hostC
  HostName c.example.com
  User carol
  # MCP yes
  # MCP-maxChars 500
`;

    it('applies global timeout to hosts without a per-host override', () => {
      const entries = parseSshConfig(GLOBAL_CONFIG);
      const a = entries.find(e => e.alias === 'hostA')!;
      expect(a.mcpTimeout).toBe(30000);
    });

    it('per-host timeout overrides global default', () => {
      const entries = parseSshConfig(GLOBAL_CONFIG);
      const b = entries.find(e => e.alias === 'hostB')!;
      expect(b.mcpTimeout).toBe(5000);
    });

    it('applies global maxChars none as Infinity to hosts without override', () => {
      const entries = parseSshConfig(GLOBAL_CONFIG);
      const a = entries.find(e => e.alias === 'hostA')!;
      expect(a.mcpMaxChars).toBe(Infinity);
    });

    it('per-host maxChars overrides global default', () => {
      const entries = parseSshConfig(GLOBAL_CONFIG);
      const c = entries.find(e => e.alias === 'hostC')!;
      expect(c.mcpMaxChars).toBe(500);
    });

    it('global # MCP yes does not auto-enable hosts', () => {
      const config = `
# MCP yes

Host silent
  HostName silent.example.com
  User u
`;
      const entries = parseSshConfig(config);
      expect(entries).toHaveLength(0);
    });

    it('global MCP-key applies to hosts without a per-host key', () => {
      const config = `
# MCP-key /global/.ssh/key

Host srv
  HostName srv.example.com
  User u
  # MCP yes
`;
      const entries = parseSshConfig(config);
      expect(entries[0].mcpKey).toBe('/global/.ssh/key');
    });

    it('global MCP-disableSudo applies to all MCP hosts', () => {
      const config = `
# MCP-disableSudo

Host srv
  HostName srv.example.com
  User u
  # MCP yes
`;
      const entries = parseSshConfig(config);
      expect(entries[0].mcpDisableSudo).toBe(true);
    });

    it('global MCP-executionMode applies to all MCP hosts', () => {
      const config = `
# MCP-executionMode persistent-shell

Host srv
  HostName srv.example.com
  User u
  # MCP yes
`;
      const entries = parseSshConfig(config);
      expect(entries[0].mcpExecutionMode).toBe('persistent-shell');
    });
  });
});
