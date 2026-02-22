# SSH MCP Server

[![NPM Version](https://img.shields.io/npm/v/ssh-mcp)](https://www.npmjs.com/package/ssh-mcp)
[![Downloads](https://img.shields.io/npm/dm/ssh-mcp)](https://www.npmjs.com/package/ssh-mcp)
[![Node Version](https://img.shields.io/node/v/ssh-mcp)](https://nodejs.org/)
[![License](https://img.shields.io/github/license/tufantunc/ssh-mcp)](./LICENSE)
[![GitHub Stars](https://img.shields.io/github/stars/tufantunc/ssh-mcp?style=social)](https://github.com/tufantunc/ssh-mcp/stargazers)
[![GitHub Forks](https://img.shields.io/github/forks/tufantunc/ssh-mcp?style=social)](https://github.com/tufantunc/ssh-mcp/forks)
[![Build Status](https://github.com/tufantunc/ssh-mcp/actions/workflows/publish.yml/badge.svg)](https://github.com/tufantunc/ssh-mcp/actions)
[![GitHub issues](https://img.shields.io/github/issues/tufantunc/ssh-mcp)](https://github.com/tufantunc/ssh-mcp/issues)

[![Trust Score](https://archestra.ai/mcp-catalog/api/badge/quality/tufantunc/ssh-mcp)](https://archestra.ai/mcp-catalog/tufantunc__ssh-mcp)

**SSH MCP Server** is a local Model Context Protocol (MCP) server that exposes SSH control for Linux and Windows systems, enabling LLMs and other MCP clients to execute shell commands securely via SSH.

## Contents

- [Quick Start](#quick-start)
- [Features](#features)
- [Installation](#installation)
- [Client Setup](#client-setup)
- [Testing](#testing)
- [Disclaimer](#disclaimer)
- [Support](#support)

## Quick Start

- [Install](#installation) SSH MCP Server
- [Configure](#configuration) SSH MCP Server
- [Set up](#client-setup) your MCP Client (e.g. Claude Desktop, Cursor, etc)
- Execute remote shell commands on your Linux or Windows server via natural language

## Features

- MCP-compliant server exposing SSH capabilities
- Execute shell commands on remote Linux and Windows systems
- Secure authentication via password or SSH key
- Built with TypeScript and the official MCP SDK
- **Multi-host mode** - reads `~/.ssh/config` and exposes all opted-in hosts as separate tools in a single process
- **Configurable timeout protection** with automatic process abortion
- **Graceful timeout handling** - attempts to kill hanging processes before closing connections
- **Execution mode selection** - choose per-command exec channels or a shared persistent shell session

### Tools

**Single-host mode** (default):

- `exec`: Execute a shell command on the remote server
- `sudo-exec`: Execute a shell command with sudo elevation

**Multi-host mode** (`--config`): tools are namespaced per host alias:

- `exec__<alias>`: Execute a shell command on the named host
- `sudo_exec__<alias>`: Execute a shell command with sudo on the named host

All `exec` / `exec__*` tools accept:
- `command` (required): Shell command to execute
- `description` (optional): Appended as a comment for audit trails

**Configuration:**
- Timeout: `--timeout` (ms, default 60000)
- Max command length: `--maxChars` (default 1000; use `none` or `0` for no limit)
- Disable sudo tool: `--disableSudo`

## Installation

1. **Clone the repository:**
   ```bash
   git clone https://github.com/tufantunc/ssh-mcp.git
   cd ssh-mcp
   ```
2. **Install dependencies:**
   ```bash
   npm install
   ```

## Client Setup

You can configure your IDE or LLM like Cursor, Windsurf, Claude Desktop to use this MCP Server.

### Multi-host mode (recommended)

One process, all your servers - controlled entirely from `~/.ssh/config`.

**Step 1 - Mark hosts in `~/.ssh/config`:**

```ssh-config
Host beryl
  HostName beryl.prv
  User root
  IdentityFile ~/.ssh/id_ed25519
  # MCP yes

Host va
  HostName va.vps.latentbyte.com
  User hmd
  IdentityFile ~/.ssh/id_ed25519
  # MCP yes
  # MCP-timeout 30000
  # MCP-maxChars none

Host old-box
  HostName old.example.com
  User admin
  # host is NOT enabled for agents - no `# MCP yes`
```

**Available `# MCP-*` directives** (all optional, per Host block):

| Directive | Example | Description |
|---|---|---|
| `# MCP yes` | | Enable this host for agents (required to opt in) |
| `# MCP-key <path>` | `# MCP-key ~/.ssh/other_key` | Override key path (falls back to `IdentityFile`) |
| `# MCP-timeout <ms>` | `# MCP-timeout 30000` | Per-host command timeout (default: 60000) |
| `# MCP-maxChars <n\|none>` | `# MCP-maxChars none` | Per-host max command length (default: 1000) |
| `# MCP-disableSudo` | | Disable `sudo_exec__<alias>` for this host |
| `# MCP-executionMode <mode>` | `# MCP-executionMode persistent-shell` | Execution strategy for this host |

**Step 2 - Add a single MCP server entry:**

```json
{
  "mcpServers": {
    "ssh-mcp": {
      "command": "npx",
      "args": ["--yes", "--package=ssh-mcp", "ssh-mcp", "--config"]
    }
  }
}
```

To use a non-default config file: `--config=/path/to/ssh_config`

This registers tools like `exec__beryl`, `sudo_exec__beryl`, `exec__va`, `sudo_exec__va` automatically.

---

### Single-host mode (one server per host)

Pass `--host` to target a specific server. Tools are named `exec` and `sudo-exec`.

**Required Parameters:**
- `host`: Hostname or IP of the remote server
- `user`: SSH username

**Optional Parameters:**
- `port`: SSH port (default: 22)
- `password`: SSH password (or use `key` for key-based auth)
- `key`: Path to private SSH key
- `sudoPassword`: Password for sudo elevation
- `suPassword`: Password for `su -` elevation (persistent root shell)
- `timeout`: Command execution timeout in milliseconds (default: 60000)
- `maxChars`: Max command characters (default: 1000; use `none` or `0` to disable)
- `disableSudo`: Flag to disable the `sudo-exec` tool completely
- `executionMode`: `exec` (default) or `persistent-shell`

```json
{
  "mcpServers": {
    "ssh-mcp-beryl": {
      "command": "npx",
      "args": [
        "--yes", "--package=ssh-mcp", "ssh-mcp",
        "--host=beryl.prv",
        "--port=22",
        "--user=root",
        "--key=/Users/you/.ssh/id_ed25519",
        "--timeout=30000",
        "--maxChars=none"
      ]
    }
  }
}
```

### Claude Code

**Multi-host (recommended) - add once, control all your servers:**

```bash
claude mcp add --transport stdio ssh-mcp -- npx --yes --package=ssh-mcp ssh-mcp --config
```

Then mark hosts in `~/.ssh/config` with `# MCP yes` as shown above.

**Single-host:**

```bash
claude mcp add --transport stdio ssh-mcp -- npx --yes --package=ssh-mcp ssh-mcp -- --host=YOUR_HOST --user=YOUR_USER --key=/path/to/key
```

For more information about MCP in Claude Code, see the [official documentation](https://docs.claude.com/en/docs/claude-code/mcp).

## Testing

You can use the [MCP Inspector](https://modelcontextprotocol.io/docs/tools/inspector) for visual debugging of this MCP Server.

```sh
npm run inspect
```

## Disclaimer

SSH MCP Server is provided under the [MIT License](./LICENSE). Use at your own risk. This project is not affiliated with or endorsed by any SSH or MCP provider.

## Contributing

We welcome contributions! Please see our [Contributing Guidelines](./CONTRIBUTING.md) for more information.

## Code of Conduct

This project follows a [Code of Conduct](./CODE_OF_CONDUCT.md) to ensure a welcoming environment for everyone.

## Support

If you find SSH MCP Server helpful, consider starring the repository or contributing! Pull requests and feedback are welcome. 
