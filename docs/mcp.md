# MCP client (stdio)

`lmconn mcp` is a [Model Context Protocol](https://modelcontextprotocol.io) client
(protocol `2025-11-25`) that spawns a server as a subprocess and talks
newline-delimited JSON-RPC over its stdin/stdout. No network is involved.

```sh
lmconn mcp tools     --command npx --arg -y --arg @modelcontextprotocol/server-everything
lmconn mcp call      --command my-server --tool add --arguments '{"a":1,"b":2}'
lmconn mcp session   --command my-server \
  --call '{"name":"search","arguments":{"q":"x"}}' --call '{"name":"fetch","arguments":{"id":1}}'
lmconn mcp resources|prompts --command my-server
lmconn mcp read      --command my-server --uri file:///note
lmconn mcp prompt    --command my-server --name greet --arguments '{"who":"mcp"}'
```

Common flags: `--command` (required), `--arg` (repeatable, may start with `--`),
`--cwd`, `--timeout-ms` (per request, default 30000). `session` runs its `--call`s
in order inside one connection; `call` and `session` results carry `text`,
`content`, `isError` and the server's `notifications/message` logs for that call.

Server→client requests: `ping` is answered; sampling, elicitation and roots are
refused with `-32601` (the client advertises no capabilities).

Errors: `USAGE` (exit 2), `SPAWN`, `SERVER_EXIT`, `SERVER_ERROR` (JSON-RPC error
from the server), `PROTOCOL`, `TIMEOUT` (exit 1). Library API: `McpClient` /
`withMcp` in `src/mcp.js`, on the shared stdio transport in `src/rpc-stdio.js`
(also used by the ACP client).

## Testing against lmmock

`lmmock stdio mcp` is the server mock (see lmmock's `docs/mcp.md`).
`test/mcp-lmmock.test.js` runs discovery, a multi-call session (three results and
a scripted error), out-of-script calls and the CLI against it using
`test/mocks/mcp-conversation.json` (a copy of lmmock's
`tests/stdio/mcp-conversation.json`):

```sh
LMMOCK_BIN=/path/to/lmmock npm test
```

Skipped when no lmmock with `stdio mcp` is on PATH. `test/mcp.test.js` covers the
client hermetically with `test/mocks/mcp-fake-server.mjs`.
