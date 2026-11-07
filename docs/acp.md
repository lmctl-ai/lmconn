# ACP client

`lmconn acp chat` talks to any [Agent Client Protocol](https://agentclientprotocol.com)
agent that speaks newline-delimited JSON-RPC on stdio, and runs a multi-turn
conversation in one session: `initialize` → `session/new` → one `session/prompt`
per turn. Agent text arrives as `agent_message_chunk` updates and each turn ends
with a `stopReason`.

```sh
lmconn acp chat --command gemini --arg --experimental-acp \
  --prompt "Hello" --prompt "Summarise that in one line"
```

Result envelope:

```json
{"ok":true,"result":{"sessionId":"…","agentCapabilities":{},"turns":[
  {"prompt":"Hello","text":"Hi there!","chunks":["Hi ","there!"],"stopReason":"end_turn"}]}}
```

Flags: `--command` (required), `--arg` (repeatable, may start with `--`),
`--prompt` (repeatable) or `--prompts-file` (JSON array of strings), `--cwd`,
`--timeout-ms` (per request, default 30000), `--auto-approve`.

Agent→client requests: `session/request_permission` is cancelled unless
`--auto-approve` (then the first `allow_*` option is chosen); `fs/*` and
`terminal/*` are refused with `-32601` and not advertised as capabilities.

Errors: `USAGE` (exit 2), `SPAWN`, `AGENT_EXIT`, `AGENT_ERROR`, `PROTOCOL`,
`TIMEOUT` (exit 1). The library API is `AcpClient` / `converse` in `src/acp.js`.

## Testing against lmmock

[lmmock](https://github.com/lmctl-ai/lmmock) ships an ACP server mock
(`lmmock stdio acp`, see its `docs/acp.md`). `test/acp-lmmock.test.js` drives a
three-turn conversation against it using `test/mocks/acp-conversation.json`
(a copy of lmmock's `tests/stdio/acp-conversation.json`):

```sh
LMMOCK_BIN=/path/to/lmmock npm test
```

The integration tests skip when no lmmock with `stdio acp` is on PATH.
`test/acp.test.js` covers the client hermetically with a small Node fake agent.
