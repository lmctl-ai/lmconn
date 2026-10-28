# lmconnectors

`lmconn`: connectors for AI-agent workflows. One CLI, scriptable from
lmscript through `system()` or as a cli.schema.v1 module. Credentials live
in one SQLite database (`node:sqlite`), like n8n's credential store, minus
the server.

## Install

```sh
npm link        # puts lmconn on PATH
```

## Quickstart

```sh
lmconn cred set deepseek api_key --env DEEPSEEK_API_KEY   # store without echoing
lmconn cred list                                          # names only
lmconn llm providers                                      # who is configured
lmconn llm chat deepseek --prompt "say ok"
lmconn llm chat claude --prompt "say ok"                  # agent CLI adapter
lmconn llm probe                                          # one live call per provider
lmconn --cli-schema --json                                # cli.schema.v1 document
```

## Layout

- `src/creds.js` — SQLite credential store
- `src/providers/` — LLM provider registry and adapters (API + agent CLI)
- `src/cmd-*.js` — command areas (`cred`, `llm`, `http`, `github`)
- `schema/` — generated cli.schema.v1 for lmscript import
- `examples/` — lmscript scripts that drive lmconn

See AGENTS.md for the engineering contracts.
