# CLI (`forgeguard`)

The developer CLI for config validation, policy management, and route inspection.

## Subcommands

| Command | Purpose | I/O? |
|---------|---------|------|
| `forgeguard check --config <path>` | Parse + validate config, exit 0/1 | File read only |
| `forgeguard routes --config <path>` | Print route table from config | File read only |
| `forgeguard policies validate` | Validate Cedar policies locally | File read only |
| `forgeguard policies sync` | Sync policies to Verified Permissions | AWS API calls |
| `forgeguard policies test` | Test authorization decisions against VP | AWS API calls |

## Architecture (FCIS)

- `check.rs` — thin I/O shell calling `forgeguard_http::load_config()`
- `routes.rs` — pure `format_route_table(&ProxyConfig) -> String` + I/O `run()` wrapper
- `policies/` — each subcommand follows the same pattern

The formatting logic in `routes.rs` is a pure function with unit tests. The `run()` function handles only file I/O and printing.

## Route Table Output

```
METHOD   PATH                                          ACTION                    AUTH            GATE
--------------------------------------------------------------------------------------------------------------
GET      /health                                       -                         anonymous       -
POST     /webhooks/:provider                           -                         anonymous       -
GET      /docs/:page                                   -                         opportunistic   -
GET      /api/lists                                    todo:list:list            required        -
GET      /api/lists/:id/suggestions                    todo:list:suggest         required        todo:ai-suggestions
```

## Key Files

| File | Role |
|------|------|
| `crates/cli/src/main.rs` | CLI entry, command dispatch |
| `crates/cli/src/check.rs` | Config validation command |
| `crates/cli/src/routes.rs` | Route table formatting (pure) + display |
| `crates/cli/src/policies/` | Policy validate, sync, test commands |
