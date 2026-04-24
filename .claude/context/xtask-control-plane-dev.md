# xtask: Control Plane Local Dev Stack

`cargo xtask control-plane dev` is a one-shot local development environment for the control plane. It starts `dynamodb-local` in a container, creates the table, seeds organizations, then launches the control-plane binary as a child process. Ctrl-C the child to exit; the container is stopped and removed automatically via `ContainerGuard`.

## What it does

Defined in `xtask/src/control_plane/dev.rs`.

1. **Detects the container runtime** (`docker` or `podman`) and starts `amazon/dynamodb-local` on a randomly assigned host port. The port is printed so other terminals can target it.
2. **Creates the DynamoDB table** (default `forgeguard-orgs-dev`) with `PK`/`SK` from the shared `orgs_schema()` in `infra/control-plane/schema/forgeguard-orgs.json`.
3. **Seeds organizations** from `examples/control-plane/orgs.test.json` (org rows only — no Cognito users, no membership rows).
4. **Launches the control plane** via `cargo run -p forgeguard_control_plane -- --store dynamodb --dynamodb-table <table> --listen <addr>` and waits on it.

The parent ignores `SIGINT` while the child runs so that Ctrl-C reaches only the child; when the child exits, the parent resumes and `ContainerGuard::drop` stops/removes the container.

## AWS env wiring

The CP binary builds one shared `aws_config::defaults(...)` `SdkConfig` and hands it to both the DynamoDB client and the Verified Permissions client (`crates/control-plane/src/app.rs:78-87`). Because the same config feeds every AWS client, the dev stack has to scope its overrides carefully or they leak to services that should hit real AWS.

The child inherits the parent shell's environment with two overrides:

| Env var | Value | Why |
|---|---|---|
| `AWS_ENDPOINT_URL_DYNAMODB` | `http://127.0.0.1:<port>` | Per-service endpoint override. Scopes the redirect to DynamoDB only. The service-unspecific `AWS_ENDPOINT_URL` would redirect VP/Cognito to `dynamodb-local` too — you'd see responses from the local Jetty server (`com.amazonaws.dynamodb.v20120810#InvalidAction`) being interpreted as a VP deny. `aws-config` 1.x resolves `AWS_ENDPOINT_URL_<SERVICE>` natively via its default provider chain. |
| `AWS_REGION` | `us-east-2` | Pins the region so the child has a deterministic value regardless of what the caller's shell or profile sets. |

**No access-key env vars are set.** The SDK's default credential provider chain resolves credentials from the parent shell (typically `AWS_PROFILE=admin` + an active SSO session). Why not force `AWS_ACCESS_KEY_ID=test`/`AWS_SECRET_ACCESS_KEY=test` like some dynamodb-local guides suggest?

- VP and Cognito calls go to real AWS and reject synthetic credentials with `AccessDeniedException: "The security token included in the request is invalid."`
- `dynamodb-local` accepts any signed request, so real SSO credentials work for it as well. There's no reason to force a fake pair.

Because credential inheritance is silent, the launch banner reminds the operator to set `AWS_PROFILE` and refresh the SSO session before starting dev.

## What `dev` seeds vs what it does not

`dev` writes only organization rows to the local table. It does **not** provision Cognito users, membership rows, or 1Password secrets. Run `cargo xtask control-plane seed --dynamodb-endpoint http://127.0.0.1:<port> --dynamodb-table forgeguard-orgs-dev` in a second terminal to populate the rest of the fixture data. See [xtask-control-plane-tools.md](./xtask-control-plane-tools.md).

## Ports and cleanup

Each `dev` invocation picks a free ephemeral port for `dynamodb-local`; the launch message prints both the container id and the endpoint URL. When the child exits, `ContainerGuard` stops and removes the container. Crashed runs can leave orphan containers behind:

```sh
docker ps --filter ancestor=amazon/dynamodb-local --format "{{.Names}}\t{{.Ports}}"
docker rm -f <name>
```

The CP binary listens on `127.0.0.1:3001` by default (override with `--listen`).

## Typical workflow

```sh
export AWS_PROFILE=admin
aws sso login --profile admin

# Terminal 1
cargo xtask control-plane dev
# → "Starting dynamodb-local on port 55005"
# → "Launching control plane (listen: 127.0.0.1:3001, table: forgeguard-orgs-dev, endpoint: http://127.0.0.1:55005)..."

# Terminal 2 — populate Cognito users + membership rows
cargo xtask control-plane seed \
  --dynamodb-endpoint http://127.0.0.1:55005 \
  --dynamodb-table forgeguard-orgs-dev

# Terminal 2 — exercise an authenticated flow
TOKEN=$(cargo xtask control-plane token --user acme-admin)
curl -i -X POST http://127.0.0.1:3001/api/v1/organizations/org-acme/keys \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-ForgeGuard-Org-Id: org-acme"
```

## Flags

| Flag | Env var | Default |
|---|---|---|
| `--table` | `FORGEGUARD_CP_DYNAMODB_TABLE` | `forgeguard-orgs-dev` |
| `--listen` | `FORGEGUARD_CP_LISTEN` | `127.0.0.1:3001` |
| `--seed` | — | `examples/control-plane/orgs.test.json` |
| trailing `--` args | — | forwarded verbatim to the CP binary |
