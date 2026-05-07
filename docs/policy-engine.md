# Policy engine

Agent Policy Vault adds a fail-closed **Policy Decision Point (PDP)** on the transparent proxy path. After a request matches a brokered service and a credential is resolved, the engine evaluates declarative policies bound to the agent via **grants** before the upstream call proceeds.

## Concepts

- **Policy** — YAML/JSON document (versioned per vault) describing allowed methods, path patterns, body constraints, rate limits, time windows, and quotas. Stored `content_hash` must match a canonical recomputation on every evaluation (tamper detection).
- **Grant** — Binds a subject (`agent` or `user`) to a policy version (or “latest”) with optional expiry. Multiple grants compose conservatively: all applicable grants must allow.
- **Audit** — `policy_audit` records creates, revokes, and deny/allow decisions (hash mismatch yields `decision.deny` with rule `hash-mismatch`).

## HTTP API

Routes under `POST|GET|DELETE /v1/vaults/{vault}/policies` and `/grants` require a **user** session with vault **member** or **admin** role. Agent tokens receive `403` on mutations.

## CLI

See `agent-vault policies --help` and `agent-vault grants --help`.

## Smoke test

With a running server, registered user, vault, credential, service, policy, and grant:

```bash
# Use vault run or HTTPS_PROXY with a proxy session token.
HTTPS_PROXY="http://<token>:vault@127.0.0.1:14322" curl -sS "https://api.example.com/v1/allowed-path"
```

Denials return `403` from the proxy with a `policy_denied` style log line (see server / MITM logging).

## Permission registry

Parameterized, signed policy templates are **not** implemented in this milestone; see product design notes for future `PolicyTemplate` / registry sources.
