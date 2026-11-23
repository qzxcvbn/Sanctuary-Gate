# Sanctuary Gate

An open-source, edge-computing gateway that stops unconsented bulk scraping of a site's content — by unrecognized bots outright, and by registered aggregators unless they hold a valid cryptographic handshake.

## Architecture

Sanctuary Gate intercepts automated scraping and data-mining agents at the network edge. Instead of relying on voluntary compliance structures (like `robots.txt`), it enforces a layered defense: known-bad bots are denied outright, registered aggregators must present a cryptographic handshake, and everything else (general site traffic, including real visitors) passes through a self-hosted proof-of-work challenge.

The architecture consists of two decoupled services communicating over an isolated internal network:

1. **Gateway Proxy (`/gateway`)** — A high-performance edge service that filters inbound requests using a deny-list, per-IP rate limiting, Ed25519 signature checks with atomic replay-attack protection, and a self-hosted proof-of-work challenge.
2. **Token Mint Oracle (`/mint`)** — A stateless service that acts as a secure signing oracle, issuing Ed25519 identity tokens to registered aggregators.

### Verification Matrix

1. **Tier 0 (Deny-list):** Requests matching `blocked_user_agents` (known AI-training crawlers) are refused immediately.
2. **Tier 1 (Rate Limiting):** Per-IP token bucket (`requests_per_minute` / `burst`) throttles request velocity.
3. **Tier 2 (Cryptographic Proof):** Registered aggregators must present a unique request nonce with an Ed25519 signature from their delegated public key.
4. **Tier 3 (Replay Defense):** Submits the signature to an internal atomic cache to block high-frequency replay injections.
5. **Tier 4 (Directory Mapping):** Checks path access patterns against `authorized_aggregators` entries.
6. **Tier 5 (Proof-of-Work Challenge):** Unrecognized traffic is redirected to `/__sanctuary/challenge`, a self-hosted HTML+JS page that solves a SHA-256 proof-of-work puzzle client-side. On success, a short-lived signed session cookie is issued.

`global_default` can be set to `"CHALLENGE"` (default), `"DENY"` (strict allowlist), or `"ALLOW"` (fully open).

All decisions are emitted as structured JSON audit log lines (including source IP) for building an evidence trail.

## Getting Started

### Prerequisites

- Docker and Docker Compose V2

### Configuration

Key `config/ai-permissions.json` toggles:

- `global_default` — `"CHALLENGE"` (default), `"DENY"`, or `"ALLOW"`
- `monetization_enabled` — `false` by default. Set `true` to require payment verification for `ALLOWED_PAID` aggregators.
- `blocked_user_agents` — explicit deny-list of known AI-training crawlers.
- `known_hosting_cidrs` — datacenter/cloud IP ranges used as an audit-log signal only.
- `rate_limit` / `pow_challenge` — tune `requests_per_minute`, `burst`, `difficulty_bits`, and TTLs.
- `route_overrides` — per-path difficulty and session TTL overrides.

### Deployment

1. Configure your crawler governance rules and expected public keys inside `config/ai-permissions.json`.
2. Optionally configure an upstream backend via `UPSTREAM_URL` environment variable to forward authorized traffic.
3. Spin up the service mesh using Docker Compose:

```bash
docker-compose up --build -d
```

4. Verify both services are running:

```bash
curl http://localhost:8080/health
curl http://localhost:8081/health
```

## Upstream Reverse Proxy

By default, the gateway returns static text responses for authorized requests. Set `UPSTREAM_URL` to forward traffic to a backend:

```yaml
environment:
  - UPSTREAM_URL=http://web-backend:80
```

When configured, any request that passes the authorization pipeline is proxied to the upstream server. Without it, the gateway terminates the request with a text response.

## Cookie Security

The `sanctuary_session` cookie is set with `Secure: true` when the request arrives via HTTPS (`r.TLS != nil`) or when `X-Forwarded-Proto: https` is received from a trusted proxy. In local development accessed over plain HTTP, the cookie is set without the Secure flag.

## Configuration Reference

| Setting | Default | Description |
|---|---|---|
| `global_default` | `"CHALLENGE"` | What to do with unrecognized traffic |
| `enforced_handshake` | `true` | Require Ed25519 signature from registered aggregators |
| `monetization_enabled` | `false` | Require payment verification before minting |
| `rate_limit.requests_per_minute` | `60` | Sustained rate per IP |
| `rate_limit.burst` | `requests_per_minute` | Burst capacity |
| `pow_challenge.enabled` | `true` | Enable proof-of-work challenge |
| `pow_challenge.difficulty_bits` | `18` | SHA-256 leading zero bits required |
| `pow_challenge.hosting_difficulty_bonus` | `4` | Extra difficulty for datacenter IPs |
| `GATEWAY_TRUSTED_PROXIES` | *(empty)* | CIDRs allowed to set X-Forwarded-For |

## Health Checks

Both services expose `/health`:

```bash
curl http://localhost:8080/health  # Gateway
curl http://localhost:8081/health  # Mint
```

The mint service exposes its signing endpoint internally on port 8081 (not published to the host). Use:

```bash
curl -X POST http://localhost:8081/v1/mint \
  -H 'Content-Type: application/json' \
  -d '{"contract_id":"abc","token_count":1,"payload_nonces":["deadbeef00000000"]}'
```

## Environment Variables

| Variable | Service | Description |
|---|---|---|
| `CONFIG_PATH` | Both | Path to `ai-permissions.json` |
| `MINT_KEY_DIR` | Mint | Directory for persistent Ed25519 key (`./keys` default) |
| `KEY_DIR` | Gateway | Directory for persistent challenge HMAC key (survives restarts) |
| `GATEWAY_CHALLENGE_SECRET` | Gateway | Optional 64-hex-char HMAC seed — if set, the challenge key persists across restarts and multi-instance deployments. If unset, an ephemeral key is generated and persisted to `KEY_DIR`. |
| `GATEWAY_TRUSTED_PROXIES` | Gateway | Comma-separated CIDRs for X-Forwarded-For trust |
| `UPSTREAM_URL` | Gateway | Optional reverse proxy target (e.g., `http://backend:80`). When set, authorized requests and passed challenges are forwarded upstream. When unset, the gateway returns static text responses (the original behavior). |
| `GATEWAY_TLS_CERT` / `GATEWAY_TLS_KEY` | Gateway | TLS certificate and key (optional) |
| `MINT_TLS_CERT` / `MINT_TLS_KEY` | Mint | TLS certificate and key (optional) |

## Audit Log Parsing

The gateway emits structured JSON audit lines. To parse with `jq`:

```bash
docker logs sanctuary_gate_edge 2>&1 | jq -c 'select(.event)'
```

Example: extract all blocked requests in the last hour:

```bash
docker logs sanctuary_gate_edge 2>&1 | jq -c 'select(.event == "blocked-user-agent")'
```

## License

This project is licensed under the [Apache License 2.0](LICENSE).
