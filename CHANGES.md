# Changelog

## v1.3.0

### Bug Fixes

**`gateway/main.go` — Challenge/session HMAC verification always failed**

`signBlob` computes the HMAC over the base64-*encoded* payload string, but `verifyBlob` was
computing it over the *decoded* raw bytes — a different byte sequence, so `hmac.Equal` could
never match. Every challenge solution and every session cookie failed verification
unconditionally: with `global_default: "CHALLENGE"` (the shipped default), no unregistered
visitor could ever actually pass the PoW challenge — they'd solve the puzzle correctly and still
get `403` from `/__sanctuary/verify`, stuck in an unbreakable redirect loop. Only found by
actually running the stack end-to-end and solving a real puzzle against it (`docker compose up`
+ a scripted client), not by static review. Fixed by computing the MAC over the encoded string in
both directions.

**`mint/main.go` — Key persistence compile failure**

`loadOrGenerateKey` called `ed25519.UnmarshalPrivateKey`/`ed25519.MarshalPrivateKey`, neither of
which exist in Go's standard `crypto/ed25519` package (`PrivateKey` is already a raw `[]byte`).
The mint service could not compile. Fixed by reading/writing the key bytes directly.

**`gateway/main.go` — Unlocked config reads racing SIGHUP reload**

`IngestionGatewayHandler` and `VerifyHandler` read `globalPolicy` fields directly, without
`globalPolicyMu.RLock()`, while `reloadConfig()` (triggered by SIGHUP) replaces `globalPolicy`
under the write lock. Both handlers now snapshot every field they need under a single `RLock()`
at the top of the request instead.

**`gateway/main.go` — Signature recorded in the replay cache before verification**

`verifyTokenHandshake` called `tokenCache.storeIfAbsent` before `ed25519.Verify`, so a malformed
or invalid signature attempt still consumed a cache slot under its literal string. Verification
now runs first; only a signature that actually validates gets recorded as seen.

### Security Fixes

**`gateway/main.go` — Unauthenticated `X-Forwarded-For` spoofing**

`clientIP` trusted `X-Forwarded-For` from any client, letting a request spoof its own IP to get
a fresh rate-limit bucket per request and to forge the IP-bound session cookie check. Added
`GATEWAY_TRUSTED_PROXIES` (comma-separated CIDRs, env var) — `X-Forwarded-For` is now only
honored when `RemoteAddr` is inside that set; otherwise `RemoteAddr` is used directly. Unset by
default (nothing is trusted).

### Adaptive proof-of-work difficulty and route-tiered challenge policy

**`gateway/main.go`, `config/ai-permissions.json`**

Puzzle difficulty and session TTL were both fixed, site-wide constants. Added
`pow_challenge.hosting_difficulty_bonus`, added on top of `difficulty_bits` for requests from
`known_hosting_cidrs` (previously an audit-log-only signal). Added `route_overrides`, a list of
`{path_prefix, difficulty_bits, session_ttl_seconds}` entries letting specific paths demand a
harder puzzle and a shorter-lived session than the site-wide default — the first matching prefix
wins, falling back to the site-wide `pow_challenge` values when nothing matches (empty list by
default, so existing deployments are unaffected until they opt in).

### Richer session binding

**`gateway/main.go`**

`sanctuary_session` was bound to `sha256(client_ip)` alone, so a cookie stolen or replayed from a
different client profile behind the same (or a rotated but same-subnet) IP would still validate.
The session payload now carries `sha256(ip + user_agent + accept_language)` and the difficulty
tier it was earned at, so a session solved for a lower-difficulty route no longer authorizes a
path whose `route_overrides` entry demands a higher one — the client gets redirected to solve a
fresh, harder challenge instead of silently passing.

---

## v1.2.0

### Monetization made optional

**`config/ai-permissions.json`, `mint/main.go`, `gateway/main.go`**

Payment was previously mandatory for any aggregator to be minted a usable token. Added
`ingestion_governance.monetization_enabled` (default `false`) — `mint`'s
`validatePaymentProof` check now only runs when it's `true`. `mint` reads this from the
same policy file the gateway uses, so `docker-compose.yml` now mounts `./config` and sets
`CONFIG_PATH` for the `mint` service too (previously it had no config access at all).
`access_status` on `authorized_aggregators` entries generalized from the hardcoded
`"CONDITIONAL"` string to `"ALLOWED_PAID"` / `"ALLOWED_FREE"`.

---

### Self-hosted proof-of-work challenge for unrecognized traffic

**`gateway/main.go`**

Previously, any request whose `User-Agent` wasn't a pre-registered aggregator was denied
outright — the gateway never actually served general site traffic. Added a new
`global_default: "CHALLENGE"` mode (now the default): unrecognized traffic is redirected
to `/__sanctuary/challenge`, a self-contained HTML+JS page that solves a small SHA-256
proof-of-work puzzle client-side, then `POST`s the solution to `/__sanctuary/verify` for a
short-lived signed `sanctuary_session` cookie. Challenges and sessions are HMAC-signed,
self-contained blobs — no server-side challenge storage, no third-party CAPTCHA service.
This costs a human requester a few hundred imperceptible milliseconds; a script that never
executes JavaScript can't solve it at all, and a headless browser that does pays real
compute on every solve. `global_default: "DENY"` (strict allowlist-only) and `"ALLOW"`
(fully open, no challenge) remain available.

---

### Per-IP rate limiting

**`gateway/main.go`**

No throttling existed anywhere — an unbounded flood of requests, authorized or not, cost
only the O(1) rejection check. Added `RateLimiter`, a per-IP token bucket
(`rate_limit.requests_per_minute` / `burst`), evicting idle buckets on the same periodic
janitor pattern as `HardenedTokenCache`. Requests over the limit get `429`.

---

### Known-hosting-range and blocked-UA signals

**`gateway/main.go`, `config/ai-permissions.json`**

Added `blocked_user_agents`, an explicit deny-list checked before any other logic (ships
with a starter set of known AI-training crawler UAs), and `known_hosting_cidrs`, a
datacenter/cloud IP-range list logged as a heightened-suspicion audit signal only — not
auto-blocking, since datacenter/VPN traffic alone isn't proof of a bot.

---

### Structured, IP-aware audit logging

**`gateway/main.go`**

Source IP was never captured anywhere in the previous version, and audit entries were
unstructured `log.Printf` strings. Added `clientIP` (reads `X-Forwarded-For`, falls back
to `RemoteAddr`) and `auditLog`, which emits one structured JSON line per decision
(timestamp, event, IP, UA, path) — needed for any real evidence trail of scraping
attempts, not just human-readable debug output.

---

### Status-code cleanup

**`gateway/main.go`**

Failed/missing signature handshakes previously returned a blanket `402 Payment Required`,
which conflated "not cryptographically valid" with "didn't pay" even though payment is no
longer the default framing. Handshake failures and directory-permission denials now return
`403`; `402` is no longer used by the gateway (mint still returns it for a declined
payment when `monetization_enabled` is `true`).

---

### Removed `gateway/filter.wasm`

Empty (0-byte) unused stub. The proof-of-work/challenge logic above lives natively in Go;
no WASM plugin layer is used.

---

## v1.1.1

### Bug Fixes

**`gateway/main.go` — Status code serialization (`executeSilenceProtocol`)**

`string(rune(status))` was used to convert an integer HTTP status code to a string. In Go, casting an integer to `rune` then to `string` produces the Unicode character at that code point, not the decimal text representation — `string(rune(403))` yields `"ǃ"`, not `"403"`. Fixed by replacing with `strconv.Itoa(status)`, which produces the correct numeric string.

---

### Security Fixes

**`gateway/main.go` — Unbounded `sync.Map` memory growth**

The bare `sync.Map` used for replay prevention stored every seen token signature indefinitely with no eviction. Under sustained traffic, or a deliberate flood of unique signatures, this would grow without bound and exhaust container memory.

Replaced with `HardenedTokenCache`, a thin wrapper around `sync.Map` that records a `seenAt` Unix timestamp alongside each entry. A background goroutine sweeps the map every 10 minutes and deletes entries older than the 24-hour TTL, bounding memory to the rolling window of unique traffic volume.

The replay check itself (`storeIfAbsent`) remains unconditional — any previously seen signature is rejected regardless of TTL state. The TTL controls eviction only; signatures become replayable after the window elapses, so the TTL must be greater than or equal to the mint service's intended token validity window.

---

### Infrastructure Fixes

**`docker-compose.yml` — Mint service port exposure**

The `mint` service had `ports: "8081:8081"`, which bound the cryptographic signing endpoint to the host's public network interface. Any process with host network access could reach the mint directly, bypassing the gateway entirely.

Replaced with `expose: "8081"`, which makes the port reachable only to other containers on the internal `sanctuary_network` bridge. The gateway can still call `http://mint:8081/v1/mint` as before; the port is no longer externally addressable.
