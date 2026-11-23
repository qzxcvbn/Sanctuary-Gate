package main

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"html/template"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

type IngestionPolicy struct {
	PolicyMetadata struct {
		Version        string `json:"version"`
		LegalFramework string `json:"legal_framework"`
	} `json:"policy_metadata"`
	IngestionGovernance struct {
		GlobalDefault       string   `json:"global_default"`
		EnforcedHandshake   bool     `json:"enforced_handshake"`
		MonetizationEnabled bool     `json:"monetization_enabled"`
		PublicDirectories   []string `json:"public_directories"`
		BlockedUserAgents   []string `json:"blocked_user_agents"`
		KnownHostingCIDRs   []string `json:"known_hosting_cidrs"`
		RateLimit           struct {
			RequestsPerMinute float64 `json:"requests_per_minute"`
			Burst             float64 `json:"burst"`
		} `json:"rate_limit"`
		PowChallenge struct {
			Enabled                bool  `json:"enabled"`
			DifficultyBits         int   `json:"difficulty_bits"`
			HostingDifficultyBonus int   `json:"hosting_difficulty_bonus"`
			ChallengeTTLSeconds    int64 `json:"challenge_ttl_seconds"`
			SessionTTLSeconds      int64 `json:"session_ttl_seconds"`
		} `json:"pow_challenge"`
		RouteOverrides []struct {
			PathPrefix        string `json:"path_prefix"`
			DifficultyBits    int    `json:"difficulty_bits"`
			SessionTTLSeconds int64  `json:"session_ttl_seconds"`
		} `json:"route_overrides"`
		AuthorizedAggregators map[string]struct {
			AccessStatus             string   `json:"access_status"`
			MintPublicKey            string   `json:"mint_public_key"`
			PermittedDirectories     []string `json:"permitted_directories"`
			MonetizationHandshakeURL string   `json:"monetization_handshake_url"`
		} `json:"authorized_aggregators"`
	} `json:"ingestion_governance"`
}

type cacheEntry struct {
	seenAt int64 // Unix timestamp (UTC)
}

// HardenedTokenCache wraps sync.Map with TTL-based eviction to bound memory growth.
// The TTL governs eviction only — replay protection blocks any previously seen
// signature unconditionally; once a signature is evicted it becomes replayable,
// so TTL must be >= the token validity window enforced by the mint service.
type HardenedTokenCache struct {
	mapping sync.Map
	ttl     time.Duration
}

// storeIfAbsent records the signature if not already present. Returns true if the
// signature was already in the cache (i.e., this is a replay attempt).
func (c *HardenedTokenCache) storeIfAbsent(sig string) (alreadySeen bool) {
	_, loaded := c.mapping.LoadOrStore(sig, cacheEntry{seenAt: time.Now().UTC().Unix()})
	return loaded
}

func (c *HardenedTokenCache) startJanitor(interval time.Duration) {
	ticker := time.NewTicker(interval)
	for range ticker.C {
		now := time.Now().UTC().Unix()
		evicted := 0
		c.mapping.Range(func(key, value any) bool {
			if now-value.(cacheEntry).seenAt >= int64(c.ttl.Seconds()) {
				c.mapping.Delete(key)
				evicted++
			}
			return true
		})
		if evicted > 0 {
			log.Printf("[MAINTENANCE] Token cache sweep complete. Evicted %d expired signatures.", evicted)
		}
	}
}

// bucket is a per-key token bucket used by RateLimiter.
type bucket struct {
	mu         sync.Mutex
	tokens     float64
	lastRefill time.Time
}

// RateLimiter is a simple per-key token-bucket limiter, bounded the same way
// HardenedTokenCache bounds replay-signature memory: a periodic janitor evicts
// buckets that have gone idle rather than letting the map grow unbounded.
type RateLimiter struct {
	buckets           sync.Map // string -> *bucket
	requestsPerMinute float64
	burst             float64
}

func newRateLimiter(requestsPerMinute, burst float64) *RateLimiter {
	if requestsPerMinute <= 0 {
		requestsPerMinute = 60
	}
	if burst <= 0 {
		burst = requestsPerMinute
	}
	return &RateLimiter{requestsPerMinute: requestsPerMinute, burst: burst}
}

func (rl *RateLimiter) Allow(key string) bool {
	now := time.Now()
	value, _ := rl.buckets.LoadOrStore(key, &bucket{tokens: rl.burst, lastRefill: now})
	b := value.(*bucket)

	b.mu.Lock()
	defer b.mu.Unlock()

	elapsed := now.Sub(b.lastRefill).Seconds()
	b.tokens += elapsed * (rl.requestsPerMinute / 60)
	if b.tokens > rl.burst {
		b.tokens = rl.burst
	}
	b.lastRefill = now

	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

func (rl *RateLimiter) startJanitor(interval, idleTTL time.Duration) {
	ticker := time.NewTicker(interval)
	for range ticker.C {
		now := time.Now()
		evicted := 0
		rl.buckets.Range(func(key, value any) bool {
			b := value.(*bucket)
			b.mu.Lock()
			idle := now.Sub(b.lastRefill)
			b.mu.Unlock()
			if idle >= idleTTL {
				rl.buckets.Delete(key)
				evicted++
			}
			return true
		})
		if evicted > 0 {
			log.Printf("[MAINTENANCE] Rate limiter sweep complete. Evicted %d idle buckets.", evicted)
		}
	}
}

var (
	globalPolicy        IngestionPolicy
	globalPolicyMu      sync.RWMutex
	tokenCache          *HardenedTokenCache
	rateLimiter         *RateLimiter
	hostingCIDRs        []*net.IPNet
	challengeSigningKey []byte
	trustedProxyCIDRs   []*net.IPNet
	upstreamProxy       *httputil.ReverseProxy
)

func reloadConfig() error {
	configPath := os.Getenv("CONFIG_PATH")
	if configPath == "" {
		configPath = "./config/ai-permissions.json"
	}

	file, err := os.Open(configPath)
	if err != nil {
		return err
	}
	defer file.Close()

	bytes, err := io.ReadAll(file)
	if err != nil {
		return err
	}

	var newPolicy IngestionPolicy
	if err := json.Unmarshal(bytes, &newPolicy); err != nil {
		return err
	}

	// Parse CIDRs
	var newCIDRs []*net.IPNet
	for _, cidr := range newPolicy.IngestionGovernance.KnownHostingCIDRs {
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			log.Printf("[WARN] Skipping invalid hosting CIDR %q: %v", cidr, err)
			continue
		}
		newCIDRs = append(newCIDRs, network)
	}

	// Validate aggregator public key lengths — Ed25519 public keys are exactly 32 bytes = 64 hex chars.
	// Log warnings for malformed keys so misconfigurations are visible before they cause silent failures.
	for name, cfg := range newPolicy.IngestionGovernance.AuthorizedAggregators {
		if cfg.MintPublicKey != "" {
			if len(cfg.MintPublicKey) != 64 {
				log.Printf("[WARN] Invalid public key for aggregator %q: expected 64 hex chars, got %d", name, len(cfg.MintPublicKey))
			} else if _, err := hex.DecodeString(cfg.MintPublicKey); err != nil {
				log.Printf("[WARN] Non-hex characters in public key for aggregator %q: %v", name, err)
			}
		}
	}

	globalPolicyMu.Lock()
	globalPolicy = newPolicy
	hostingCIDRs = newCIDRs
	globalPolicyMu.Unlock()

	log.Printf("[CONFIG] Configuration reloaded successfully. Version: %s", newPolicy.PolicyMetadata.Version)
	return nil
}

func init() {
	log.SetFlags(log.Ldate | log.Ltime | log.LUTC)

	for _, cidr := range strings.Split(os.Getenv("GATEWAY_TRUSTED_PROXIES"), ",") {
		cidr = strings.TrimSpace(cidr)
		if cidr == "" {
			continue
		}
		_, network, err := net.ParseCIDR(cidr)
		if err != nil {
			log.Fatalf("[CRITICAL] Invalid GATEWAY_TRUSTED_PROXIES entry %q: %v", cidr, err)
		}
		trustedProxyCIDRs = append(trustedProxyCIDRs, network)
	}
	if len(trustedProxyCIDRs) == 0 {
		log.Printf("[WARN] GATEWAY_TRUSTED_PROXIES not set; X-Forwarded-For will be ignored and RemoteAddr used directly.")
	}

	if err := reloadConfig(); err != nil {
		log.Fatalf("[CRITICAL] Configuration load failure: %v", err)
	}

	if !globalPolicy.IngestionGovernance.EnforcedHandshake {
		log.Printf("[WARN] Enforced handshake disabled — registered aggregators may operate without cryptographic proof.")
	}

	rateLimiter = newRateLimiter(
		globalPolicy.IngestionGovernance.RateLimit.RequestsPerMinute,
		globalPolicy.IngestionGovernance.RateLimit.Burst,
	)
	go rateLimiter.startJanitor(10*time.Minute, time.Hour)

	challengeSigningKey = loadOrGenerateChallengeKey()

	// Set up optional upstream reverse proxy. When configured, authorized requests
	// and passed challenges are forwarded to the backend instead of returning static text.
	if upstreamURL := os.Getenv("UPSTREAM_URL"); upstreamURL != "" {
		parsed, err := url.Parse(upstreamURL)
		if err != nil {
			log.Printf("[WARN] Invalid UPSTREAM_URL %q: %v — gateway will respond with static text.", upstreamURL, err)
		} else {
			upstreamProxy = httputil.NewSingleHostReverseProxy(parsed)
			log.Printf("[INIT] Upstream reverse proxy configured for %s", upstreamURL)
		}
	}

	tokenCache = &HardenedTokenCache{ttl: 24 * time.Hour}
	go tokenCache.startJanitor(10 * time.Minute)

	// SIGHUP handler for config hot-reload
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGHUP)
	go func() {
		for range sigChan {
			log.Printf("[CONFIG] SIGHUP received, reloading configuration...")
			if err := reloadConfig(); err != nil {
				log.Printf("[ERROR] Config reload failed: %v", err)
			}
		}
	}()

	log.Printf("[INIT] Sanctuary Gate edge node initialized successfully. Version: %s", globalPolicy.PolicyMetadata.Version)
}

// isTrustedProxy reports whether remoteAddr (the immediate TCP peer) is a
// configured upstream reverse proxy/load balancer. X-Forwarded-For is only
// honored from such peers — otherwise it's a trivially spoofable header any
// client can set to fake their IP and bypass per-IP rate limiting.
func isTrustedProxy(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	parsed := net.ParseIP(host)
	if parsed == nil {
		return false
	}
	for _, cidr := range trustedProxyCIDRs {
		if cidr.Contains(parsed) {
			return true
		}
	}
	return false
}

// aggregatorKey normalizes a User-Agent string into its base product token
// (e.g. "Google-Gemini-Bot/1.0" -> "Google-Gemini-Bot") so versioned crawler
// identifiers resolve to the same registry entries configured in the policy.
func aggregatorKey(ua string) string {
	base := ua
	if idx := strings.Index(base, "/"); idx >= 0 {
		base = base[:idx]
	}
	return strings.ToLower(strings.TrimSpace(base))
}

// isValidRedirect validates that a URL for client-side redirection is safe:
// must be an absolute path (no scheme, no host) and must not contain backslash
// sequences that can trigger open redirects in certain browser parsers.
func isValidRedirect(target string) bool {
	if target == "" {
		return false
	}
	if strings.Contains(target, "\\") {
		return false
	}
	parsed, err := url.Parse(target)
	if err != nil {
		return false
	}
	return parsed.Host == ""
}

func clientIP(r *http.Request) string {
	if fwd := r.Header.Get("X-Forwarded-For"); fwd != "" && isTrustedProxy(r.RemoteAddr) {
		return strings.TrimSpace(strings.Split(fwd, ",")[0])
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// loadOrGenerateChallengeKey loads a persistent HMAC signing key from disk if
// GATEWAY_CHALLENGE_SECRET is unset (making it survive restarts), or falls back
// to an ephemeral key generated from rand.Reader. Without a persistent key,
// every container redeploy invalidates active sessions and pending challenges.
func loadOrGenerateChallengeKey() []byte {
	keyPath := filepath.Join(os.Getenv("KEY_DIR"), "challenge.key")
	if key, err := os.ReadFile(keyPath); err == nil && len(key) == 32 {
		return key
	}
	if key := os.Getenv("GATEWAY_CHALLENGE_SECRET"); key != "" {
		data, err := hex.DecodeString(key)
		if err == nil && len(data) == 32 {
			return data
		}
		log.Fatalf("[CRITICAL] Invalid GATEWAY_CHALLENGE_SECRET: expected 64 hex chars (32 bytes)")
	}
	// Generate ephemeral key
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		log.Fatalf("[CRITICAL] Failed to generate challenge signing key: %v", err)
	}
	// Persist so it survives restarts
	if err := os.MkdirAll(filepath.Dir(keyPath), 0700); err == nil {
		if err := os.WriteFile(keyPath, key, 0600); err != nil {
			log.Printf("[WARN] Failed to persist challenge key to %s: %v", keyPath, err)
		}
	}
	return key
}

func isKnownHosting(ip string) bool {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return false
	}
	globalPolicyMu.RLock()
	defer globalPolicyMu.RUnlock()
	for _, cidr := range hostingCIDRs {
		if cidr.Contains(parsed) {
			return true
		}
	}
	return false
}

func matchesBlockedUA(ua string) bool {
	if ua == "" {
		return false
	}
	lowerUA := strings.ToLower(ua)
	globalPolicyMu.RLock()
	defer globalPolicyMu.RUnlock()
	for _, blocked := range globalPolicy.IngestionGovernance.BlockedUserAgents {
		if strings.Contains(lowerUA, strings.ToLower(blocked)) {
			return true
		}
	}
	return false
}

func pathAllowed(path string) bool {
	globalPolicyMu.RLock()
	defer globalPolicyMu.RUnlock()
	for _, prefix := range globalPolicy.IngestionGovernance.PublicDirectories {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}

// effectivePowSettings resolves the PoW difficulty and resulting session TTL
// for a given request path: the first matching entry in route_overrides wins
// (most specific prefix should be listed first in config), falling back to
// the site-wide pow_challenge defaults. A known-hosting-range IP additionally
// gets hosting_difficulty_bonus added on top, since that's a heightened-
// suspicion signal (see isKnownHosting) worth making bulk automation pay for.
func effectivePowSettings(path string, isHosting bool) (difficultyBits int, sessionTTLSeconds int64) {
	globalPolicyMu.RLock()
	difficultyBits = globalPolicy.IngestionGovernance.PowChallenge.DifficultyBits
	sessionTTLSeconds = globalPolicy.IngestionGovernance.PowChallenge.SessionTTLSeconds
	hostingBonus := globalPolicy.IngestionGovernance.PowChallenge.HostingDifficultyBonus
	for _, ov := range globalPolicy.IngestionGovernance.RouteOverrides {
		if strings.HasPrefix(path, ov.PathPrefix) {
			if ov.DifficultyBits > 0 {
				difficultyBits = ov.DifficultyBits
			}
			if ov.SessionTTLSeconds > 0 {
				sessionTTLSeconds = ov.SessionTTLSeconds
			}
			break
		}
	}
	globalPolicyMu.RUnlock()

	if isHosting {
		difficultyBits += hostingBonus
	}
	return difficultyBits, sessionTTLSeconds
}

// auditLog emits one structured JSON line per decision, so ingestion refusals and
// grants can be reconstructed later as an evidence trail (source IP included, unlike
// the previous plain log.Printf calls which never captured it).
func auditLog(event string, fields map[string]string) {
	entry := map[string]string{
		"ts":    time.Now().UTC().Format(time.RFC3339),
		"event": event,
	}
	for k, v := range fields {
		entry[k] = v
	}
	line, err := json.Marshal(entry)
	if err != nil {
		return
	}
	log.Println(string(line))
}

func evaluateDirectoryPermissions(targetPath string, aggregator string) bool {
	globalPolicyMu.RLock()
	config, ok := globalPolicy.IngestionGovernance.AuthorizedAggregators[aggregator]
	if !ok {
		globalPolicyMu.RUnlock()
		return false
	}
	accessStatus := config.AccessStatus
	permittedDirs := config.PermittedDirectories
	globalPolicyMu.RUnlock()

	if accessStatus != "ALLOWED_PAID" && accessStatus != "ALLOWED_FREE" {
		return false
	}

	for _, prefix := range permittedDirs {
		if strings.HasPrefix(targetPath, prefix) {
			return true
		}
	}
	return false
}

func verifyTokenHandshake(nonceHex, sigHex, aggregator string) bool {
	globalPolicyMu.RLock()
	config, ok := globalPolicy.IngestionGovernance.AuthorizedAggregators[aggregator]
	if !ok {
		globalPolicyMu.RUnlock()
		return false
	}
	pubKeyHex := config.MintPublicKey
	globalPolicyMu.RUnlock()

	if pubKeyHex == "" {
		return false
	}

	pubKeyBytes, err := hex.DecodeString(pubKeyHex)
	if err != nil {
		return false
	}

	nonceBytes, err := hex.DecodeString(nonceHex)
	if err != nil {
		return false
	}

	sigBytes, err := hex.DecodeString(sigHex)
	if err != nil {
		return false
	}

	if !ed25519.Verify(pubKeyBytes, nonceBytes, sigBytes) {
		return false
	}

	// Replay check: only a signature that has actually verified gets recorded —
	// an invalid/malformed attempt must not consume a cache slot that could
	// later shadow the legitimate resend of that same literal string.
	if tokenCache.storeIfAbsent(sigHex) {
		log.Printf("[SECURITY WARNING] Replay attack blocked on signature: %s", sigHex[:16])
		return false
	}

	return true
}

// --- Self-hosted proof-of-work challenge -----------------------------------
//
// This is deliberately not a "prove you're human" CAPTCHA. It doesn't try to
// classify the requester at all — it just makes each unrecognized request cost
// real client-side compute before it's admitted. A human loading one page pays
// a few hundred milliseconds, imperceptibly. A script that never executes
// JavaScript can't solve it at all. A headless browser that does execute JS
// pays the compute cost on every solve, which is what makes bulk automated
// crawling expensive rather than free. Challenges and sessions are self-
// contained HMAC-signed blobs — no server-side challenge storage is needed,
// consistent with the mint service's stateless design.

func signBlob(payload []byte) string {
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, challengeSigningKey)
	mac.Write([]byte(encoded))
	return encoded + "." + hex.EncodeToString(mac.Sum(nil))
}

func verifyBlob(token string) ([]byte, bool) {
	parts := strings.SplitN(token, ".", 2)
	if len(parts) != 2 {
		return nil, false
	}
	expectedSig, err := hex.DecodeString(parts[1])
	if err != nil {
		return nil, false
	}
	// MAC is computed over the encoded (base64) form, matching signBlob — not
	// over the decoded payload, which is a different byte sequence and would
	// never match (this previously made every challenge/session token fail
	// verification unconditionally).
	mac := hmac.New(sha256.New, challengeSigningKey)
	mac.Write([]byte(parts[0]))
	if !hmac.Equal(expectedSig, mac.Sum(nil)) {
		return nil, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, false
	}
	return payload, true
}

type challengePayload struct {
	Nonce             string `json:"nonce"`
	DifficultyBits    int    `json:"difficulty_bits"`
	SessionTTLSeconds int64  `json:"session_ttl_seconds"`
	ExpiresAt         int64  `json:"expires_at"`
}

// issueChallenge resolves the difficulty/session-TTL for the target path (via
// effectivePowSettings, which also applies the known-hosting-IP bonus) and
// carries both forward, HMAC-signed, in the challenge token — so the exact
// same values apply when VerifyHandler later mints the session, regardless of
// a config reload landing in between.
func issueChallenge(path, ip string) (string, challengePayload) {
	nonceBytes := make([]byte, 16)
	_, _ = rand.Read(nonceBytes)

	difficulty, sessionTTL := effectivePowSettings(path, isKnownHosting(ip))

	globalPolicyMu.RLock()
	challengeTTL := globalPolicy.IngestionGovernance.PowChallenge.ChallengeTTLSeconds
	globalPolicyMu.RUnlock()

	payload := challengePayload{
		Nonce:             hex.EncodeToString(nonceBytes),
		DifficultyBits:    difficulty,
		SessionTTLSeconds: sessionTTL,
		ExpiresAt: time.Now().UTC().Add(
			time.Duration(challengeTTL) * time.Second,
		).Unix(),
	}
	raw, _ := json.Marshal(payload)
	return signBlob(raw), payload
}

func leadingZeroBits(data []byte) int {
	count := 0
	for _, b := range data {
		if b == 0 {
			count += 8
			continue
		}
		for i := 7; i >= 0; i-- {
			if b&(1<<uint(i)) == 0 {
				count++
			} else {
				return count
			}
		}
	}
	return count
}

// verifyChallengeSolution returns the challenge's payload (so the caller can
// mint a session at the same difficulty/TTL the puzzle was issued at) once
// the blob's HMAC, expiry, and PoW solution all check out.
func verifyChallengeSolution(token, counter string) (challengePayload, bool) {
	raw, ok := verifyBlob(token)
	if !ok {
		return challengePayload{}, false
	}
	var payload challengePayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		return challengePayload{}, false
	}
	if time.Now().UTC().Unix() > payload.ExpiresAt {
		return challengePayload{}, false
	}
	hash := sha256.Sum256([]byte(payload.Nonce + counter))
	if leadingZeroBits(hash[:]) < payload.DifficultyBits {
		return challengePayload{}, false
	}
	return payload, true
}

type sessionPayload struct {
	FingerprintHash string `json:"fingerprint_hash"`
	Difficulty      int    `json:"difficulty"`
	ExpiresAt       int64  `json:"expires_at"`
}

// sessionFingerprint binds a session to more than the raw IP: a rotated
// residential-proxy IP still shares the same User-Agent/Accept-Language most
// of the time, but a session stolen or replayed across a genuinely different
// client profile (different browser, different locale) won't match.
func sessionFingerprint(r *http.Request, ip string) string {
	ua := r.Header.Get("User-Agent")
	lang := r.Header.Get("Accept-Language")
	sum := sha256.Sum256([]byte(ip + "\x00" + ua + "\x00" + lang))
	return hex.EncodeToString(sum[:])
}

func issueSessionToken(r *http.Request, ip string, difficulty int, ttlSeconds int64) string {
	payload := sessionPayload{
		FingerprintHash: sessionFingerprint(r, ip),
		Difficulty:      difficulty,
		ExpiresAt: time.Now().UTC().Add(
			time.Duration(ttlSeconds) * time.Second,
		).Unix(),
	}
	raw, _ := json.Marshal(payload)
	return signBlob(raw)
}

// verifySessionToken returns the decoded payload alongside the ok flag so
// callers can additionally compare payload.Difficulty against whatever
// difficulty the current request's path requires (see effectivePowSettings) —
// a session earned on a low-sensitivity route must not authorize a route
// configured to demand a higher one.
func verifySessionToken(token string, r *http.Request, ip string) (sessionPayload, bool) {
	raw, ok := verifyBlob(token)
	if !ok {
		return sessionPayload{}, false
	}
	var payload sessionPayload
	if err := json.Unmarshal(raw, &payload); err != nil {
		return sessionPayload{}, false
	}
	if time.Now().UTC().Unix() > payload.ExpiresAt {
		return sessionPayload{}, false
	}
	if payload.FingerprintHash != sessionFingerprint(r, ip) {
		return sessionPayload{}, false
	}
	return payload, true
}

var challengeTemplate = template.Must(template.New("challenge").Parse(`<!doctype html>
<html>
<head><meta charset="utf-8"><title>Verifying your connection...</title></head>
<body>
<noscript>
<p style="color:red;font-weight:bold">JavaScript is required to verify you're a real visitor. Please enable JavaScript and refresh.</p>
</noscript>
<div id="challenge-content">
<p>Verifying your connection, please wait a moment...</p>
<script>
(async () => {
  const token = {{.Token | printf "%q"}};
  const nonce = {{.Nonce | printf "%q"}};
  const difficulty = {{.Difficulty}};
  const next = {{.Next | printf "%q"}};

  function leadingZeroBits(bytes) {
    let count = 0;
    for (const b of bytes) {
      if (b === 0) { count += 8; continue; }
      for (let i = 7; i >= 0; i--) {
        if ((b & (1 << i)) === 0) { count++; } else { return count; }
      }
    }
    return count;
  }

  const enc = new TextEncoder();
  let counter = 0;
  while (true) {
    const digest = await crypto.subtle.digest("SHA-256", enc.encode(nonce + counter));
    if (leadingZeroBits(new Uint8Array(digest)) >= difficulty) break;
    counter++;
  }

  const res = await fetch("/__sanctuary/verify", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({token: token, counter: String(counter)})
  });

  if (res.ok) {
    document.getElementById("challenge-content").innerHTML = '<p style="color:green">Verification complete. Redirecting...</p>';
    setTimeout(() => window.location.replace(next), 300);
  } else {
    document.getElementById("challenge-content").innerHTML = '<p style="color:red">Verification failed. Please refresh to try again.</p>';
  }
})();
</script>
</div>
</body>
</html>`))

type challengePageData struct {
	Token      string
	Nonce      string
	Difficulty int
	Next       string
}

func ChallengeHandler(w http.ResponseWriter, r *http.Request) {
	next := r.URL.Query().Get("next")
	if !isValidRedirect(next) {
		next = "/"
	}
	token, payload := issueChallenge(next, clientIP(r))

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_ = challengeTemplate.Execute(w, challengePageData{
		Token:      token,
		Nonce:      payload.Nonce,
		Difficulty: payload.DifficultyBits,
		Next:       next,
	})
}

type verifyRequest struct {
	Token   string `json:"token"`
	Counter string `json:"counter"`
}

func VerifyHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	ip := clientIP(r)

	var req verifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	challenge, ok := verifyChallengeSolution(req.Token, req.Counter)
	if !ok {
		auditLog("challenge-failed", map[string]string{"ip": ip})
		w.WriteHeader(http.StatusForbidden)
		return
	}

	isSecure := r.TLS != nil || (isTrustedProxy(r.RemoteAddr) && r.Header.Get("X-Forwarded-Proto") == "https")
	http.SetCookie(w, &http.Cookie{
		Name:     "sanctuary_session",
		Value:    issueSessionToken(r, ip, challenge.DifficultyBits, challenge.SessionTTLSeconds),
		Path:     "/",
		HttpOnly: true,
		Secure:   isSecure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   int(challenge.SessionTTLSeconds),
	})
	auditLog("challenge-passed", map[string]string{"ip": ip})
	w.WriteHeader(http.StatusOK)
}

// --- Main ingestion decision path -------------------------------------------

func IngestionGatewayHandler(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	targetedAggregator := aggregatorKey(r.Header.Get("User-Agent"))
	incomingNonce := r.Header.Get("X-Sanctuary-Nonce")
	incomingSignature := r.Header.Get("X-Monetization-Token")
	logFields := map[string]string{"ip": ip, "ua": targetedAggregator, "path": r.URL.Path}

	if matchesBlockedUA(targetedAggregator) {
		auditLog("blocked-user-agent", logFields)
		executeSilenceProtocol(w, http.StatusForbidden, "Ingestion refused. Agent is on the denied ingestion list.")
		return
	}

	if !rateLimiter.Allow(ip) {
		auditLog("rate-limited", logFields)
		executeSilenceProtocol(w, http.StatusTooManyRequests, "Ingestion refused. Request velocity exceeds permitted threshold.")
		return
	}

	// Informational only: a datacenter/cloud IP isn't proof of a bot (corporate
	// NAT, VPNs), so it's logged as a heightened-suspicion signal rather than
	// used to auto-block.
	if isKnownHosting(ip) {
		auditLog("known-hosting-ip", logFields)
	}

	globalPolicyMu.RLock()
	_, registered := globalPolicy.IngestionGovernance.AuthorizedAggregators[targetedAggregator]
	enforcedHandshake := globalPolicy.IngestionGovernance.EnforcedHandshake
	globalDefault := globalPolicy.IngestionGovernance.GlobalDefault
	powChallengeEnabled := globalPolicy.IngestionGovernance.PowChallenge.Enabled
	globalPolicyMu.RUnlock()

	if registered {
		if enforcedHandshake && !verifyTokenHandshake(incomingNonce, incomingSignature, targetedAggregator) {
			auditLog("handshake-failed", logFields)
			executeSilenceProtocol(w, http.StatusForbidden, "Ingestion refused. Cryptographic proof invalid or replayed.")
			return
		}
		if !evaluateDirectoryPermissions(r.URL.Path, targetedAggregator) {
			auditLog("directory-denied", logFields)
			executeSilenceProtocol(w, http.StatusForbidden, "Ingestion refused. Target path outside perimeter schema.")
			return
		}
		auditLog("authorized-aggregator", logFields)
		if upstreamProxy != nil {
			upstreamProxy.ServeHTTP(w, r)
		} else {
			auditLog("no-upstream-configured", logFields)
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Target state authorized. Ingestion handshake verified."))
		}
		return
	}

	// Unregistered UA: general traffic, not a known aggregator. Behavior is
	// governed by global_default.
	switch globalDefault {
	case "ALLOW":
		auditLog("general-allow", logFields)
		if upstreamProxy != nil {
			upstreamProxy.ServeHTTP(w, r)
		} else {
			auditLog("no-upstream-configured", logFields)
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("Access granted."))
		}
		return

	case "CHALLENGE":
		if !powChallengeEnabled {
			auditLog("general-allow", logFields)
			if upstreamProxy != nil {
				upstreamProxy.ServeHTTP(w, r)
			} else {
				auditLog("no-upstream-configured", logFields)
				w.Header().Set("Content-Type", "text/plain; charset=utf-8")
				w.WriteHeader(http.StatusOK)
				w.Write([]byte("Access granted."))
			}
			return
		}
		requiredDifficulty, _ := effectivePowSettings(r.URL.Path, isKnownHosting(ip))
		if cookie, err := r.Cookie("sanctuary_session"); err == nil {
			if session, ok := verifySessionToken(cookie.Value, r, ip); ok && session.Difficulty >= requiredDifficulty {
				if !pathAllowed(r.URL.Path) {
					auditLog("path-restricted", logFields)
					executeSilenceProtocol(w, http.StatusForbidden, "Ingestion refused. Target path outside public perimeter.")
					return
				}
				auditLog("session-allow", logFields)
				if upstreamProxy != nil {
					upstreamProxy.ServeHTTP(w, r)
				} else {
					auditLog("no-upstream-configured", logFields)
					w.Header().Set("Content-Type", "text/plain; charset=utf-8")
					w.WriteHeader(http.StatusOK)
					w.Write([]byte("Access granted."))
				}
				return
			}
		}
		auditLog("challenge-issued", logFields)
		http.Redirect(w, r, "/__sanctuary/challenge?next="+url.QueryEscape(r.URL.Path), http.StatusFound)
		return

	default: // "DENY"
		auditLog("default-deny", logFields)
		executeSilenceProtocol(w, http.StatusForbidden, "Ingestion refused. Absolute perimeter containment protocol active.")
		return
	}
}

func executeSilenceProtocol(w http.ResponseWriter, status int, operationalMessage string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	response, _ := json.Marshal(map[string]string{
		"status":   "error",
		"code":     strconv.Itoa(status),
		"category": "Sanctuary_Gate_Refusal",
		"details":  operationalMessage,
	})
	w.Write(response)
}

func main() {
	serverAddress := ":8080"
	mux := http.NewServeMux()
	mux.HandleFunc("/__sanctuary/challenge", ChallengeHandler)
	mux.HandleFunc("/__sanctuary/verify", VerifyHandler)
	mux.HandleFunc("/", IngestionGatewayHandler)

	// Health check endpoint for Docker healthcheck and operational monitoring.
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
	})

	server := &http.Server{
		Addr:              serverAddress,
		Handler:           mux,
		ReadTimeout:       10 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	certFile := os.Getenv("GATEWAY_TLS_CERT")
	keyFile := os.Getenv("GATEWAY_TLS_KEY")

	if certFile != "" && keyFile != "" {
		log.Printf("[START] Activating Gateway Proxy (TLS) on %s", serverAddress)
		if err := server.ListenAndServeTLS(certFile, keyFile); err != nil {
			log.Fatalf("[FATAL] Network proxy failure: %v", err)
		}
	} else {
		log.Printf("[START] Activating Gateway Proxy on %s (no TLS — use in a trusted network)", serverAddress)
		if err := server.ListenAndServe(); err != nil {
			log.Fatalf("[FATAL] Network proxy failure: %v", err)
		}
	}
}
