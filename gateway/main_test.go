package main

import (
	"net"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

var _ = os.Setenv("CONFIG_PATH", "/tmp/opencode/sanctuary-gateway-test-config.json")
var _ = os.Setenv("KEY_DIR", "/tmp/opencode/sanctuary-gateway-test-keys")

func TestAggregatorKey(t *testing.T) {
	tests := []struct {
		ua   string
		want string
	}{
		{"Google-Gemini-Bot/1.0", "google-gemini-bot"},
		{"Google-Gemini-Bot", "google-gemini-bot"},
		{"  GPTBot  ", "gptbot"},
	}
	for _, tt := range tests {
		if got := aggregatorKey(tt.ua); got != tt.want {
			t.Errorf("aggregatorKey(%q) = %q, want %q", tt.ua, got, tt.want)
		}
	}
}

func TestLeadingZeroBits(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
		want int
	}{
		{"zero byte", []byte{0x00}, 8},
		{"high bit set", []byte{0x80}, 0},
		{"two zero bytes", []byte{0x00, 0x00}, 16},
	}
	for _, tt := range tests {
		if got := leadingZeroBits(tt.in); got != tt.want {
			t.Errorf("%s: leadingZeroBits(%v) = %d, want %d", tt.name, tt.in, got, tt.want)
		}
	}
}

func TestIsValidRedirect(t *testing.T) {
	if !isValidRedirect("/some/path") {
		t.Error("expected /some/path to be a valid redirect target")
	}
	if isValidRedirect("") {
		t.Error("expected empty target to be invalid")
	}
	if isValidRedirect("https://evil.example.com/phish") {
		t.Error("expected absolute URL to be invalid")
	}
	if isValidRedirect("/ok\\evil") {
		t.Error("expected backslash path to be invalid")
	}
	if isValidRedirect("//evil.example.com/phish") {
		t.Error("expected protocol-relative URL to be invalid")
	}
}

func TestSessionFingerprint(t *testing.T) {
	r1 := httptest.NewRequest("GET", "/api", nil)
	r1.Header.Set("User-Agent", "TestAgent/1.0")
	r1.Header.Set("Accept-Language", "en-US")
	r2 := httptest.NewRequest("GET", "/api", nil)
	r2.Header.Set("User-Agent", "TestAgent/1.0")
	r2.Header.Set("Accept-Language", "en-US")
	r3 := httptest.NewRequest("GET", "/api", nil)
	r3.Header.Set("User-Agent", "OtherAgent/2.0")
	r3.Header.Set("Accept-Language", "en-US")

	h1 := sessionFingerprint(r1, "203.0.113.10")
	h2 := sessionFingerprint(r2, "203.0.113.10")
	h3 := sessionFingerprint(r3, "203.0.113.10")
	if h1 != h2 {
		t.Error("expected identical fingerprints for identical client profiles")
	}
	if h1 == h3 {
		t.Error("expected different fingerprints for different user agents")
	}
}

func TestRateLimiterAllow(t *testing.T) {
	rl := newRateLimiter(60, 2)
	if !rl.Allow("198.51.100.7") {
		t.Error("expected first token to be available")
	}
	if !rl.Allow("198.51.100.7") {
		t.Error("expected second token to be available")
	}
	if rl.Allow("198.51.100.7") {
		t.Error("expected third immediate request to be rate limited")
	}
}

func TestHardenedTokenCache(t *testing.T) {
	c := &HardenedTokenCache{ttl: time.Hour}
	if c.storeIfAbsent("sig-1") {
		t.Error("first sighting of sig-1 must not be treated as replay")
	}
	if !c.storeIfAbsent("sig-1") {
		t.Error("second sighting of sig-1 must be treated as replay")
	}
	if c.storeIfAbsent("sig-2") {
		t.Error("first sighting of sig-2 must not be treated as replay")
	}
}

func TestVerifyTokenHandshake_unknownAggregator(t *testing.T) {
	tokenCache = &HardenedTokenCache{ttl: time.Hour}
	globalPolicy = IngestionPolicy{}
	if verifyTokenHandshake("deadbeef", "abcd", "UnknownBot") {
		t.Error("unknown aggregator must fail verification")
	}
}

func TestMatchesBlockedUA(t *testing.T) {
	globalPolicy = IngestionPolicy{}
	globalPolicy.IngestionGovernance.BlockedUserAgents = []string{"GPTBot"}
	if !matchesBlockedUA("gptbot/3.5") {
		t.Error("expected gptbot/3.5 to be blocked")
	}
	if matchesBlockedUA("Mozilla/5.0") {
		t.Error("expected generic UA to be allowed")
	}
}

func TestPathAllowed(t *testing.T) {
	globalPolicy = IngestionPolicy{}
	globalPolicy.IngestionGovernance.PublicDirectories = []string{"/public/"}
	if !pathAllowed("/public/open-access/x") {
		t.Error("expected /public/ prefix to be allowed")
	}
	if pathAllowed("/private/x") {
		t.Error("expected /private/ prefix to be denied")
	}
}

func TestEffectivePowSettings(t *testing.T) {
	globalPolicy = IngestionPolicy{}
	globalPolicy.IngestionGovernance.PowChallenge.DifficultyBits = 18
	globalPolicy.IngestionGovernance.RouteOverrides = []struct {
		PathPrefix        string `json:"path_prefix"`
		DifficultyBits    int    `json:"difficulty_bits"`
		SessionTTLSeconds int64  `json:"session_ttl_seconds"`
	}{
		{PathPrefix: "/api/", DifficultyBits: 24, SessionTTLSeconds: 300},
	}
	difficulty, ttl := effectivePowSettings("/api/v1/x", false)
	if difficulty != 24 {
		t.Errorf("expected route override difficulty 24, got %d", difficulty)
	}
	if ttl != 300 {
		t.Errorf("expected route override ttl 300, got %d", ttl)
	}

	difficulty, ttl = effectivePowSettings("/other/x", false)
	if difficulty != 18 {
		t.Errorf("expected site-wide default difficulty 18, got %d", difficulty)
	}
}

func TestEvaluateDirectoryPermissions(t *testing.T) {
	globalPolicy = IngestionPolicy{}
	globalPolicy.IngestionGovernance.AuthorizedAggregators = map[string]struct {
		AccessStatus             string   `json:"access_status"`
		MintPublicKey            string   `json:"mint_public_key"`
		PermittedDirectories     []string `json:"permitted_directories"`
		MonetizationHandshakeURL string   `json:"monetization_handshake_url"`
	}{
		"Google-Gemini-Bot": {
			AccessStatus:             "ALLOWED_PAID",
			MintPublicKey:            "REPLACE_WITH_YOUR_ED25519_PUBLIC_KEY_HEX",
			PermittedDirectories:     []string{"/public/open-access/"},
			MonetizationHandshakeURL: "http://mint:8081/v1/mint",
		},
	}
	if !evaluateDirectoryPermissions("/public/open-access/data", "Google-Gemini-Bot") {
		t.Error("expected permitted directory to be allowed")
	}
	if evaluateDirectoryPermissions("/private/data", "Google-Gemini-Bot") {
		t.Error("expected non-permitted directory to be denied")
	}
}

func TestIsKnownHosting(t *testing.T) {
	_, network, err := net.ParseCIDR("10.0.0.0/8")
	if err != nil {
		t.Fatalf("failed to parse CIDR: %v", err)
	}
	hostingCIDRs = []*net.IPNet{network}
	if !isKnownHosting("10.1.2.3") {
		t.Error("expected 10.1.2.3 to be known hosting")
	}
	if isKnownHosting("8.8.8.8") {
		t.Error("expected 8.8.8.8 to not be known hosting")
	}
}
