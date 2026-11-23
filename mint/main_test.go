package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

var _ = os.Setenv("CONFIG_PATH", "/tmp/opencode/sanctuary-mint-test-config.json")
var _ = os.Setenv("MINT_KEY_DIR", "/tmp/opencode/sanctuary-mint-test-keys")

func TestValidatePaymentProof(t *testing.T) {
	if !validatePaymentProof(Payment{Provider: "stripe", InvoicePreimage: "preimage"}, 1) {
		t.Error("expected valid payment proof to pass")
	}
	if validatePaymentProof(Payment{Provider: "", InvoicePreimage: "preimage"}, 1) {
		t.Error("expected empty provider to fail payment proof")
	}
	if validatePaymentProof(Payment{Provider: "stripe", InvoicePreimage: ""}, 1) {
		t.Error("expected empty preimage to fail payment proof")
	}
}

func TestMintTokensHandler_MintsTokens(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate keypair: %v", err)
	}
	publicKey = pub
	privateKey = priv
	mintRateLimiter = newRateLimiter(30, 10)

	body := `{"contract_id":"test-contract","token_count":1,"payload_nonces":["deadbeef"]}`
	req := httptest.NewRequest(http.MethodPost, "/v1/mint", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "198.51.100.5:1234"
	rec := httptest.NewRecorder()
	MintTokensHandler(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected status 201, got %d: %s", rec.Code, rec.Body.String())
	}

	var resp MintResponse
	if err := json.NewDecoder(rec.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode mint response: %v", err)
	}
	if resp.Status != "minted" {
		t.Errorf("expected status minted, got %q", resp.Status)
	}
	if len(resp.MintedTokens) != 1 {
		t.Fatalf("expected 1 minted token, got %d", len(resp.MintedTokens))
	}

	sigBytes, err := hex.DecodeString(resp.MintedTokens[0].Signature)
	if err != nil {
		t.Fatalf("failed to decode signature: %v", err)
	}
	nonceBytes := []byte{0xde, 0xad, 0xbe, 0xef}
	if !ed25519.Verify(pub, nonceBytes, sigBytes) {
		t.Error("minted signature did not verify against the nonce")
	}
}

func TestMintTokensHandler_RejectsNonceMismatch(t *testing.T) {
	publicKey = ed25519.PublicKey(nil)
	privateKey = ed25519.PrivateKey(nil)
	mintRateLimiter = newRateLimiter(30, 10)

	body := `{"contract_id":"test-contract","token_count":2,"payload_nonces":["deadbeef"]}`
	req := httptest.NewRequest(http.MethodPost, "/v1/mint", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "198.51.100.5:1234"
	rec := httptest.NewRecorder()
	MintTokensHandler(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400 for nonce mismatch, got %d", rec.Code)
	}
}

func TestMintTokensHandler_RejectsInvalidHexNonce(t *testing.T) {
	publicKey = ed25519.PublicKey(nil)
	privateKey = ed25519.PrivateKey(nil)
	mintRateLimiter = newRateLimiter(30, 10)

	body := `{"contract_id":"test-contract","token_count":1,"payload_nonces":["zz"]}`
	req := httptest.NewRequest(http.MethodPost, "/v1/mint", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "198.51.100.5:1234"
	rec := httptest.NewRecorder()
	MintTokensHandler(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400 for invalid hex nonce, got %d", rec.Code)
	}
}

func TestMintTokensHandler_RejectsMissingSecret(t *testing.T) {
	prevSecret := os.Getenv("MINT_SHARED_SECRET")
	os.Setenv("MINT_SHARED_SECRET", "topsecret")
	defer os.Setenv("MINT_SHARED_SECRET", prevSecret)

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate keypair: %v", err)
	}
	publicKey = pub
	privateKey = priv
	mintRateLimiter = newRateLimiter(30, 10)

	body := `{"contract_id":"test-contract","token_count":1,"payload_nonces":["deadbeef"]}`
	req := httptest.NewRequest(http.MethodPost, "/v1/mint", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.RemoteAddr = "198.51.100.5:1234"
	rec := httptest.NewRecorder()
	MintTokensHandler(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected status 401 without mint secret, got %d", rec.Code)
	}

	req = httptest.NewRequest(http.MethodPost, "/v1/mint", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Sanctuary-Mint-Secret", "topsecret")
	req.RemoteAddr = "198.51.100.6:1234"
	rec = httptest.NewRecorder()
	MintTokensHandler(rec, req)

	if rec.Code == http.StatusUnauthorized {
		t.Fatalf("expected status 201 with correct mint secret, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestMintTokensHandler_RateLimited(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate keypair: %v", err)
	}
	publicKey = pub
	privateKey = priv
	mintRateLimiter = newRateLimiter(60, 1)

	body := `{"contract_id":"test-contract","token_count":1,"payload_nonces":["deadbeef"]}`
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodPost, "/v1/mint", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.RemoteAddr = "198.51.100.7:1234"
		rec := httptest.NewRecorder()
		MintTokensHandler(rec, req)
		if i == 0 && rec.Code != http.StatusCreated && rec.Code != http.StatusUnauthorized && rec.Code != http.StatusPaymentRequired {
			t.Fatalf("expected first mint request to pass auth/limits, got %d", rec.Code)
		}
		if i == 1 && rec.Code != http.StatusTooManyRequests {
			t.Fatalf("expected second mint request to be rate limited, got %d", rec.Code)
		}
	}
}
