package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// MintRequest represents the inbound batch token signature request from an aggregator.
type MintRequest struct {
	ContractID       string   `json:"contract_id"`
	PaymentReference Payment  `json:"payment_reference"`
	TokenCount       int      `json:"token_count"`
	PayloadNonces    []string `json:"payload_nonces"`
}

// Payment captures the payment verification details submitted by an aggregator.
// NOTE: validatePaymentProof is a structured hook — integrate a real payment provider
// (Lightning invoice preimage verification, on-chain tx hash check, Stripe webhook, etc.)
// by replacing the stub body below.
type Payment struct {
	Provider        string `json:"provider"`
	InvoicePreimage string `json:"invoice_preimage"`
}

// MintResponse represents the signed assets returned to the automated consumer.
type MintResponse struct {
	Status       string        `json:"status"`
	ContractID   string        `json:"contract_id"`
	TokenCount   int           `json:"token_count"`
	PublicKey    string        `json:"public_key"`
	MintedTokens []MintedAsset `json:"minted_tokens"`
}

// MintedAsset is a single nonce-signature pair returned by the mint.
type MintedAsset struct {
	Nonce     string `json:"nonce"`
	Signature string `json:"signature"`
}

var (
	publicKey  ed25519.PublicKey
	privateKey ed25519.PrivateKey

	monetizationEnabled bool

	mintRateLimiter *RateLimiter
)

type mintPolicy struct {
	IngestionGovernance struct {
		MonetizationEnabled bool `json:"monetization_enabled"`
	} `json:"ingestion_governance"`
}

// mintBucket is a per-key token bucket used by the mint rate limiter.
type mintBucket struct {
	mu         sync.Mutex
	tokens     float64
	lastRefill time.Time
}

// RateLimiter is a simple per-key token-bucket limiter used by the mint to
// bound signing-oracle throughput. Idle buckets are evicted by a janitor.
type RateLimiter struct {
	buckets           sync.Map // string -> *mintBucket
	requestsPerMinute float64
	burst             float64
}

func newRateLimiter(requestsPerMinute, burst float64) *RateLimiter {
	if requestsPerMinute <= 0 {
		requestsPerMinute = 30
	}
	if burst <= 0 {
		burst = requestsPerMinute
	}
	return &RateLimiter{requestsPerMinute: requestsPerMinute, burst: burst}
}

func (rl *RateLimiter) Allow(key string) bool {
	now := time.Now()
	value, _ := rl.buckets.LoadOrStore(key, &mintBucket{tokens: rl.burst, lastRefill: now})
	b := value.(*mintBucket)

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
			b := value.(*mintBucket)
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
			log.Printf("[MAINTENANCE] Mint rate limiter sweep complete. Evicted %d idle buckets.", evicted)
		}
	}
}

// clientIP returns the remote client IP used for mint rate limiting.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// mintAuthorized reports whether the mint signing oracle should serve the
// request. When the MINT_SHARED_SECRET env var is set, callers must present it
// in the X-Sanctuary-Mint-Secret header (constant-time comparison); when unset,
// the oracle remains open for internal-network-only deployments.
func mintAuthorized(r *http.Request) bool {
	secret := os.Getenv("MINT_SHARED_SECRET")
	if secret == "" {
		return true
	}
	return subtle.ConstantTimeCompare([]byte(secret), []byte(r.Header.Get("X-Sanctuary-Mint-Secret"))) == 1
}

// loadOrGenerateKey loads an existing Ed25519 private key from disk or generates a new one.
// Ed25519.PrivateKey is a raw []byte (64 bytes: 32 private + 32 public), so we read/write
// the bytes directly rather than using Marshal/Unmarshal helpers which vary across Go versions.
func loadOrGenerateKey(keyDir string) (ed25519.PublicKey, ed25519.PrivateKey, error) {
	privPath := filepath.Join(keyDir, "mint_private.key")

	// Try loading existing key first
	if data, err := os.ReadFile(privPath); err == nil {
		if len(data) == ed25519.PrivateKeySize {
			priv := ed25519.PrivateKey(data)
			pub := priv.Public().(ed25519.PublicKey)
			return pub, priv, nil
		}
		log.Printf("[WARN] Corrupted key at %s (wrong size %d); generating new keypair.", privPath, len(data))
	}

	// Generate new keypair
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	// Persist to disk
	dir := filepath.Dir(privPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, nil, err
	}
	// Ed25519.PrivateKey is a raw []byte (32 private + 32 public). Read and write the bytes directly.
	if err := os.WriteFile(privPath, []byte(priv), 0600); err != nil {
		return nil, nil, err
	}
	log.Printf("[KEY] New Ed25519 keypair generated and persisted to %s", privPath)
	return pub, priv, nil
}

// validatePaymentProof verifies a payment submission before minting tokens.
// This is a structured hook — replace with integration to your payment provider:
//   - Lightning: verify invoice preimage matches an invoice on the Lightning network
//   - On-chain: verify transaction hash exists and is confirmed
//   - Stripe: verify webhook signature and payment status
//
// Currently returns true for any non-empty payment struct.
func validatePaymentProof(p Payment, count int) bool {
	if p.InvoicePreimage == "" || p.Provider == "" {
		return false
	}
	return true
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func init() {
	log.SetFlags(log.Ldate | log.Ltime | log.LUTC)

	configPath := os.Getenv("CONFIG_PATH")
	if configPath == "" {
		configPath = "./config/ai-permissions.json"
	}

	if file, err := os.Open(configPath); err == nil {
		defer file.Close()
		bytes, err := io.ReadAll(file)
		if err != nil {
			log.Fatalf("[CRITICAL] Read interface failed: %v", err)
		}
		var policy mintPolicy
		if err := json.Unmarshal(bytes, &policy); err != nil {
			log.Fatalf("[CRITICAL] Configuration corruption: %v", err)
		}
		monetizationEnabled = policy.IngestionGovernance.MonetizationEnabled
	} else {
		log.Printf("[WARN] No policy configuration found at %s; defaulting to monetization disabled.", configPath)
	}

	keyDir := os.Getenv("MINT_KEY_DIR")
	if keyDir == "" {
		keyDir = "./keys"
	}

	pub, priv, err := loadOrGenerateKey(keyDir)
	if err != nil {
		log.Fatalf("[CRITICAL] Mint Initialization Failure: %v", err)
	}
	publicKey = pub
	privateKey = priv

	log.Printf("[INIT] Sanctuary Mint Active. Monetization enabled: %v. Public Key: %s", monetizationEnabled, hex.EncodeToString(publicKey))

	mintRateLimiter = newRateLimiter(30, 10)
	go mintRateLimiter.startJanitor(10*time.Minute, time.Hour)
}

func MintTokensHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	ip := clientIP(r)
	if !mintRateLimiter.Allow(ip) {
		w.WriteHeader(http.StatusTooManyRequests)
		json.NewEncoder(w).Encode(map[string]string{"error": "Mint rate limit exceeded"})
		return
	}

	if !mintAuthorized(r) {
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid mint secret"})
		return
	}

	var req MintRequest
	err := json.NewDecoder(r.Body).Decode(&req)
	if err != nil || len(req.PayloadNonces) != req.TokenCount || req.TokenCount <= 0 {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]string{"error": "Invalid payload parameters or structural nonce discrepancy"})
		return
	}

	// Verify clearing mechanism (only when monetization is enabled by the admin;
	// identity/signature minting keeps working for free otherwise).
	if monetizationEnabled && !validatePaymentProof(req.PaymentReference, req.TokenCount) {
		w.WriteHeader(http.StatusPaymentRequired)
		json.NewEncoder(w).Encode(map[string]string{"error": "Payment verification failed"})
		return
	}

	var mintedAssets []MintedAsset

	// Iterate and batch sign nonces statelessly
	for _, nonceHex := range req.PayloadNonces {
		nonceBytes, err := hex.DecodeString(nonceHex)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "Nonces must be valid hex-encoded strings"})
			return
		}

		// Perform atomic signature operations
		signatureBytes := ed25519.Sign(privateKey, nonceBytes)

		mintedAssets = append(mintedAssets, MintedAsset{
			Nonce:     nonceHex,
			Signature: hex.EncodeToString(signatureBytes),
		})
	}

	res := MintResponse{
		Status:       "minted",
		ContractID:   req.ContractID,
		TokenCount:   req.TokenCount,
		PublicKey:    hex.EncodeToString(publicKey),
		MintedTokens: mintedAssets,
	}

	log.Printf("[AUDIT] Minted token batch. Contract: %s | Count: %d", req.ContractID, req.TokenCount)

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(res)
}

func main() {
	serverAddress := ":8081"
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/mint", MintTokensHandler)
	mux.HandleFunc("/health", healthHandler)

	server := &http.Server{
		Addr:              serverAddress,
		Handler:           mux,
		ReadTimeout:       10 * time.Second,
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	certFile := os.Getenv("MINT_TLS_CERT")
	keyFile := os.Getenv("MINT_TLS_KEY")

	if certFile != "" && keyFile != "" {
		log.Printf("[START] Launching Sanctuary Mint Service (TLS) on %s", serverAddress)
		if err := server.ListenAndServeTLS(certFile, keyFile); err != nil {
			log.Fatalf("[FATAL] Network error: %v", err)
		}
	} else {
		log.Printf("[START] Launching Sanctuary Mint Service on %s (no TLS — use in a trusted network)", serverAddress)
		if err := server.ListenAndServe(); err != nil {
			log.Fatalf("[FATAL] Network error: %v", err)
		}
	}
}
