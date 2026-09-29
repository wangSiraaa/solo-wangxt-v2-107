package config

import (
	"crypto/sha256"
	"fmt"
	"os"
	"strconv"
	"time"
)

type Config struct {
	HTTPAddr             string
	BaseURL              string
	DatabaseURL          string
	EncryptionKey        []byte
	CookieSecure         bool
	MaxAuthAgeForBinding time.Duration
	ProviderHTTPTimeout  time.Duration
}

func Load() (Config, error) {
	cfg := Config{
		HTTPAddr:             env("HTTP_ADDR", ":8080"),
		BaseURL:              env("BASE_URL", "http://localhost:8080"),
		DatabaseURL:          os.Getenv("DATABASE_URL"),
		CookieSecure:         envBool("COOKIE_SECURE", false),
		MaxAuthAgeForBinding: envDuration("MAX_AUTH_AGE_FOR_BINDING", 5*time.Minute),
		ProviderHTTPTimeout:  envDuration("PROVIDER_HTTP_TIMEOUT", 10*time.Second),
	}
	if cfg.DatabaseURL == "" {
		return cfg, fmt.Errorf("DATABASE_URL is required")
	}

	key := os.Getenv("FLOW_ENCRYPTION_KEY")
	if key == "" {
		// Deterministic only for local docker-compose/integration testing.
		key = "local-dev-flow-secret-key-change!"
	}
	sum := sha256.Sum256([]byte(key))
	cfg.EncryptionKey = sum[:]

	return cfg, nil
}

func env(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envBool(key string, fallback bool) bool {
	v := os.Getenv(key)
	if v == "" {
		return fallback
	}
	b, err := strconv.ParseBool(v)
	return err == nil && b
}

func envDuration(key string, fallback time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return fallback
}
