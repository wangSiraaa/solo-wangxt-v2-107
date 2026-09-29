package main

import (
	"context"
	"log"
	"net/http"
	"time"

	"github.example/multitenant-oidc/internal/auth"
	"github.example/multitenant-oidc/internal/config"
	"github.example/multitenant-oidc/internal/database"
	"github.example/multitenant-oidc/internal/httpapi"
	oidcx "github.example/multitenant-oidc/internal/oidc"
)

func main() {
	ctx := context.Background()
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	pool, err := database.Connect(ctx, cfg.DatabaseURL)
	if err != nil {
		log.Fatalf("connect database: %v", err)
	}
	defer pool.Close()
	if err := database.Migrate(ctx, pool); err != nil {
		log.Fatalf("migrate database: %v", err)
	}

	resolver := oidcx.NewResolver(cfg.ProviderHTTPTimeout)
	service := auth.NewService(pool, resolver, cfg.EncryptionKey, cfg.BaseURL, cfg.MaxAuthAgeForBinding)
	handler := httpapi.NewServer(service, cfg.BaseURL, cfg.CookieSecure)

	server := &http.Server{
		Addr:              cfg.HTTPAddr,
		Handler:           handler.Routes(),
		ReadHeaderTimeout: 5 * time.Second,
	}
	log.Printf("listening on %s", cfg.HTTPAddr)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("http server: %v", err)
	}
}
