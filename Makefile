.PHONY: run up down test-integration fmt

run:
	DATABASE_URL='postgres://app:app@localhost:5432/multitenant_oidc?sslmode=disable' \
	BASE_URL='http://localhost:8080' \
	go run ./cmd/server

up:
	docker compose up -d --wait postgres keycloak

down:
	docker compose down -v

fmt:
	gofmt -w cmd internal tests

test-integration: up
	DATABASE_URL='postgres://app:app@localhost:5432/multitenant_oidc?sslmode=disable' \
	go test -tags=integration -v ./tests
