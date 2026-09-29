# Multi-tenant OIDC login and binding API

Go service demonstrating multi-tenant OIDC login with:

- Go, `github.com/coreos/go-oidc/v3`, and `golang.org/x/oauth2`
- PostgreSQL tenant/issuer/client and identity mapping tables
- Local Keycloak realms as identity providers
- No frontend or UI; APIs return JSON authorization URLs and callback results
- OIDC signature, issuer, audience, `nonce`, `state`, and S256 PKCE validation
- Identity resolution by `(tenant_id, issuer, subject)`, never by email
- Account linking that forces a fresh Keycloak login (`prompt=login`) for both identities and checks `auth_time`
- Idempotent OAuth callback consumption using row locks and a one-time flow status
- Configured callback URIs only
- ID tokens excluded from logs and API errors

## Run locally

```bash
docker compose up -d --wait postgres keycloak
export DATABASE_URL='postgres://app:app@localhost:5432/multitenant_oidc?sslmode=disable'
export BASE_URL='http://localhost:8080'
go run ./cmd/server
```

Keycloak is published on `http://localhost:8081`; Keycloak admin is `admin/admin`. The seeded application is public client `multitenant-app`.

Seeded users all use password `password`:

| Realm | Username | Email |
| --- | --- | --- |
| tenant-a | a.alice | shared@example.com |
| tenant-a | a.carol | a.carol@example.com |
| tenant-a | a.dave | a.dave@example.com |
| tenant-b | b.alice | shared@example.com |
| tenant-b | b.bob | b.bob@example.com |
| tenant-c | c.alice | shared@example.com |

`tenant-c` exists but its client mapping for `tenant-a` is disabled, producing `tenant_unauthorized`.

## API

### Start login

`POST /api/login/start`

```json
{
  "tenant_id": "tenant-a",
  "issuer": "http://localhost:8081/realms/tenant-a",
  "redirect_uri": "http://localhost:8080/callback/login"
}
```

Response:

```json
{
  "auth_url": "http://localhost:8081/...",
  "state": "opaque-random-state"
}
```

Open `auth_url` in an HTTP client/browser. Keycloak redirects to the API callback:

`GET /callback/login?code=...&state=...`

A successful callback sets the `oidc_session` cookie (`__Host-oidc_session` when `COOKIE_SECURE=true`) and returns tenant/member/session details. The session is opaque; its SHA-256 hash is stored.

### Current identity

`GET /api/me`

Returns tenant, member, issuer, and subject. It does not return email as the identity key.

### Start binding/linking

`POST /api/links/start`

```json
{
  "tenant_id": "tenant-b",
  "issuer1": "http://localhost:8081/realms/tenant-b",
  "issuer2": "http://localhost:8081/realms/tenant-b"
}
```

Both redirects use `/callback/link`. The first callback JSON contains `next_auth_url`; the test client immediately opens that to authenticate the second identity. Each leg uses `prompt=login`; both tokens must contain a recent `auth_time`.

## Error classes

| HTTP | `error.code` | Meaning |
| ---: | --- | --- |
| 401 | `authentication_failed` | Bad signature/issuer/audience/nonce/state/PKCE, replayed code, stale link, missing or expired session |
| 403/404 | `tenant_unauthorized` | Tenant/issuer not configured or the mapping is disabled |
| 400 | `invalid_request` | Bad JSON or callback URI is not allow-listed |
| 409 | `binding_conflict` | Both verified identities already belong to different members |

## Identity model

Email is stored only as a claim snapshot when `email_verified=true`; it has no unique constraint and no lookup role. The authoritative key is:

```text
tenant_id + issuer + subject
```

That keeps `shared@example.com` in the two Keycloak realms separate. Repeated callbacks lock the flow row, transition it from `pending` to `consumed`/`failed`, and return `authentication_failed`; member provisioning is protected by a Postgres advisory lock and unique key.

## Integration tests

Tests are behind the `integration` build tag and run their own server on port 8080.

```bash
docker compose up -d --wait postgres keycloak
DATABASE_URL='postgres://app:app@localhost:5432/multitenant_oidc?sslmode=disable' \
  go test -tags=integration -v ./tests
```

Covered cases:

1. Cross-tenant same email creates separate members and sessions.
2. Authorization-code/state replay returns 401 and cannot provision another member.
3. Disabled tenant/issuer mapping returns 403 `tenant_unauthorized` before provider redirect.
4. Binding two identities that already belong to different members returns 409 `binding_conflict`.
5. Binding an existing and a fresh identity succeeds only after both legs reauthenticate.
6. Keycloak RSA signing-key rotation is followed by a successful new login through JWKS-based verification.

## Production notes

- Set `COOKIE_SECURE=true` and serve exclusively over HTTPS.
- Replace the deterministic local encryption passphrase with a secret in `FLOW_ENCRYPTION_KEY`; PKCE verifiers are encrypted at rest.
- Configure issuer/client rows out of band; don't expose tenant or issuer administration publicly.
- Use confidential OIDC clients where the deployment can protect a secret; the local example uses a public Keycloak client with forced S256 PKCE.
