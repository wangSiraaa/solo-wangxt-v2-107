package auth

import (
	"context"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	oidcx "github.example/multitenant-oidc/internal/oidc"
	"golang.org/x/oauth2"
)

type DBTX interface {
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Begin(ctx context.Context) (pgx.Tx, error)
}

const (
	flowTTL           = 10 * time.Minute
	sessionTTL        = 8 * time.Hour
	loginCallbackPath = "/callback/login"
	linkCallbackPath  = "/callback/link"
)

type Service struct {
	db                DBTX
	providers         *oidcx.Resolver
	encryptionKey     []byte
	baseURL           string
	maxAuthAgeBinding time.Duration
	now               func() time.Time
}

func NewService(db DBTX, providers *oidcx.Resolver, encryptionKey []byte, baseURL string, maxAuthAge time.Duration) *Service {
	return &Service{
		db:                db,
		providers:         providers,
		encryptionKey:     encryptionKey,
		baseURL:            strings.TrimRight(baseURL, "/"),
		maxAuthAgeBinding: maxAuthAge,
		now:               time.Now,
	}
}

type StartLoginRequest struct {
	TenantID    string `json:"tenant_id"`
	Issuer      string `json:"issuer"`
	RedirectURI string `json:"redirect_uri"`
}

type StartLinkRequest struct {
	TenantID string `json:"tenant_id"`
	Issuer1  string `json:"issuer1"`
	Issuer2  string `json:"issuer2"`
}

type StartFlowResult struct {
	AuthURL string `json:"auth_url"`
	State   string `json:"state"`
	LinkID  string `json:"link_id,omitempty"`
	Leg     int    `json:"leg,omitempty"`
}

type CallbackResult struct {
	Kind        string `json:"kind"`
	TenantID    string `json:"tenant_id"`
	MemberID    string `json:"member_id,omitempty"`
	Session     string `json:"session_token,omitempty"`
	LinkID      string `json:"link_id,omitempty"`
	Leg         int    `json:"leg,omitempty"`
	NextAuthURL string `json:"next_auth_url,omitempty"`
	Status      string `json:"status"`
}

type flowRecord struct {
	ID                string
	Kind              string
	TenantID          string
	Issuer            string
	ClientID          string
	ClientSecret      string
	RedirectURI       string
	NonceHash         []byte
	EncryptedVerifier []byte
	Status            string
	ExpiresAt         time.Time
	LinkFlowID        sql.NullString
	ExpectedLeg       sql.NullInt16
}

func (f flowRecord) clientConfig() ClientConfig {
	return ClientConfig{
		TenantID:     f.TenantID,
		Issuer:       f.Issuer,
		ClientID:     f.ClientID,
		ClientSecret: f.ClientSecret,
		RedirectURIs: []string{f.RedirectURI},
		Enabled:      true,
	}
}

type idTokenClaims struct {
	Nonce         string `json:"nonce"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	AuthTime      *int64 `json:"auth_time"`
}

func (s *Service) StartLogin(ctx context.Context, req StartLoginRequest) (StartFlowResult, error) {
	client, err := s.authorizedClient(ctx, req.TenantID, req.Issuer, req.RedirectURI)
	if err != nil {
		return StartFlowResult{}, err
	}
	state, nonce, verifier, authURL, err := s.authorizationURL(ctx, client, false)
	if err != nil {
		return StartFlowResult{}, NewAPIError(401, ErrorAuthenticationFailed, "cannot start OIDC authorization")
	}
	if err := s.insertOAuthFlow(ctx, s.db, "login", client, state, nonce, verifier, "", 0); err != nil {
		return StartFlowResult{}, err
	}
	return StartFlowResult{AuthURL: authURL, State: state}, nil
}

func (s *Service) StartLink(ctx context.Context, req StartLinkRequest) (StartFlowResult, error) {
	if req.TenantID == "" || req.Issuer1 == "" || req.Issuer2 == "" {
		return StartFlowResult{}, NewAPIError(400, ErrorInvalidRequest, "tenant_id, issuer1 and issuer2 are required")
	}
	redirect := s.baseURL + linkCallbackPath
	client1, err := s.authorizedClient(ctx, req.TenantID, req.Issuer1, redirect)
	if err != nil {
		return StartFlowResult{}, err
	}
	client2, err := s.authorizedClient(ctx, req.TenantID, req.Issuer2, redirect)
	if err != nil {
		return StartFlowResult{}, err
	}

	linkID := uuid.NewString()
	if _, err := s.db.Exec(ctx, `
		INSERT INTO link_flows(id, tenant_id, issuer1, issuer2, status)
		VALUES ($1,$2,$3,$4,'pending')`, linkID, req.TenantID, req.Issuer1, req.Issuer2); err != nil {
		return StartFlowResult{}, err
	}

	state, nonce, verifier, authURL, err := s.authorizationURL(ctx, client1, true)
	if err != nil {
		return StartFlowResult{}, NewAPIError(401, ErrorAuthenticationFailed, "cannot start OIDC authorization")
	}
	if err := s.insertOAuthFlow(ctx, s.db, "link", client1, state, nonce, verifier, linkID, 1); err != nil {
		return StartFlowResult{}, err
	}
	return StartFlowResult{AuthURL: authURL, State: state, LinkID: linkID, Leg: 1}, nil
}

func (s *Service) Callback(ctx context.Context, callbackPath string, params url.Values) (CallbackResult, error) {
	state := params.Get("state")
	if state == "" {
		return CallbackResult{}, NewAPIError(400, ErrorAuthenticationFailed, "missing state")
	}
	if errParam := params.Get("error"); errParam != "" {
		return CallbackResult{}, NewAPIError(401, ErrorAuthenticationFailed, "provider returned an authorization error")
	}
	code := params.Get("code")
	if code == "" {
		return CallbackResult{}, NewAPIError(400, ErrorAuthenticationFailed, "missing authorization code")
	}
	if callbackPath != loginCallbackPath && callbackPath != linkCallbackPath {
		return CallbackResult{}, NewAPIError(400, ErrorInvalidRequest, "unsupported callback address")
	}
	tx, err := s.db.Begin(ctx)
	if err != nil {
		return CallbackResult{}, err
	}
	defer tx.Rollback(ctx)

	flow, err := s.lockFlow(ctx, tx, state)
	if err != nil {
		return CallbackResult{}, err
	}
	expectedPath := loginCallbackPath
	if flow.Kind == "link" {
		expectedPath = linkCallbackPath
	}
	if callbackPath != expectedPath || flow.RedirectURI != s.baseURL+callbackPath {
		return CallbackResult{}, NewAPIError(400, ErrorInvalidRequest, "callback address does not match authorization flow")
	}
	if flow.Status != "pending" || s.now().UTC().After(flow.ExpiresAt) {
		_, _ = tx.Exec(ctx, `UPDATE oauth_flows SET status='expired' WHERE id=$1 AND status='pending'`, flow.ID)
		_ = tx.Commit(ctx)
		// Same error whether a browser back button, replay, or race repeats the
		// code. Rows are locked so concurrent callbacks cannot create two members.
		return CallbackResult{}, NewAPIError(401, ErrorAuthenticationFailed, "authorization response has already been used or expired")
	}

	verifier, err := decryptAESGCM(s.encryptionKey, flow.EncryptedVerifier)
	if err != nil {
		_, _ = tx.Exec(ctx, `UPDATE oauth_flows SET status='failed' WHERE id=$1`, flow.ID)
		_ = tx.Commit(ctx)
		return CallbackResult{}, NewAPIError(401, ErrorAuthenticationFailed, "invalid authorization flow")
	}

	identity, err := s.verifyAuthorizationCode(ctx, flow.clientConfig(), code, verifier, flow.NonceHash)
	if err != nil {
		_, _ = tx.Exec(ctx, `UPDATE oauth_flows SET status='failed' WHERE id=$1`, flow.ID)
		_ = tx.Commit(ctx)
		return CallbackResult{}, err
	}
	if flow.Kind == "link" {
		if identity.AuthTime == nil || s.now().UTC().Sub(*identity.AuthTime) > s.maxAuthAgeBinding {
			_, _ = tx.Exec(ctx, `UPDATE oauth_flows SET status='failed' WHERE id=$1`, flow.ID)
			_ = tx.Commit(ctx)
			return CallbackResult{}, NewAPIError(401, ErrorAuthenticationFailed, "fresh reauthentication is required for account binding")
		}
	}

	var result CallbackResult
	if flow.Kind == "login" {
		result, err = s.completeLogin(ctx, tx, flow, identity)
	} else {
		result, err = s.completeLinkLeg(ctx, tx, flow, identity)
	}
	if err != nil {
		return CallbackResult{}, err
	}
	if _, err := tx.Exec(ctx, `UPDATE oauth_flows SET status='consumed' WHERE id=$1`, flow.ID); err != nil {
		return CallbackResult{}, err
	}
	if result.Status == "completed" {
		if _, err := tx.Exec(ctx, `
			UPDATE link_flows SET status='completed', completed_at=now(), completed_member_id=$2
			WHERE id=$1 AND status='pending'`, result.LinkID, nullableUUID(result.MemberID)); err != nil {
			return CallbackResult{}, err
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return CallbackResult{}, err
	}
	return result, nil
}

func (s *Service) lockFlow(ctx context.Context, tx pgx.Tx, state string) (flowRecord, error) {
	var flow flowRecord
	row := tx.QueryRow(ctx, `
		SELECT f.id, f.kind, f.tenant_id, f.issuer, f.client_id, COALESCE(c.client_secret,''),
		       f.redirect_uri, f.nonce_hash, f.encrypted_code_verifier, f.status, f.expires_at,
		       f.link_flow_id, f.expected_leg
		FROM oauth_flows f
		JOIN oidc_clients c ON c.tenant_id = f.tenant_id AND c.issuer = f.issuer
		WHERE f.state_hash = $1
		FOR UPDATE`, hashSHA256(state))
	err := row.Scan(&flow.ID, &flow.Kind, &flow.TenantID, &flow.Issuer, &flow.ClientID, &flow.ClientSecret,
		&flow.RedirectURI, &flow.NonceHash, &flow.EncryptedVerifier, &flow.Status, &flow.ExpiresAt,
		&flow.LinkFlowID, &flow.ExpectedLeg)
	if err == pgx.ErrNoRows {
		return flowRecord{}, NewAPIError(401, ErrorAuthenticationFailed, "unknown or expired state")
	}
	return flow, err
}

func (s *Service) completeLogin(ctx context.Context, tx pgx.Tx, flow flowRecord, identity *VerifiedIdentity) (CallbackResult, error) {
	if err := lockIdentity(ctx, tx, identity.TenantID, identity.Issuer, identity.Subject); err != nil {
		return CallbackResult{}, err
	}

	memberID, err := findIdentityMember(ctx, tx, identity.TenantID, identity.Issuer, identity.Subject)
	if err != nil {
		return CallbackResult{}, err
	}
	if memberID == "" {
		if err := tx.QueryRow(ctx, `INSERT INTO account_members(tenant_id) VALUES ($1) RETURNING id`, identity.TenantID).Scan(&memberID); err != nil {
			return CallbackResult{}, err
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO oidc_identities(tenant_id, issuer, subject, member_id, email, email_verified)
			VALUES ($1,$2,$3,$4,$5,$6)`,
			identity.TenantID, identity.Issuer, identity.Subject, memberID, identity.Email, identity.EmailVerified); err != nil {
			return CallbackResult{}, mapWriteError(err)
		}
	} else if _, err := tx.Exec(ctx, `
		UPDATE oidc_identities
		SET email=$4, email_verified=$5, updated_at=now()
		WHERE tenant_id=$1 AND issuer=$2 AND subject=$3`,
		identity.TenantID, identity.Issuer, identity.Subject, identity.Email, identity.EmailVerified); err != nil {
		return CallbackResult{}, err
	}

	sessionToken, err := s.createSession(ctx, tx, identity.TenantID, memberID, identity.Issuer, identity.Subject)
	if err != nil {
		return CallbackResult{}, err
	}
	return CallbackResult{Kind: "login", Status: "completed", TenantID: identity.TenantID, MemberID: memberID, Session: sessionToken}, nil
}

func (s *Service) completeLinkLeg(ctx context.Context, tx pgx.Tx, flow flowRecord, identity *VerifiedIdentity) (CallbackResult, error) {
	if !flow.LinkFlowID.Valid || flow.ExpectedLeg.Int16 < 1 {
		return CallbackResult{}, NewAPIError(500, ErrorInvalidRequest, "invalid link flow")
	}
	linkID := flow.LinkFlowID.String
	leg := int(flow.ExpectedLeg.Int16)

	var linkTenantID, linkStatus, nextIssuer string
	err := tx.QueryRow(ctx, `SELECT tenant_id, status, CASE WHEN $2=1 THEN issuer2 ELSE issuer1 END FROM link_flows WHERE id=$1 FOR UPDATE`, linkID, leg).
		Scan(&linkTenantID, &linkStatus, &nextIssuer)
	if err == pgx.ErrNoRows {
		return CallbackResult{}, NewAPIError(404, ErrorInvalidRequest, "link flow not found")
	}
	if err != nil {
		return CallbackResult{}, err
	}
	if linkStatus != "pending" || linkTenantID != identity.TenantID {
		return CallbackResult{}, NewAPIError(401, ErrorAuthenticationFailed, "link flow has already been completed or expired")
	}

	var authTime sql.NullTime
	if identity.AuthTime != nil {
		authTime = sql.NullTime{Time: *identity.AuthTime, Valid: true}
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO link_flow_identities(link_flow_id, leg, issuer, subject, email, email_verified, auth_time)
		VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		linkID, leg, identity.Issuer, identity.Subject, identity.Email, identity.EmailVerified, authTime); err != nil {
		return CallbackResult{}, mapWriteError(err)
	}

	if leg == 1 {
		client, err := s.authorizedClientInTx(ctx, tx, identity.TenantID, nextIssuer, s.baseURL+linkCallbackPath)
		if err != nil {
			return CallbackResult{}, err
		}
		state, nonce, verifier, authURL, err := s.authorizationURL(ctx, client, true)
		if err != nil {
			return CallbackResult{}, NewAPIError(401, ErrorAuthenticationFailed, "cannot start second OIDC authorization")
		}
		if err := s.insertOAuthFlow(ctx, tx, "link", client, state, nonce, verifier, linkID, 2); err != nil {
			return CallbackResult{}, err
		}
		return CallbackResult{Kind: "link", Status: "pending_second_identity", TenantID: identity.TenantID, LinkID: linkID, Leg: 2, NextAuthURL: authURL}, nil
	}

	memberID, sessionToken, err := s.finalizeLink(ctx, tx, linkID, identity.TenantID)
	if err != nil {
		return CallbackResult{}, err
	}
	return CallbackResult{Kind: "link", Status: "completed", TenantID: identity.TenantID, MemberID: memberID, Session: sessionToken, LinkID: linkID}, nil
}

func (s *Service) finalizeLink(ctx context.Context, tx pgx.Tx, linkID, tenantID string) (string, string, error) {
	legs, err := loadLinkLegs(ctx, tx, linkID)
	if err != nil {
		return "", "", err
	}
	if len(legs) != 2 {
		return "", "", NewAPIError(401, ErrorAuthenticationFailed, "both identities must authenticate")
	}
	if legs[0].Issuer == legs[1].Issuer && legs[0].Subject == legs[1].Subject {
		return "", "", NewAPIError(400, ErrorBindingConflict, "two distinct OIDC identities are required")
	}

	ordered := append([]LinkIdentity(nil), legs...)
	slices.SortFunc(ordered, func(a, b LinkIdentity) int {
		return strings.Compare(a.Issuer+"\x00"+a.Subject, b.Issuer+"\x00"+b.Subject)
	})
	for _, identity := range ordered {
		if err := lockIdentity(ctx, tx, tenantID, identity.Issuer, identity.Subject); err != nil {
			return "", "", err
		}
	}

	memberIDs := make([]string, 2)
	for i, identity := range legs {
		id, err := findIdentityMember(ctx, tx, tenantID, identity.Issuer, identity.Subject)
		if err != nil {
			return "", "", err
		}
		memberIDs[i] = id
	}
	if memberIDs[0] != "" && memberIDs[1] != "" && memberIDs[0] != memberIDs[1] {
		if _, err := tx.Exec(ctx, `UPDATE link_flows SET status='abandoned' WHERE id=$1`, linkID); err != nil {
			return "", "", err
		}
		return "", "", NewAPIError(409, ErrorBindingConflict, "identities already belong to different members")
	}

	memberID := memberIDs[0]
	if memberID == "" {
		memberID = memberIDs[1]
	}
	if memberID == "" {
		if err := tx.QueryRow(ctx, `INSERT INTO account_members(tenant_id) VALUES ($1) RETURNING id`, tenantID).Scan(&memberID); err != nil {
			return "", "", err
		}
	}
	for _, identity := range legs {
		existing, err := findIdentityMember(ctx, tx, tenantID, identity.Issuer, identity.Subject)
		if err != nil {
			return "", "", err
		}
		if existing != "" {
			continue
		}
		if _, err := tx.Exec(ctx, `
			INSERT INTO oidc_identities(tenant_id, issuer, subject, member_id, email, email_verified)
			VALUES ($1,$2,$3,$4,$5,$6)`,
			tenantID, identity.Issuer, identity.Subject, memberID, identity.Email, identity.EmailVerified); err != nil {
			return "", "", mapWriteError(err)
		}
	}

	sessionToken, err := s.createSession(ctx, tx, tenantID, memberID, legs[1].Issuer, legs[1].Subject)
	if err != nil {
		return "", "", err
	}
	return memberID, sessionToken, nil
}

func (s *Service) createSession(ctx context.Context, tx pgx.Tx, tenantID, memberID, issuer, subject string) (string, error) {
	rawToken, err := newRandomString(32)
	if err != nil {
		return "", err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO sessions(token_hash, tenant_id, member_id, issuer, subject, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6)`,
		hashSHA256(rawToken), tenantID, memberID, issuer, subject, s.now().UTC().Add(sessionTTL)); err != nil {
		return "", err
	}
	return rawToken, nil
}

func (s *Service) authorizationURL(ctx context.Context, client ClientConfig, forceLogin bool) (state, nonce, verifier, authURL string, err error) {
	state, err = newRandomString(32)
	if err != nil {
		return
	}
	nonce, err = newRandomString(32)
	if err != nil {
		return
	}
	verifier, err = oauth2.GenerateVerifier()
	if err != nil {
		return
	}
	provider, err := s.providers.Build(ctx, client.Issuer, client.ClientID, client.ClientSecret, client.RedirectURIs[0], nil)
	if err != nil {
		return "", "", "", "", err
	}
	options := []oauth2.AuthCodeOption{
		oauth2.SetAuthURLParam("nonce", nonce),
		oauth2.S256ChallengeOption(verifier),
	}
	if forceLogin {
		options = append(options, oauth2.SetAuthURLParam("prompt", "login"))
	}
	return state, nonce, verifier, provider.Config.AuthCodeURL(state, options...), nil
}

func (s *Service) insertOAuthFlow(ctx context.Context, tx DBTX, kind string, client ClientConfig, state, nonce, verifier, linkID string, leg int) error {
	encrypted, err := encryptAESGCM(s.encryptionKey, verifier)
	if err != nil {
		return err
	}
	var linkUUID sql.NullString
	if linkID != "" {
		linkUUID = sql.NullString{String: linkID, Valid: true}
	}
	var expectedLeg sql.NullInt16
	if leg > 0 {
		expectedLeg = sql.NullInt16{Int16: int16(leg), Valid: true}
	}
	_, err = tx.Exec(ctx, `
		INSERT INTO oauth_flows(kind, tenant_id, issuer, client_id, redirect_uri, state_hash, nonce_hash,
			encrypted_code_verifier, link_flow_id, expected_leg, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
		kind, client.TenantID, client.Issuer, client.ClientID, client.RedirectURIs[0],
		hashSHA256(state), hashSHA256(nonce), encrypted, linkUUID, expectedLeg, s.now().UTC().Add(flowTTL))
	return mapWriteError(err)
}

func (s *Service) verifyAuthorizationCode(ctx context.Context, client ClientConfig, code, verifier string, expectedNonceHash []byte) (*VerifiedIdentity, error) {
	provider, err := s.providers.Build(ctx, client.Issuer, client.ClientID, client.ClientSecret, client.RedirectURIs[0], nil)
	if err != nil {
		return nil, NewAPIError(401, ErrorAuthenticationFailed, "OIDC provider discovery failed")
	}
	exchangeCtx := context.WithValue(ctx, oauth2.HTTPClient, s.providers.HTTPClient())
	token, err := provider.Config.Exchange(exchangeCtx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		return nil, NewAPIError(401, ErrorAuthenticationFailed, "authorization code exchange or PKCE verification failed")
	}
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok || rawIDToken == "" {
		return nil, NewAPIError(401, ErrorAuthenticationFailed, "provider did not return an identity token")
	}

	idToken, err := provider.Verifier.Verify(ctx, rawIDToken)
	if err != nil {
		return nil, NewAPIError(401, ErrorAuthenticationFailed, "identity token signature, issuer or audience verification failed")
	}
	if idToken.Issuer != client.Issuer || len(idToken.Audience) != 1 || idToken.Audience[0] != client.ClientID {
		return nil, NewAPIError(401, ErrorAuthenticationFailed, "identity token issuer or audience mismatch")
	}
	var claims idTokenClaims
	if err := idToken.Claims(&claims); err != nil {
		return nil, NewAPIError(401, ErrorAuthenticationFailed, "identity token claims are invalid")
	}
	if !constantTimeEqualHex(hex.EncodeToString(expectedNonceHash), hashString(claims.Nonce)) {
		return nil, NewAPIError(401, ErrorAuthenticationFailed, "nonce mismatch")
	}

	identity := &VerifiedIdentity{TenantID: client.TenantID, Issuer: idToken.Issuer, Subject: idToken.Subject, EmailVerified: claims.EmailVerified}
	if claims.EmailVerified {
		identity.Email = strings.ToLower(strings.TrimSpace(claims.Email))
	}
	if claims.AuthTime != nil {
		t := time.Unix(*claims.AuthTime, 0).UTC()
		identity.AuthTime = &t
	}
	if identity.Subject == "" {
		return nil, NewAPIError(401, ErrorAuthenticationFailed, "identity token is missing subject")
	}
	return identity, nil
}

func (s *Service) Session(ctx context.Context, token string) (SessionInfo, error) {
	if token == "" {
		return SessionInfo{}, NewAPIError(401, ErrorAuthenticationFailed, "missing session")
	}
	var info SessionInfo
	var expiresAt time.Time
	err := s.db.QueryRow(ctx, `
		SELECT id, tenant_id, member_id, issuer, subject, expires_at
		FROM sessions WHERE token_hash=$1`, hashSHA256(token)).
		Scan(&info.ID, &info.TenantID, &info.MemberID, &info.Issuer, &info.Subject, &expiresAt)
	if err == pgx.ErrNoRows || s.now().UTC().After(expiresAt) {
		return SessionInfo{}, NewAPIError(401, ErrorAuthenticationFailed, "session is invalid or expired")
	}
	return info, err
}

func (s *Service) authorizedClient(ctx context.Context, tenantID, issuer, redirectURI string) (ClientConfig, error) {
	return scanAuthorizedClient(ctx, s.db, tenantID, issuer, redirectURI)
}

func (s *Service) authorizedClientInTx(ctx context.Context, tx pgx.Tx, tenantID, issuer, redirectURI string) (ClientConfig, error) {
	return scanAuthorizedClient(ctx, tx, tenantID, issuer, redirectURI)
}

func scanAuthorizedClient(ctx context.Context, q DBTX, tenantID, issuer, redirectURI string) (ClientConfig, error) {
	if tenantID == "" || issuer == "" || redirectURI == "" {
		return ClientConfig{}, NewAPIError(400, ErrorInvalidRequest, "tenant_id, issuer and redirect_uri are required")
	}
	var tenantExists bool
	if err := q.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM tenants WHERE id=$1)`, tenantID).Scan(&tenantExists); err != nil {
		return ClientConfig{}, err
	}
	if !tenantExists {
		return ClientConfig{}, NewAPIError(404, ErrorTenantUnauthorized, "tenant is not registered")
	}
	var cfg ClientConfig
	err := q.QueryRow(ctx, `
		SELECT tenant_id, issuer, client_id, COALESCE(client_secret,''), redirect_uris, enabled
		FROM oidc_clients WHERE tenant_id=$1 AND issuer=$2 FOR SHARE`, tenantID, issuer).
		Scan(&cfg.TenantID, &cfg.Issuer, &cfg.ClientID, &cfg.ClientSecret, &cfg.RedirectURIs, &cfg.Enabled)
	if err == pgx.ErrNoRows {
		return ClientConfig{}, NewAPIError(403, ErrorTenantUnauthorized, "issuer is not authorized for tenant")
	}
	if err != nil {
		return ClientConfig{}, err
	}
	if !cfg.Enabled {
		return ClientConfig{}, NewAPIError(403, ErrorTenantUnauthorized, "issuer is disabled for tenant")
	}
	if !slices.Contains(cfg.RedirectURIs, redirectURI) {
		return ClientConfig{}, NewAPIError(400, ErrorInvalidRequest, "redirect_uri is not allow-listed")
	}
	return cfg, nil
}

func lockIdentity(ctx context.Context, tx pgx.Tx, tenantID, issuer, subject string) error {
	lock1, lock2 := advisoryLockKeys(tenantID, issuer, subject)
	_, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock($1,$2)`, lock1, lock2)
	return err
}

func findIdentityMember(ctx context.Context, tx pgx.Tx, tenantID, issuer, subject string) (string, error) {
	var memberID string
	err := tx.QueryRow(ctx, `
		SELECT member_id FROM oidc_identities
		WHERE tenant_id=$1 AND issuer=$2 AND subject=$3`, tenantID, issuer, subject).Scan(&memberID)
	if err == pgx.ErrNoRows {
		return "", nil
	}
	return memberID, err
}

func loadLinkLegs(ctx context.Context, tx pgx.Tx, linkID string) ([]LinkIdentity, error) {
	rows, err := tx.Query(ctx, `
		SELECT leg, issuer, subject, email, email_verified, auth_time
		FROM link_flow_identities WHERE link_flow_id=$1 ORDER BY leg`, linkID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	legs := make([]LinkIdentity, 0, 2)
	for rows.Next() {
		var leg LinkIdentity
		var authTime sql.NullTime
		if err := rows.Scan(&leg.Leg, &leg.Issuer, &leg.Subject, &leg.Email, &leg.EmailVerified, &authTime); err != nil {
			return nil, err
		}
		if authTime.Valid {
			leg.AuthTime = &authTime.Time
		}
		legs = append(legs, leg)
	}
	return legs, rows.Err()
}

func advisoryLockKeys(tenantID, issuer, subject string) (int32, int32) {
	sum := hashSHA256(tenantID, issuer, subject)
	return int32(binary.BigEndian.Uint32(sum[:4])), int32(binary.BigEndian.Uint32(sum[4:8]))
}

func mapWriteError(err error) error {
	if err == nil {
		return nil
	}
	if strings.Contains(err.Error(), "SQLSTATE 23505") {
		return NewAPIError(409, ErrorBindingConflict, "verified OIDC identity is already bound to another member")
	}
	return err
}

func nullableUUID(value string) any {
	if value == "" {
		return nil
	}
	return value
}
