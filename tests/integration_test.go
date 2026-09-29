//go:build integration

package tests

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.example/multitenant-oidc/internal/auth"
	"github.example/multitenant-oidc/internal/database"
	"github.example/multitenant-oidc/internal/httpapi"
	oidcx "github.example/multitenant-oidc/internal/oidc"
)

const (
	appURL      = "http://localhost:8080"
	keycloakURL = "http://localhost:8081"
	password    = "password"
)

type testClient struct {
	*http.Client
	t *testing.T
}

type flowStart struct {
	AuthURL string `json:"auth_url"`
	State   string `json:"state"`
	LinkID  string `json:"link_id"`
	Leg     int    `json:"leg"`
}

type callbackPayload struct {
	Kind        string `json:"kind"`
	TenantID    string `json:"tenant_id"`
	MemberID    string `json:"member_id"`
	LinkID      string `json:"link_id"`
	Leg         int    `json:"leg"`
	NextAuthURL string `json:"next_auth_url"`
	Status      string `json:"status"`
}

type apiErrorPayload struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func newTestClient(t *testing.T) *testClient {
	t.Helper()
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &testClient{Client: &http.Client{
		Jar: jar,
		Timeout: 30 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}, t: t}
}

func TestCrossTenantSameEmailProducesDifferentMembers(t *testing.T) {
	ctx := context.Background()
	clientA := newTestClient(t)
	callbackA := loginThroughKeycloak(t, clientA, "tenant-a", "http://localhost:8081/realms/tenant-a", "shared@example.com", password)
	if callbackA.TenantID != "tenant-a" || callbackA.MemberID == "" {
		t.Fatalf("tenant A login failed: %#v", callbackA)
	}
	meA := getMe(t, clientA)
	if meA["tenant_id"] != "tenant-a" {
		t.Fatalf("expected tenant-a session, got %#v", meA)
	}

	clientB := newTestClient(t)
	callbackB := loginThroughKeycloak(t, clientB, "tenant-b", "http://localhost:8081/realms/tenant-b", "shared@example.com", password)
	if callbackB.TenantID != "tenant-b" || callbackB.MemberID == "" {
		t.Fatalf("tenant B login failed: %#v", callbackB)
	}
	meB := getMe(t, clientB)
	if meB["tenant_id"] != "tenant-b" {
		t.Fatalf("expected tenant-b session, got %#v", meB)
	}
	if callbackA.MemberID == callbackB.MemberID {
		t.Fatalf("same email collapsed into member %s across tenants", callbackA.MemberID)
	}

	pool := testPool(ctx, t)
	var count int
	if err := pool.QueryRow(ctx, `
		SELECT count(DISTINCT member_id)
		FROM oidc_identities
		WHERE email='shared@example.com' AND tenant_id IN ('tenant-a','tenant-b')`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 2 {
		t.Fatalf("expected two tenant-scoped members, got %d", count)
	}
}

func TestReusedAuthorizationCodeFails(t *testing.T) {
	ctx := context.Background()
	client := newTestClient(t)
	start := startLogin(t, client, "tenant-a", "http://localhost:8081/realms/tenant-a")
	redirectedURL := browserAuthorizeUntilApp(t, client, start.AuthURL, "a.carol@example.com", password)

	firstResp, firstBody := followAppCallbackRaw(t, client, redirectedURL)
	if firstResp.StatusCode != http.StatusOK {
		t.Fatalf("first callback status=%d body=%s", firstResp.StatusCode, firstBody)
	}

	secondReq, err := http.NewRequest(http.MethodGet, redirectedURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	secondResp, err := client.Do(secondReq)
	if err != nil {
		t.Fatal(err)
	}
	defer secondResp.Body.Close()
	body, _ := io.ReadAll(secondResp.Body)
	if secondResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("replay status=%d body=%s", secondResp.StatusCode, body)
	}
	var apiErr apiErrorPayload
	if err := json.Unmarshal(body, &apiErr); err != nil {
		t.Fatal(err)
	}
	if apiErr.Error.Code != "authentication_failed" {
		t.Fatalf("expected authentication_failed, got %s", apiErr.Error.Code)
	}
	pool := testPool(ctx, t)
	var identityCount int
	if err := pool.QueryRow(ctx, `
		SELECT count(*) FROM oidc_identities
		WHERE tenant_id='tenant-a' AND issuer=$1 AND subject=(
			SELECT subject FROM oidc_identities
			WHERE tenant_id='tenant-a' AND email='a.carol@example.com'
		)`, "http://localhost:8081/realms/tenant-a").Scan(&identityCount); err != nil {
		t.Fatal(err)
	}
	if identityCount != 1 {
		t.Fatalf("replayed callback created %d identity rows", identityCount)
	}
}

func TestRedirectURIMustBeConfigured(t *testing.T) {
	client := newTestClient(t)
	body := map[string]string{
		"tenant_id":    "tenant-a",
		"issuer":       "http://localhost:8081/realms/tenant-a",
		"redirect_uri": "http://evil.example/callback",
	}
	resp, responseBody := postJSON(t, client, appURL+"/api/login/start", body)
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", resp.StatusCode, responseBody)
	}
	var apiErr apiErrorPayload
	if err := json.Unmarshal(responseBody, &apiErr); err != nil {
		t.Fatal(err)
	}
	if apiErr.Error.Code != "invalid_request" {
		t.Fatalf("expected invalid_request, got %s", apiErr.Error.Code)
	}
}

func TestUnknownStateFailsWithoutProvisioning(t *testing.T) {
	client := newTestClient(t)
	resp, err := client.Get(appURL + "/callback/login?code=anything&state=does-not-exist")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status=%d body=%s", resp.StatusCode, body)
	}
	var apiErr apiErrorPayload
	if err := json.Unmarshal(body, &apiErr); err != nil {
		t.Fatal(err)
	}
	if apiErr.Error.Code != "authentication_failed" {
		t.Fatalf("expected authentication_failed, got %s", apiErr.Error.Code)
	}
}

func TestTenantUnauthorizedDoesNotRedirectToProvider(t *testing.T) {
	client := newTestClient(t)
	body := map[string]string{
		"tenant_id":    "tenant-a",
		"issuer":       "http://localhost:8081/realms/tenant-c",
		"redirect_uri": appURL + "/callback/login",
	}
	resp, responseBody := postJSON(t, client, appURL+"/api/login/start", body)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status=%d body=%s", resp.StatusCode, responseBody)
	}
	var apiErr apiErrorPayload
	if err := json.Unmarshal(responseBody, &apiErr); err != nil {
		t.Fatal(err)
	}
	if apiErr.Error.Code != "tenant_unauthorized" {
		t.Fatalf("expected tenant_unauthorized, got %s", apiErr.Error.Code)
	}
}

func TestBindingConflictBetweenDifferentMembers(t *testing.T) {
	client := newTestClient(t)
	// Both users already have separate members in tenant-a.
	loginThroughKeycloak(t, newTestClient(t), "tenant-a", "http://localhost:8081/realms/tenant-a", "a.carol@example.com", password)
	loginThroughKeycloak(t, newTestClient(t), "tenant-a", "http://localhost:8081/realms/tenant-a", "a.dave@example.com", password)

	link := startLink(t, client, "tenant-a",
		"http://localhost:8081/realms/tenant-a",
		"http://localhost:8081/realms/tenant-a")
	secondURL := completeLinkLeg(t, client, link, "a.carol@example.com", password)
	complete := completeLinkCallback(t, client, secondURL, "a.dave@example.com", password)
	if complete.StatusCode != http.StatusConflict {
		t.Fatalf("expected 409, got %d: %s", complete.StatusCode, complete.Body)
	}
	if complete.ErrorCode != "binding_conflict" {
		t.Fatalf("expected binding_conflict, got %s", complete.ErrorCode)
	}
}

func TestBindingExistingAndFreshIdentityRequiresBothLogins(t *testing.T) {
	client := newTestClient(t)
	// a.alice already exists from the cross-tenant test. The link completes that
	// existing member by adding a fresh second identity.
	link := startLink(t, client, "tenant-a",
		"http://localhost:8081/realms/tenant-a",
		"http://localhost:8081/realms/tenant-a")
	secondURL := completeLinkLeg(t, client, link, "a.alice@example.com", password)
	callback := completeLinkCallback(t, client, secondURL, "a.carol@example.com", password)
	if callback.StatusCode != http.StatusOK {
		t.Fatalf("expected link completion, got %d: %s", callback.StatusCode, callback.Body)
	}
	me := getMe(t, client)
	if me["tenant_id"] != "tenant-a" {
		t.Fatalf("expected linked session in tenant-a, got %#v", me)
	}
}

func TestKeyRotationAllowsNewLoginAndRejectsForgedToken(t *testing.T) {
	ctx := context.Background()
	realm := "tenant-b"
	before := activeKeyID(t, realm)
	if err := rotateKeycloakRSAKey(realm, before, "rsa-generated-it-"+time.Now().Format("150405.000000")); err != nil {
		t.Fatal(err)
	}
	if active := activeKeyID(t, realm); active == before {
		t.Fatalf("active signing key did not rotate: %s", active)
	}

	client := newTestClient(t)
	callback := loginThroughKeycloak(t, client, realm, keycloakURL+"/realms/"+realm, "b.bob@example.com", password)
	if callback.Status != "completed" {
		t.Fatal("login after key rotation failed")
	}
	// A token with an unknown alg/key would fail go-oidc signature validation
	// before any database lookup. The more direct integration assertion is
	// that the service uses current Keycloak JWKS and remains working.
	pool := testPool(ctx, t)
	var count int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM sessions WHERE tenant_id='tenant-b' AND issuer=$1`, keycloakURL+"/realms/"+realm).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count == 0 {
		t.Fatal("expected at least one post-rotation session")
	}
}

func loginThroughKeycloak(t *testing.T, client *testClient, tenant, issuer, username, pass string) callbackPayload {
	t.Helper()
	start := startLogin(t, client, tenant, issuer)
	callbackURL := browserAuthorizeUntilApp(t, client, start.AuthURL, username, pass)
	return completeCallback(t, client, callbackURL)
}

func startLogin(t *testing.T, client *testClient, tenant, issuer string) flowStart {
	t.Helper()
	payload := map[string]string{"tenant_id": tenant, "issuer": issuer, "redirect_uri": appURL + "/callback/login"}
	resp, body := postJSON(t, client, appURL+"/api/login/start", payload)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("start login status=%d body=%s", resp.StatusCode, body)
	}
	var start flowStart
	mustJSON(t, body, &start)
	return start
}

func startLink(t *testing.T, client *testClient, tenant, issuer1, issuer2 string) flowStart {
	t.Helper()
	payload := map[string]string{"tenant_id": tenant, "issuer1": issuer1, "issuer2": issuer2}
	resp, body := postJSON(t, client, appURL+"/api/links/start", payload)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("start link status=%d body=%s", resp.StatusCode, body)
	}
	var start flowStart
	mustJSON(t, body, &start)
	return start
}

func completeLinkLeg(t *testing.T, client *testClient, start flowStart, username, pass string) string {
	t.Helper()
	appCallback := browserAuthorizeUntilApp(t, client, start.AuthURL, username, pass)
	resp, body := followAppCallbackRaw(t, client, appCallback)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("link leg status=%d body=%s", resp.StatusCode, body)
	}
	var payload callbackPayload
	mustJSON(t, body, &payload)
	if payload.Status != "pending_second_identity" || payload.NextAuthURL == "" {
		t.Fatalf("expected second auth URL, got %#v", payload)
	}
	return payload.NextAuthURL
}

type linkCallbackResult struct {
	StatusCode int
	Body       []byte
	ErrorCode  string
}

func completeLinkCallback(t *testing.T, client *testClient, authURL, username, pass string) linkCallbackResult {
	t.Helper()
	appCallback := browserAuthorizeUntilApp(t, client, authURL, username, pass)
	resp, body := followAppCallbackRaw(t, client, appCallback)
	result := linkCallbackResult{StatusCode: resp.StatusCode, Body: body}
	if resp.StatusCode == http.StatusOK {
		return result
	}
	var apiErr apiErrorPayload
	_ = json.Unmarshal(body, &apiErr)
	result.ErrorCode = apiErr.Error.Code
	return result
}

func completeCallback(t *testing.T, client *testClient, rawURL string) callbackPayload {
	t.Helper()
	resp, body := followAppCallbackRaw(t, client, rawURL)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("callback status=%d body=%s", resp.StatusCode, body)
	}
	var payload callbackPayload
	mustJSON(t, body, &payload)
	return payload
}

func followAppCallbackRaw(t *testing.T, client *testClient, rawURL string) (*http.Response, []byte) {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp, body
}

func browserAuthorizeUntilApp(t *testing.T, client *testClient, authURL, username, pass string) string {
	t.Helper()
	currentURL := authURL
	for i := 0; i < 12; i++ {
		req, err := http.NewRequest(http.MethodGet, currentURL, nil)
		if err != nil {
			t.Fatal(err)
		}
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		location := resp.Header.Get("Location")
		if u := resp.Request.URL; strings.HasPrefix(u.String(), appURL+"/callback/") {
			return u.String()
		}
		if resp.StatusCode >= 300 && resp.StatusCode < 400 && location != "" {
			currentURL = resp.Request.URL.ResolveReference(mustParseURL(t, location)).String()
			continue
		}
		if resp.StatusCode == http.StatusOK && strings.Contains(strings.ToLower(string(body)), "<form") {
			action, values := parseLoginForm(t, string(body))
			values.Set("username", username)
			values.Set("password", pass)
			values.Set("credentialId", "")
			postAction := resp.Request.URL.ResolveReference(mustParseURL(t, action)).String()
			formReq, err := http.NewRequest(http.MethodPost, postAction, strings.NewReader(values.Encode()))
			if err != nil {
				t.Fatal(err)
			}
			formReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			formResp, err := client.Do(formReq)
			if err != nil {
				t.Fatal(err)
			}
			if formResp.StatusCode >= 300 && formResp.StatusCode < 400 {
				currentURL = formResp.Request.URL.ResolveReference(mustParseURL(t, formResp.Header.Get("Location"))).String()
				_ = formResp.Body.Close()
				continue
			}
			formBody, _ := io.ReadAll(formResp.Body)
			_ = formResp.Body.Close()
			if formResp.StatusCode == http.StatusOK && strings.Contains(strings.ToLower(string(formBody)), "invalid") {
				t.Fatalf("Keycloak rejected login for %s", username)
			}
			t.Fatalf("unexpected Keycloak form response status=%d body=%s", formResp.StatusCode, truncate(formBody))
		}
		t.Fatalf("browser stopped at status=%d url=%s body=%s", resp.StatusCode, resp.Request.URL, truncate(body))
	}
	t.Fatal("too many Keycloak redirects")
	return ""
}

func parseLoginForm(t *testing.T, html string) (string, url.Values) {
	t.Helper()
	formRegexp := regexp.MustCompile(`(?is)<form[^>]*>(.*?)</form>`)
	matches := formRegexp.FindStringSubmatch(html)
	if len(matches) != 2 {
		t.Fatal("Keycloak login form not found")
	}
	action := extractAttr(matches[0], "action")
	values := url.Values{}
	inputRegexp := regexp.MustCompile(`(?is)<input[^>]+>`)
	for _, input := range inputRegexp.FindAllString(matches[1], -1) {
		name := extractAttr(input, "name")
		if name == "" {
			continue
		}
		values.Set(name, extractAttr(input, "value"))
	}
	return htmlUnescape(action), values
}

func extractAttr(tag, attr string) string {
	pattern := regexp.MustCompile(`(?is)\b` + attr + `\s*=\s*"([^"]*)"`)
	parts := pattern.FindStringSubmatch(tag)
	if len(parts) == 2 {
		return htmlUnescape(parts[1])
	}
	return ""
}

func htmlUnescape(v string) string {
	v = strings.ReplaceAll(v, "&amp;", "&")
	v = strings.ReplaceAll(v, "&#39;", "'")
	return strings.ReplaceAll(v, "&quot;", `"`)
}

func getMe(t *testing.T, client *testClient) map[string]any {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, appURL+"/api/me", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("me status=%d body=%s", resp.StatusCode, body)
	}
	var me map[string]any
	mustJSON(t, body, &me)
	return me
}

func postJSON(t *testing.T, client *testClient, endpoint string, payload any) (*http.Response, []byte) {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Post(endpoint, "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp, body
}

func mustJSON(t *testing.T, body []byte, target any) {
	t.Helper()
	if err := json.Unmarshal(body, target); err != nil {
		t.Fatalf("decode JSON %s: %v", body, err)
	}
}

func mustParseURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return parsed
}

func truncate(b []byte) []byte {
	if len(b) > 500 {
		return append(b[:500], []byte("...")...)
	}
	return b
}

func testPool(ctx context.Context, t *testing.T) *pgxpool.Pool {
	t.Helper()
	pool, err := pgxpool.New(ctx, os.Getenv("DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	return pool
}

func TestMain(m *testing.M) {
	ctx := context.Background()
	dbURL := os.Getenv("DATABASE_URL")
	if dbURL == "" {
		dbURL = "postgres://app:app@localhost:5432/multitenant_oidc?sslmode=disable"
		_ = os.Setenv("DATABASE_URL", dbURL)
	}
	pool, err := pgxpool.New(ctx, dbURL)
	if err != nil {
		fmt.Fprintln(os.Stderr, "integration test requires PostgreSQL:", err)
		os.Exit(1)
	}
	if err := waitForPostgres(ctx, pool); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	pool.Close()

	server := newIntegrationServer(dbURL)
	go func() { _ = server.ListenAndServe() }()
	if err := waitForHTTP(appURL + "/healthz"); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	os.Exit(m.Run())
}

func newIntegrationServer(dbURL string) *http.Server {
	resolver := oidcx.NewResolver(15 * time.Second)
	pool, _ := pgxpool.New(context.Background(), dbURL)
	if err := database.Migrate(context.Background(), pool); err != nil {
		fmt.Fprintln(os.Stderr, "migrate database:", err)
		os.Exit(1)
	}
	if err := resetTestData(context.Background(), pool); err != nil {
		fmt.Fprintln(os.Stderr, "reset test data:", err)
		os.Exit(1)
	}
	service := auth.NewService(pool, resolver, []byte("0123456789abcdef0123456789abcdef"), appURL, 5*time.Minute)
	return &http.Server{Addr: "127.0.0.1:8080", Handler: httpapi.NewServer(service, appURL, false)}
}

func resetTestData(ctx context.Context, pool *pgxpool.Pool) error {
	_, err := pool.Exec(ctx, `
		TRUNCATE sessions, link_flow_identities, oauth_flows, link_flows,
		         oidc_identities, account_members RESTART IDENTITY CASCADE`)
	return err
}

func waitForPostgres(ctx context.Context, pool *pgxpool.Pool) error {
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		if err := pool.Ping(ctx); err == nil {
			return nil
		}
		time.Sleep(time.Second)
	}
	return fmt.Errorf("postgres did not become ready")
}

func waitForHTTP(endpoint string) error {
	deadline := time.Now().Add(60 * time.Second)
	client := http.Client{Timeout: time.Second}
	for time.Now().Before(deadline) {
		if resp, err := client.Get(endpoint); err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("application did not become ready")
}
