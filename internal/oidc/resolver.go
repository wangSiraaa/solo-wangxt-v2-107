package oidcx

import (
	"context"
	"net/http"
	"sync"
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

type Provider struct {
	Issuer   string
	Discovery *gooidc.Provider
	Verifier *gooidc.IDTokenVerifier
	Config   *oauth2.Config
}

type Resolver struct {
	httpClient *http.Client
	mu         sync.RWMutex
	providers  map[string]*gooidc.Provider
}

func NewResolver(timeout time.Duration) *Resolver {
	return &Resolver{
		httpClient: &http.Client{Timeout: timeout},
		providers: map[string]*gooidc.Provider{},
	}
}

func (r *Resolver) provider(ctx context.Context, issuer string) (*gooidc.Provider, error) {
	r.mu.RLock()
	p := r.providers[issuer]
	r.mu.RUnlock()
	if p != nil {
		return p, nil
	}

	remoteCtx := gooidc.ClientContext(ctx, r.httpClient)
	newProvider, err := gooidc.NewProvider(remoteCtx, issuer)
	if err != nil {
		return nil, err
	}

	r.mu.Lock()
	if existing := r.providers[issuer]; existing != nil {
		newProvider = existing
	} else {
		r.providers[issuer] = newProvider
	}
	r.mu.Unlock()
	return newProvider, nil
}

// Build creates an OAuth2 client and a go-oidc verifier. go-oidc uses the
// issuer's JWKS endpoint and refreshes cached keys, so Keycloak key rotation is
// picked up without restarting this service.
func (r *Resolver) Build(ctx context.Context, issuer, clientID, clientSecret, redirectURL string, scopes []string) (*Provider, error) {
	ctx = gooidc.ClientContext(ctx, r.httpClient)
	discovery, err := r.provider(ctx, issuer)
	if err != nil {
		return nil, err
	}
	if scopes == nil {
		scopes = []string{gooidc.ScopeOpenID, "email", "profile"}
	}

	return &Provider{
		Issuer:    issuer,
		Discovery: discovery,
		Verifier: discovery.VerifierContext(ctx, &gooidc.Config{
			ClientID:                   clientID,
			SkipClientIDCheck:          false,
			SkipIssuerCheck:            false,
			SupportedSigningAlgs:       []string{"RS256"},
		}),
		Config: &oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			Endpoint:     discovery.Endpoint(),
			RedirectURL:  redirectURL,
			Scopes:       scopes,
		},
	}, nil
}

func (r *Resolver) HTTPClient() *http.Client { return r.httpClient }
