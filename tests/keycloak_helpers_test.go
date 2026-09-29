//go:build integration

package tests

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type keycloakComponent struct {
	ID           string         `json:"id"`
	Name         string         `json:"name"`
	ProviderID   string         `json:"providerId"`
	ProviderType string         `json:"providerType"`
	ParentID     string         `json:"parentId"`
	SubType      string         `json:"subType"`
	Config       map[string]any `json:"config"`
	Components   any            `json:"components"`
}

func keycloakAdminToken(t *testing.T) string {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, keycloakURL+"/realms/master/protocol/openid-connect/token",
		strings.NewReader("grant_type=password&client_id=admin-cli&username=admin&password=admin"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("admin token status=%d body=%s", resp.StatusCode, body)
	}
	var token struct{ AccessToken string `json:"access_token"` }
	if err := json.NewDecoder(resp.Body).Decode(&token); err != nil {
		t.Fatal(err)
	}
	return token.AccessToken
}

func keycloakComponents(t *testing.T, realm, token string) []keycloakComponent {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, keycloakURL+"/admin/realms/"+realm+"/components?type=org.keycloak.keys.KeyProvider", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("components status=%d body=%s", resp.StatusCode, body)
	}
	var components []keycloakComponent
	if err := json.NewDecoder(resp.Body).Decode(&components); err != nil {
		t.Fatal(err)
	}
	return components
}

func activeKeyID(t *testing.T, realm string) string {
	t.Helper()
	resp, err := http.Get(keycloakURL + "/realms/" + realm + "/protocol/openid-connect/certs")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var jwks struct {
		Keys []struct {
			Kid string `json:"kid"`
			Use string `json:"use"`
		} `json:"keys"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&jwks); err != nil {
		t.Fatal(err)
	}
	for _, key := range jwks.Keys {
		if key.Use == "sig" {
			return key.Kid
		}
	}
	t.Fatal("no signing key in JWKS")
	return ""
}

func rotateKeycloakRSAKey(realm, oldKid, name string) error {
	token := adminToken()
	components := adminComponents(realm, token)
	var template keycloakComponent
	for _, component := range components {
		if component.ProviderID == "rsa-generated" {
			template = component
			break
		}
	}
	if template.ID == "" {
		return fmt.Errorf("rsa-generated component not found")
	}
	template.ID = ""
	template.Name = name
	template.Config["active"] = []any{true}
	template.Config["enabled"] = []any{true}
	template.Config["priority"] = []any{float64(150)}
	if err := createComponent(realm, token, template); err != nil {
		return err
	}
	for _, component := range components {
		if component.ProviderID == "rsa-generated" {
			component.Config["priority"] = []any{float64(0)}
			if err := updateComponent(realm, token, component.ID, component); err != nil {
				return err
			}
		}
	}
	return waitForActiveKeyChange(realm, oldKid, 15*time.Second)
}

func adminToken() string {
	form := strings.NewReader("grant_type=password&client_id=admin-cli&username=admin&password=admin")
	req, _ := http.NewRequest(http.MethodPost, keycloakURL+"/realms/master/protocol/openid-connect/token", form)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	var token struct{ AccessToken string `json:"access_token"` }
	if err := json.NewDecoder(resp.Body).Decode(&token); err != nil {
		panic(err)
	}
	return token.AccessToken
}

func adminComponents(realm, token string) []keycloakComponent {
	req, _ := http.NewRequest(http.MethodGet, keycloakURL+"/admin/realms/"+realm+"/components?type=org.keycloak.keys.KeyProvider", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	var components []keycloakComponent
	if err := json.NewDecoder(resp.Body).Decode(&components); err != nil {
		panic(err)
	}
	return components
}

func createComponent(realm, token string, component keycloakComponent) error {
	raw, _ := json.Marshal(component)
	req, _ := http.NewRequest(http.MethodPost, keycloakURL+"/admin/realms/"+realm+"/components", bytes.NewReader(raw))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("create component status=%d body=%s", resp.StatusCode, body)
	}
	return nil
}

func updateComponent(realm, token, id string, component keycloakComponent) error {
	raw, _ := json.Marshal(component)
	req, _ := http.NewRequest(http.MethodPut, keycloakURL+"/admin/realms/"+realm+"/components/"+id, bytes.NewReader(raw))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("update component status=%d body=%s", resp.StatusCode, body)
	}
	return nil
}

func waitForActiveKeyChange(realm, oldKid string, wait time.Duration) error {
	deadline := time.Now().Add(wait)
	for time.Now().Before(deadline) {
		resp, err := http.Get(keycloakURL + "/realms/" + realm + "/protocol/openid-connect/certs")
		if err == nil {
			var jwks struct {
				Keys []struct {
					Kid string `json:"kid"`
					Use string `json:"use"`
				} `json:"keys"`
			}
			decodeErr := json.NewDecoder(resp.Body).Decode(&jwks)
			_ = resp.Body.Close()
			if decodeErr == nil {
				for _, key := range jwks.Keys {
					if key.Use == "sig" && key.Kid != oldKid {
						return nil
					}
				}
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("JWKS did not expose a new signing key")
}
