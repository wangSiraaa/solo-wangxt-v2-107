package auth

import "time"

type ClientConfig struct {
	TenantID     string
	Issuer       string
	ClientID     string
	ClientSecret string
	RedirectURIs []string
	Enabled      bool
}

type VerifiedIdentity struct {
	TenantID      string
	Issuer        string
	Subject       string
	Email         string
	EmailVerified bool
	AuthTime      *time.Time
}

type SessionInfo struct {
	ID       string
	TenantID string
	MemberID string
	Issuer   string
	Subject  string
}

type LinkIdentity struct {
	Leg           int
	Issuer        string
	Subject       string
	Email         string
	EmailVerified bool
	AuthTime      *time.Time
}
