package httpapi

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.example/multitenant-oidc/internal/auth"
)

type Server struct {
	service      *auth.Service
	baseURL      string
	cookieName     string
	cookieSecure bool
}

func NewServer(service *auth.Service, baseURL string, cookieSecure bool) *Server {
	return &Server{
		service:      service,
		baseURL:      strings.TrimRight(baseURL, "/"),
		cookieName:   cookieName(cookieSecure),
		cookieSecure: cookieSecure,
	}
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.health)
	mux.HandleFunc("POST /api/login/start", s.startLogin)
	mux.HandleFunc("GET /callback/login", s.callbackLogin)
	mux.HandleFunc("POST /api/links/start", s.startLink)
	mux.HandleFunc("GET /callback/link", s.callbackLink)
	mux.HandleFunc("GET /api/me", s.me)
	return loggingMiddleware(mux)
}

func (s *Server) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) startLogin(w http.ResponseWriter, r *http.Request) {
	var req auth.StartLoginRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	if req.RedirectURI == "" {
		req.RedirectURI = s.baseURL + "/callback/login"
	}
	result, err := s.service.StartLogin(r.Context(), req)
	writeServiceResult(w, err, result)
}

func (s *Server) startLink(w http.ResponseWriter, r *http.Request) {
	var req auth.StartLinkRequest
	if !decodeJSON(w, r, &req) {
		return
	}
	result, err := s.service.StartLink(r.Context(), req)
	writeServiceResult(w, err, result)
}

func (s *Server) callbackLogin(w http.ResponseWriter, r *http.Request) {
	result, err := s.service.Callback(r.Context(), r.URL.Path, r.URL.Query())
	if err == nil {
		s.setSessionCookie(w, result.Session)
	}
	writeServiceResult(w, err, result)
}

func (s *Server) callbackLink(w http.ResponseWriter, r *http.Request) {
	result, err := s.service.Callback(r.Context(), r.URL.Path, r.URL.Query())
	if err == nil && result.Status == "completed" {
		s.setSessionCookie(w, result.Session)
	}
	writeServiceResult(w, err, result)
}

func (s *Server) me(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie(s.cookieName)
	if errors.Is(err, http.ErrNoCookie) {
		writeAPIError(w, auth.NewAPIError(http.StatusUnauthorized, auth.ErrorAuthenticationFailed, "missing session"))
		return
	}
	if err != nil {
		writeAPIError(w, auth.NewAPIError(http.StatusBadRequest, auth.ErrorInvalidRequest, "invalid cookie"))
		return
	}
	info, err := s.service.Session(r.Context(), cookie.Value)
	if err != nil {
		writeServiceResult(w, err, nil)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"tenant_id": info.TenantID,
		"member_id": info.MemberID,
		"identity": map[string]string{
			"issuer":  info.Issuer,
			"subject": info.Subject,
		},
	})
}

func (s *Server) setSessionCookie(w http.ResponseWriter, token string) {
	if token == "" {
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     s.cookieName,
		Value:    token,
		Path:     "/",
		MaxAge:   8 * 60 * 60,
		HttpOnly: true,
		Secure:   s.cookieSecure,
		SameSite: http.SameSiteLaxMode,
	})
}

func cookieName(secure bool) string {
	if secure {
		return "__Host-oidc_session"
	}
	return "oidc_session"
}

func decodeJSON(w http.ResponseWriter, r *http.Request, target any) bool {
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		writeAPIError(w, auth.NewAPIError(http.StatusBadRequest, auth.ErrorInvalidRequest, "request body must be valid JSON"))
		return false
	}
	var extra struct{}
	if err := decoder.Decode(&extra); err != io.EOF {
		writeAPIError(w, auth.NewAPIError(http.StatusBadRequest, auth.ErrorInvalidRequest, "request body must contain one JSON object"))
		return false
	}
	return true
}

func writeServiceResult(w http.ResponseWriter, err error, result any) {
	if err != nil {
		writeServiceError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func writeServiceError(w http.ResponseWriter, err error) {
	var apiErr *auth.APIError
	if errors.As(err, &apiErr) {
		writeAPIError(w, apiErr)
		return
	}
	if errors.Is(err, pgx.ErrNoRows) {
		writeAPIError(w, auth.NewAPIError(http.StatusNotFound, auth.ErrorAuthenticationFailed, "resource not found"))
		return
	}
	writeAPIError(w, auth.NewAPIError(http.StatusInternalServerError, auth.ErrorInvalidRequest, "internal error"))
}

func writeAPIError(w http.ResponseWriter, err *auth.APIError) {
	writeJSON(w, err.Status, map[string]any{"error": map[string]string{
		"code":    string(err.Code),
		"message": err.Message,
	}})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(value); err != nil {
		return
	}
}

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Never log query strings: state/code may appear in callback requests and
		// providers may echo sensitive request data.
		log.Printf("%s %s", r.Method, r.URL.Path)
		next.ServeHTTP(w, r)
	})
}
