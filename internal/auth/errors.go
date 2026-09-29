package auth

import "errors"

type ErrorCode string

const (
	ErrorInvalidRequest       ErrorCode = "invalid_request"
	ErrorAuthenticationFailed ErrorCode = "authentication_failed"
	ErrorTenantUnauthorized   ErrorCode = "tenant_unauthorized"
	ErrorBindingConflict      ErrorCode = "binding_conflict"
	ErrorIdentityRequired     ErrorCode = "identity_required"
)

type APIError struct {
	Code    ErrorCode `json:"code"`
	Message string    `json:"message"`
	Status  int       `json:"status"`
}

func (e *APIError) Error() string { return e.Message }

func NewAPIError(status int, code ErrorCode, message string) *APIError {
	return &APIError{Status: status, Code: code, Message: message}
}

func AsAPIError(err error) *APIError {
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		return apiErr
	}
	return NewAPIError(500, ErrorInvalidRequest, "internal error")
}
