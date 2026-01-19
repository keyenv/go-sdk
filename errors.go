package keyenv

import "fmt"

// Error represents an error returned by the KeyEnv API.
type Error struct {
	// Status is the HTTP status code.
	Status int `json:"status"`

	// Message is the error message.
	Message string `json:"message"`

	// Code is an optional error code for programmatic handling.
	Code string `json:"code,omitempty"`
}

// Error implements the error interface.
func (e *Error) Error() string {
	if e.Code != "" {
		return fmt.Sprintf("keyenv: %s (status=%d, code=%s)", e.Message, e.Status, e.Code)
	}
	return fmt.Sprintf("keyenv: %s (status=%d)", e.Message, e.Status)
}

// IsNotFound returns true if the error is a 404 Not Found error.
func (e *Error) IsNotFound() bool {
	return e.Status == 404
}

// IsUnauthorized returns true if the error is a 401 Unauthorized error.
func (e *Error) IsUnauthorized() bool {
	return e.Status == 401
}

// IsForbidden returns true if the error is a 403 Forbidden error.
func (e *Error) IsForbidden() bool {
	return e.Status == 403
}

// IsConflict returns true if the error is a 409 Conflict error.
func (e *Error) IsConflict() bool {
	return e.Status == 409
}

// IsRateLimited returns true if the error is a 429 Too Many Requests error.
func (e *Error) IsRateLimited() bool {
	return e.Status == 429
}

// IsServerError returns true if the error is a 5xx server error.
func (e *Error) IsServerError() bool {
	return e.Status >= 500 && e.Status < 600
}

// Common error variables for sentinel error checking.
var (
	ErrUnauthorized = &Error{Status: 401, Message: "Unauthorized"}
	ErrForbidden    = &Error{Status: 403, Message: "Forbidden"}
	ErrNotFound     = &Error{Status: 404, Message: "Not found"}
	ErrConflict     = &Error{Status: 409, Message: "Conflict"}
	ErrRateLimited  = &Error{Status: 429, Message: "Rate limited"}
)
