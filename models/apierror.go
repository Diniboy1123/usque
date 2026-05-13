package models

// Known error codes from the API
const (
	InvalidPublicKey = 1001
)

type APIError struct {
	Success bool        `json:"success"`
	Errors  []ErrorInfo `json:"errors"`
}

type ErrorInfo struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// ErrorsAsString returns a string representation of the errors in the APIError.
// It concatenates the error messages into a single string, separated by semicolons.
//
// Parameters:
//   - separator: string - The string to use as a separator between error messages.
//
// Returns:
//   - string: A string containing all error messages, separated by the specified separator.
func (e *APIError) ErrorsAsString(separator string) string {
	var result string
	for _, err := range e.Errors {
		result += err.Message + separator
	}
	if len(result) > 0 {
		return result[:len(result)-len(separator)]
	}
	return result
}

// HasErrorCode checks if the APIError contains a specific error code.
// It returns true if the error code is found, otherwise false.
//
// Parameters:
//   - code: int - The error code to check for.
//
// Returns:
//   - bool: true if the error code is found, otherwise false.
func (e *APIError) HasErrorCode(code int) bool {
	for _, err := range e.Errors {
		if err.Code == code {
			return true
		}
	}
	return false
}

// Error returns a string representation of api errors.
//
// Returns:
//   - string: A string containing all error messages, separated by '; '.
func (e APIError) Error() string {
	return "API errors: " + e.ErrorsAsString("; ")
}
