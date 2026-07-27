package api

import (
	"encoding/json"
	"errors"
	"net/http"
)

func decodeJSON(w http.ResponseWriter, r *http.Request, dst any, invalidMsg string) bool {
	if invalidMsg == "" {
		invalidMsg = "invalid json"
	}
	if err := json.NewDecoder(r.Body).Decode(dst); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			writeToolDomainError(w, http.StatusRequestEntityTooLarge, toolErrorInvalidRequest, "request body too large", "", err)
			return false
		}
		writeToolDomainError(w, http.StatusBadRequest, toolErrorInvalidRequest, invalidMsg, "", err)
		return false
	}
	return true
}
