package api

import (
	"fmt"
	"net/http"
	"os"

	"github.com/agentsh/agentsh/internal/policy"
	"github.com/agentsh/agentsh/internal/policy/signing"
)

// policySigningError is a signing failure in enforce mode. status is the HTTP
// status to return for it.
type policySigningError struct {
	status int
	err    error
}

func (e *policySigningError) Error() string { return e.err.Error() }
func (e *policySigningError) Unwrap() error { return e.err }

// verifiedPolicyReader returns a policy.ReadFunc that checks the signature of
// each file it reads, including bases. In warn mode it calls warn and keeps
// the file.
func verifiedPolicyReader(mode, trustStorePath string, warn func(msg string)) policy.ReadFunc {
	var ts *signing.TrustStore
	var tsErr error
	tsLoaded := false
	return func(path string) ([]byte, error) {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read policy: %w", err)
		}
		if mode == "" || mode == "off" {
			return data, nil
		}
		enforce := mode == "enforce"
		if trustStorePath == "" {
			if enforce {
				return nil, &policySigningError{
					status: http.StatusInternalServerError,
					err:    fmt.Errorf("signing mode is enforce but trust_store not configured"),
				}
			}
			warn(fmt.Sprintf("signing mode is %q but trust_store not configured", mode))
			return data, nil
		}
		if !tsLoaded {
			ts, tsErr = signing.LoadTrustStore(trustStorePath, enforce)
			tsLoaded = true
		}
		if tsErr != nil {
			if enforce {
				return nil, &policySigningError{
					status: http.StatusInternalServerError,
					err:    fmt.Errorf("load trust store: %w", tsErr),
				}
			}
			warn(fmt.Sprintf("failed to load trust store: %v", tsErr))
			return data, nil
		}
		if _, err := signing.VerifyPolicyBytes(data, path+".sig", ts); err != nil {
			if enforce {
				return nil, &policySigningError{
					status: http.StatusForbidden,
					err:    fmt.Errorf("policy signing: %w", err),
				}
			}
			warn(fmt.Sprintf("policy signing verification failed for %s: %v", path, err))
		}
		return data, nil
	}
}

// stderrWarning prints a policy loading warning to stderr.
func stderrWarning(msg string) {
	fmt.Fprintf(os.Stderr, "WARNING: %s\n", msg)
}
