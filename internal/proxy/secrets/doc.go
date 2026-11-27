// Package secrets defines the SecretProvider interface that agentsh
// uses to fetch real credentials from external secret stores at
// session start, plus the URI grammar, sentinel errors, and the
// provider Registry shared by all provider implementations.
//
// The Registry (registry.go) constructs providers in dependency
// order via topological sort, enabling auth chaining where one
// provider's bootstrap credentials come from another (e.g. Vault
// reads its token from the OS keyring).
//
// Provider implementations live in subpackages, one per backend:
//
//   - internal/proxy/secrets/keyring — OS keyring (Keychain / Secret
//     Service / Credential Manager) via github.com/zalando/go-keyring.
//   - internal/proxy/secrets/vault — HashiCorp Vault / OpenBao KV v2
//     via github.com/hashicorp/vault/api.
//
// Future plans add awssm, gcpsm, azurekv, and op subpackages.
// Every provider imports this package for the interface and types;
// this package imports none of them.
//
// Test doubles live in the sibling secretstest package. Production
// code must not import secretstest.
package secrets
