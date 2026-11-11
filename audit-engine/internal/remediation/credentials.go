package remediation

import (
	"errors"
	"strings"
	"sync"
)

var (
	ErrInvalidProvider  = errors.New("unsupported AI provider")
	ErrInvalidAPIKey    = errors.New("API key is required")
	ErrCredentialNotSet = errors.New("provider credential is not configured")
)

// CredentialStore defines server-side provider credential operations.
// The interface can later be implemented using encrypted KMS-backed storage.
type CredentialStore interface {
	Set(provider, apiKey string) error
	Get(provider string) (string, error)
	Delete(provider string) error
	Has(provider string) bool
}

// MemoryCredentialStore keeps API keys in process memory only.
// Credentials are lost when the process exits or restarts.
type MemoryCredentialStore struct {
	mu          sync.RWMutex
	credentials map[string]string
}

func NewMemoryCredentialStore() *MemoryCredentialStore {
	return &MemoryCredentialStore{
		credentials: make(map[string]string),
	}
}

func normalizeProvider(provider string) (string, error) {
	provider = strings.ToLower(strings.TrimSpace(provider))

	switch provider {
	case "openai", "anthropic", "gemini":
		return provider, nil
	default:
		return "", ErrInvalidProvider
	}
}

func (s *MemoryCredentialStore) Set(provider, apiKey string) error {
	if s == nil {
		return errors.New("credential store is nil")
	}

	provider, err := normalizeProvider(provider)
	if err != nil {
		return err
	}

	apiKey = strings.TrimSpace(apiKey)
	if apiKey == "" {
		return ErrInvalidAPIKey
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.credentials[provider] = apiKey
	return nil
}

func (s *MemoryCredentialStore) Get(provider string) (string, error) {
	if s == nil {
		return "", errors.New("credential store is nil")
	}

	provider, err := normalizeProvider(provider)
	if err != nil {
		return "", err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	apiKey, exists := s.credentials[provider]
	if !exists {
		return "", ErrCredentialNotSet
	}

	return apiKey, nil
}

func (s *MemoryCredentialStore) Delete(provider string) error {
	if s == nil {
		return errors.New("credential store is nil")
	}

	provider, err := normalizeProvider(provider)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.credentials, provider)
	return nil
}

func (s *MemoryCredentialStore) Has(provider string) bool {
	if s == nil {
		return false
	}

	provider, err := normalizeProvider(provider)
	if err != nil {
		return false
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	_, exists := s.credentials[provider]
	return exists
}
