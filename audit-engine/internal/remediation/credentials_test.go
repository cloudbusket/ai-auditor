package remediation

import (
	"errors"
	"sync"
	"testing"
)

func TestMemoryCredentialStoreSetAndGet(t *testing.T) {
	store := NewMemoryCredentialStore()

	if err := store.Set("openai", "test-secret"); err != nil {
		t.Fatalf("Set returned error: %v", err)
	}

	got, err := store.Get("openai")
	if err != nil {
		t.Fatalf("Get returned error: %v", err)
	}

	if got != "test-secret" {
		t.Fatal("retrieved credential does not match")
	}
}

func TestMemoryCredentialStoreNormalizesProvider(t *testing.T) {
	store := NewMemoryCredentialStore()

	if err := store.Set(" OpenAI ", "test-secret"); err != nil {
		t.Fatalf("Set returned error: %v", err)
	}

	if !store.Has("openai") {
		t.Fatal("expected normalized provider credential to exist")
	}
}

func TestMemoryCredentialStoreRejectsUnsupportedProvider(t *testing.T) {
	store := NewMemoryCredentialStore()

	err := store.Set("unsupported", "test-secret")
	if !errors.Is(err, ErrInvalidProvider) {
		t.Fatalf("expected ErrInvalidProvider, got %v", err)
	}
}

func TestMemoryCredentialStoreRejectsEmptyKey(t *testing.T) {
	store := NewMemoryCredentialStore()

	err := store.Set("openai", "   ")
	if !errors.Is(err, ErrInvalidAPIKey) {
		t.Fatalf("expected ErrInvalidAPIKey, got %v", err)
	}
}

func TestMemoryCredentialStoreMissingCredential(t *testing.T) {
	store := NewMemoryCredentialStore()

	_, err := store.Get("openai")
	if !errors.Is(err, ErrCredentialNotSet) {
		t.Fatalf("expected ErrCredentialNotSet, got %v", err)
	}
}

func TestMemoryCredentialStoreReplaceCredential(t *testing.T) {
	store := NewMemoryCredentialStore()

	if err := store.Set("anthropic", "old-secret"); err != nil {
		t.Fatal(err)
	}

	if err := store.Set("anthropic", "new-secret"); err != nil {
		t.Fatal(err)
	}

	got, err := store.Get("anthropic")
	if err != nil {
		t.Fatal(err)
	}

	if got != "new-secret" {
		t.Fatal("credential replacement failed")
	}
}

func TestMemoryCredentialStoreDelete(t *testing.T) {
	store := NewMemoryCredentialStore()

	if err := store.Set("gemini", "test-secret"); err != nil {
		t.Fatal(err)
	}

	if err := store.Delete("gemini"); err != nil {
		t.Fatal(err)
	}

	if store.Has("gemini") {
		t.Fatal("credential should not exist after deletion")
	}

	_, err := store.Get("gemini")
	if !errors.Is(err, ErrCredentialNotSet) {
		t.Fatalf("expected ErrCredentialNotSet, got %v", err)
	}
}

func TestMemoryCredentialStoreConcurrentAccess(t *testing.T) {
	store := NewMemoryCredentialStore()

	var wg sync.WaitGroup

	for i := 0; i < 20; i++ {
		wg.Add(1)

		go func(i int) {
			defer wg.Done()

			if err := store.Set("openai", "secret"); err != nil {
				t.Errorf("Set failed: %v", err)
			}

			if _, err := store.Get("openai"); err != nil {
				t.Errorf("Get failed: %v", err)
			}

			store.Has("openai")
		}(i)
	}

	wg.Wait()
}
