package credential

import (
	"errors"
	"fmt"
	"sync"
)

// Credential represents a user's authentication credentials
type Credential struct {
	Username string
	APIKey   string
}

// CredentialStore manages credentials in a thread-safe manner
type CredentialStore struct {
	credentials map[string]Credential
	mu          sync.RWMutex
}

// NewCredentialStore initializes a new CredentialStore
func NewCredentialStore() *CredentialStore {
	return &CredentialStore{
		credentials: make(map[string]Credential),
	}
}

// AddCredential adds a new credential to the store
func (s *CredentialStore) AddCredential(username, apiKey string) error {
	if username == "" || apiKey == "" {
		return errors.New("username and API key cannot be empty")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.credentials[username] = Credential{
		Username: username,
		APIKey:   apiKey,
	}
	return nil
}

// GetCredential retrieves a credential by username
func (s *CredentialStore) GetCredential(username string) (Credential, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	cred, exists := s.credentials[username]
	if !exists {
		return Credential{}, errors.New("credential not found")
	}
	return cred, nil
}

// DeleteCredential removes a credential by username
func (s *CredentialStore) DeleteCredential(username string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.credentials[username]; !exists {
		return errors.New("credential not found")
	}
	delete(s.credentials, username)
	return nil
}

// CredentialProcess prints a message indicating the credential process is running
func CredentialProcess() {
	fmt.Println("Running the credential process!")
}
