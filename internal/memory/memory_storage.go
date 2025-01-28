package memory

import (
	"sync"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"
)

type MemoryStore struct {
	mu       sync.RWMutex
	sessions map[string]*webauthn.SessionData
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		sessions: make(map[string]*webauthn.SessionData),
	}
}

func (m *MemoryStore) SaveSession(userID uuid.UUID, sessionData *webauthn.SessionData) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions[userID.String()] = sessionData
}

func (m *MemoryStore) GetSession(userID uuid.UUID) (*webauthn.SessionData, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	sessionData, exists := m.sessions[userID.String()]
	return sessionData, exists
}

func (m *MemoryStore) DeleteSession(userID uuid.UUID) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sessions, userID.String())
}
