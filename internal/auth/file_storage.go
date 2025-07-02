package auth

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// TokenInfo represents stored authentication information
type TokenInfo struct {
	Type         string `json:"type"`          // "oauth" or "api"
	RefreshToken string `json:"refresh,omitempty"`
	AccessToken  string `json:"access,omitempty"`
	ExpiresAt    int64  `json:"expires,omitempty"`
	APIKey       string `json:"key,omitempty"`
}

// legacy format for backward compatibility
type legacy struct {
	Version int    `json:"version"`
	Access  string `json:"access_token"`
	Refresh string `json:"refresh_token"`
	Expires int64  `json:"expires"`
}

// nested format matches: {"anthropic":{"type":"oauth","access":"…","refresh":"…","expires":…}}
type nested struct {
	Anthropic struct {
		Type    string `json:"type"`
		Access  string `json:"access"`
		Refresh string `json:"refresh"`
		Expires int64  `json:"expires"`
	} `json:"anthropic"`
}

// IsExpired checks if the token is expired
func (t *TokenInfo) IsExpired() bool {
	if t.Type != "oauth" || t.ExpiresAt == 0 {
		return false
	}
	return time.Now().Unix() >= t.ExpiresAt
}

// NeedsRefresh checks if the token needs refresh (5 minutes before expiry)
func (t *TokenInfo) NeedsRefresh() bool {
	if t.Type != "oauth" || t.ExpiresAt == 0 {
		return false
	}
	return time.Now().Unix() >= (t.ExpiresAt - 300) // 5 minutes buffer
}

// FileStorage implements StorageBackend using JSON file storage
type FileStorage struct {
	path    string
	mu      sync.RWMutex
	metrics StorageMetrics
}

// NewFileStorage creates a new file-based storage backend
func NewFileStorage(path string) *FileStorage {
	return &FileStorage{
		path: path,
		metrics: StorageMetrics{
			Operations: make(map[string]int64),
			Errors:     make(map[string]int64),
			Latencies:  make(map[string]time.Duration),
		},
	}
}

// Get retrieves token information for a provider
func (s *FileStorage) Get(provider string) (*TokenInfo, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	
	start := time.Now()
	s.recordOperation("get")
	
	data, err := s.loadData()
	if err != nil {
		s.recordError("get", err)
		return nil, err
	}
	
	if tokenData, exists := data[provider]; exists {
		var token TokenInfo
		// Re-marshal and unmarshal to convert map to struct
		jsonData, err := json.Marshal(tokenData)
		if err != nil {
			s.recordError("get_marshal", err)
			return nil, fmt.Errorf("failed to marshal token data: %w", err)
		}
		if err := json.Unmarshal(jsonData, &token); err != nil {
			s.recordError("get_unmarshal", err)
			return nil, fmt.Errorf("failed to unmarshal token data: %w", err)
		}
		s.recordLatency("get", time.Since(start))
		return &token, nil
	}
	
	s.recordLatency("get", time.Since(start))
	return nil, nil
}

// Set stores token information for a provider
func (s *FileStorage) Set(provider string, token *TokenInfo) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	start := time.Now()
	s.recordOperation("set")
	
	// Ensure directory exists
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		s.recordError("set_mkdir", err)
		return fmt.Errorf("failed to create directory: %w", err)
	}
	
	data, err := s.loadData()
	if err != nil {
		s.recordError("set_load", err)
		return err
	}
	
	data[provider] = token
	
	// Write data to file
	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		s.recordError("set_marshal", err)
		return fmt.Errorf("failed to marshal data: %w", err)
	}
	
	if err := os.WriteFile(s.path, jsonData, 0600); err != nil {
		s.recordError("set_write", err)
		return fmt.Errorf("failed to write file: %w", err)
	}
	
	s.recordLatency("set", time.Since(start))
	return nil
}

// Remove deletes token information for a provider
func (s *FileStorage) Remove(provider string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	
	start := time.Now()
	s.recordOperation("remove")
	
	data, err := s.loadData()
	if err != nil {
		s.recordError("remove_load", err)
		return err
	}
	
	delete(data, provider)
	
	if len(data) == 0 {
		// Remove file if no data left
		err := os.Remove(s.path)
		if err != nil && !os.IsNotExist(err) {
			s.recordError("remove_file", err)
			return err
		}
		s.recordLatency("remove", time.Since(start))
		return nil
	}
	
	// Write updated data
	jsonData, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		s.recordError("remove_marshal", err)
		return fmt.Errorf("failed to marshal data: %w", err)
	}
	
	if err := os.WriteFile(s.path, jsonData, 0600); err != nil {
		s.recordError("remove_write", err)
		return fmt.Errorf("failed to write file: %w", err)
	}
	
	s.recordLatency("remove", time.Since(start))
	return nil
}

// List returns all stored provider names
func (s *FileStorage) List() ([]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	
	start := time.Now()
	s.recordOperation("list")
	
	data, err := s.loadData()
	if err != nil {
		s.recordError("list", err)
		return nil, err
	}
	
	providers := make([]string, 0, len(data))
	for provider := range data {
		providers = append(providers, provider)
	}
	
	s.recordLatency("list", time.Since(start))
	log.Printf("[DEBUG] List() collected %d tokens", len(providers))
	return providers, nil
}

// IsAvailable checks if the backend is available on this system
func (s *FileStorage) IsAvailable() bool {
	// File storage is always available
	return true
}

// RequiresUnlock checks if the backend needs to be unlocked
func (s *FileStorage) RequiresUnlock() bool {
	// File storage doesn't require unlock
	return false
}

// Unlock attempts to unlock the backend
func (s *FileStorage) Unlock() error {
	// No-op for file storage
	return nil
}

// Lock locks the backend
func (s *FileStorage) Lock() error {
	// No-op for file storage
	return nil
}

// Name returns the backend name for identification
func (s *FileStorage) Name() string {
	return "file:" + s.path
}

// loadData loads the stored data from file with dual format support
func (s *FileStorage) loadData() (map[string]interface{}, error) {
	data := make(map[string]interface{})
	
	fileData, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return data, nil
		}
		return nil, fmt.Errorf("failed to read file: %w", err)
	}
	
	if len(fileData) == 0 {
		return data, nil
	}
	
	// Try to unmarshal as existing internal format first (map[string]*TokenInfo)
	if err := json.Unmarshal(fileData, &data); err == nil {
		// Check if this is already in the expected internal format
		// Expected: {"anthropic": {"type":"oauth", "access":"...", ...}}
		if anthropicData, exists := data["anthropic"]; exists {
			// Try to convert to TokenInfo struct
			jsonData, err := json.Marshal(anthropicData)
			if err == nil {
				var token TokenInfo
				if json.Unmarshal(jsonData, &token) == nil && token.AccessToken != "" {
					// Already in correct internal format
					log.Printf("[DEBUG] branch-1 → SUCCESS ↪ %#v", token)
					return data, nil
				}
				log.Printf("[DEBUG] branch-1 → FAIL unmarshal or empty AccessToken ↪ %#v", token)
			} else {
				log.Printf("[DEBUG] branch-1 → FAIL marshal anthropicData ↪ err=%v", err)
			}
		}
	}
	
	// Try legacy format: {"version":1,"access_token":"...","refresh_token":"...","expires":...}
	var v1 legacy
	if json.Unmarshal(fileData, &v1) == nil && v1.Access != "" {
		// Convert to new format
		token := &TokenInfo{
			Type:         "oauth",
			AccessToken:  v1.Access,
			RefreshToken: v1.Refresh,
			ExpiresAt:    v1.Expires,
		}
		data["anthropic"] = token
		log.Printf("[DEBUG] branch-2 → SUCCESS ↪ %#v", token)
		return data, nil
	}
	log.Printf("[DEBUG] branch-2 → FAIL unmarshal or empty Access ↪ %#v", v1)
	
	// Try nested format: {"anthropic":{"type":"oauth","access":"...","refresh":"...","expires":...}}
	var v2 nested
	if json.Unmarshal(fileData, &v2) == nil && v2.Anthropic.Type == "oauth" {
		// Convert to internal format
		token := &TokenInfo{
			Type:         "oauth",
			AccessToken:  v2.Anthropic.Access,
			RefreshToken: v2.Anthropic.Refresh,
			ExpiresAt:    v2.Anthropic.Expires,
		}
		data["anthropic"] = token
		log.Printf("[DEBUG] branch-3 → SUCCESS ↪ %#v", token)
		return data, nil
	}
	log.Printf("[DEBUG] branch-3 → FAIL unmarshal or type != oauth ↪ %#v", v2)
	
	// If all parsing fails, return error
	finalErr := fmt.Errorf("unsupported auth file format")
	log.Printf("[DEBUG] nested-parse error: %v", finalErr)
	return nil, finalErr
}

// Metrics tracking methods
func (s *FileStorage) recordOperation(op string) {
	s.metrics.Operations[op]++
	s.metrics.LastAccess = time.Now()
}

func (s *FileStorage) recordError(op string, err error) {
	s.metrics.Errors[op]++
	s.metrics.LastError = err
}

func (s *FileStorage) recordLatency(op string, duration time.Duration) {
	s.metrics.Latencies[op] = duration
}

