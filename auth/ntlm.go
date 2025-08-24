package auth

import (
	"encoding/hex"
	"fmt"
	"strings"

	"golang.org/x/crypto/md4"
)

// NTLMAuth implements NTLM hash authentication
type NTLMAuth struct {
	Username string
	Hash     string
	Domain   string
	LMHash   string
	NTHash   string
}

// NewNTLMAuth creates a new NTLM hash authenticator
func NewNTLMAuth(params map[string]string) (*NTLMAuth, error) {
	auth := &NTLMAuth{}

	if hash, ok := params["hash"]; ok {
		username, domain, hashValue, err := ParseHashString(hash)
		if err != nil {
			return nil, fmt.Errorf("invalid NTLM hash: %v", err)
		}
		auth.Username = username
		auth.Domain = domain
		auth.Hash = hashValue
	}

	// Set username and domain if not set by hash parsing
	if username, ok := params["username"]; ok && auth.Username == "" {
		auth.Username = username
	}
	if domain, ok := params["domain"]; ok && auth.Domain == "" {
		auth.Domain = domain
	}

	return auth, nil
}

// GetCredentials returns the credentials formatted for the specific method
func (n *NTLMAuth) GetCredentials() (*Credentials, error) {
	// Verifica se o hash está em formato hexadecimal válido
	if _, err := hex.DecodeString(n.Hash); err != nil {
		return nil, fmt.Errorf("hash NTLM inválido: %v", err)
	}

	return &Credentials{
		Username: n.Username,
		Domain:   n.Domain,
		Hash:     n.Hash,
		Method:   "NTLM",
		HashType: "NT",
	}, nil
}

// GetName returns the name of the authentication method
func (n *NTLMAuth) GetName() string {
	return "NTLM"
}

// GenerateNTHash generates an NT hash from a password
func GenerateNTHash(password string) (string, error) {
	// Convert password to UTF-16LE bytes
	utf16Password := []byte{}
	for _, r := range password {
		utf16Password = append(utf16Password, byte(r), 0)
	}

	// Calculate MD4 hash
	h := md4.New()
	h.Write(utf16Password)
	ntHash := h.Sum(nil)

	// Convert to hex string
	return hex.EncodeToString(ntHash), nil
}

// ValidateNTLMHash validates an NTLM hash format
func ValidateNTLMHash(hash string) (string, string, error) {
	// Check if hash is in LM:NT format
	if strings.Contains(hash, ":") {
		parts := strings.Split(hash, ":")
		if len(parts) != 2 {
			return "", "", ErrInvalidHash
		}

		// Validate both parts are valid hex
		if _, err := hex.DecodeString(parts[0]); err != nil {
			return "", "", fmt.Errorf("%w: invalid LM hash", ErrInvalidHash)
		}

		if _, err := hex.DecodeString(parts[1]); err != nil {
			return "", "", fmt.Errorf("%w: invalid NT hash", ErrInvalidHash)
		}

		return parts[0], parts[1], nil
	}

	// NT hash only
	if _, err := hex.DecodeString(hash); err != nil {
		return "", "", fmt.Errorf("%w: invalid NT hash", ErrInvalidHash)
	}

	return "", hash, nil
}
