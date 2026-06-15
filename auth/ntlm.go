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
	// Accept LM:NT format (impacket/hashcat output) — extract NT hash.
	ntHash := n.Hash
	if strings.Contains(ntHash, ":") {
		parts := strings.SplitN(ntHash, ":", 2)
		ntHash = parts[1]
	}
	if _, err := hex.DecodeString(ntHash); err != nil {
		return nil, fmt.Errorf("hash NTLM inválido: %v", err)
	}

	return &Credentials{
		Username: n.Username,
		Domain:   n.Domain,
		Hash:     ntHash,
		Method:   "NTLM",
		HashType: "NT",
	}, nil
}

// GetName returns the name of the authentication method
func (n *NTLMAuth) GetName() string {
	return "NTLM"
}

// GenerateNTHash generates an NT hash from a password (MD4 of UTF-16LE).
func GenerateNTHash(password string) (string, error) {
	// Full Unicode UTF-16LE: handle BMP and supplementary planes (surrogate pairs).
	var buf []byte
	for _, r := range password {
		if r >= 0x10000 {
			r -= 0x10000
			high := uint16(0xD800 + (r >> 10))
			low := uint16(0xDC00 + (r & 0x3FF))
			buf = append(buf, byte(high), byte(high>>8), byte(low), byte(low>>8))
		} else {
			buf = append(buf, byte(r), byte(r>>8))
		}
	}
	h := md4.New()
	h.Write(buf)
	return hex.EncodeToString(h.Sum(nil)), nil
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
