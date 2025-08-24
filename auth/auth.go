// Package auth provides authentication methods for NullFang
package auth

import (
	"errors"
	"fmt"
	"strings"

	"github.com/m0ng3sh3ll/NullFang/logger"
)

// Common errors
var (
	ErrInvalidHash          = errors.New("invalid hash format")
	ErrAuthenticationFailed = errors.New("authentication failed")
	ErrUnsupportedMethod    = errors.New("unsupported authentication method")
	ErrMissingCredentials   = errors.New("missing required credentials")
)

// AuthType representa os tipos de autenticação suportados
type AuthType string

const (
	AuthTypeNTLM     AuthType = "NTLM"
	AuthTypeKerberos AuthType = "Kerberos"
)

// AuthMethod é a interface que todos os métodos de autenticação devem implementar
type AuthMethod interface {
	// GetCredentials retorna as credenciais formatadas para o método específico
	GetCredentials() (*Credentials, error)
	// GetName retorna o nome do método de autenticação
	GetName() string
}

// Credentials contém as informações de autenticação
type Credentials struct {
	Username   string
	Password   string
	Domain     string
	Hash       string
	Ticket     []byte
	Method     string
	HashType   string
	SessionKey []byte
}

// Option represents an option for authentication methods
type Option func(interface{})

// WithDebug enables debug logging
func WithDebug(debug bool) Option {
	return func(a interface{}) {
		if auth, ok := a.(interface{ setDebug(bool) }); ok {
			auth.setDebug(debug)
		}
	}
}

// WithServer sets the authentication server
func WithServer(server string) Option {
	return func(a interface{}) {
		if auth, ok := a.(interface{ setServer(string) }); ok {
			auth.setServer(server)
		}
	}
}

// WithPort sets the authentication server port
func WithPort(port int) Option {
	return func(a interface{}) {
		if auth, ok := a.(interface{ setPort(int) }); ok {
			auth.setPort(port)
		}
	}
}

// baseAuth contains common fields for all authentication methods
type baseAuth struct {
	debug  bool
	server string
	port   int
}

func (b *baseAuth) setDebug(debug bool) {
	b.debug = debug
}

func (b *baseAuth) setServer(server string) {
	b.server = server
}

func (b *baseAuth) setPort(port int) {
	b.port = port
}

// debugLog logs a message if debug is enabled
func (b *baseAuth) debugLog(format string, args ...interface{}) {
	if b.debug {
		fmt.Printf("[DEBUG] "+format+"\n", args...)
	}
}

// NewAuthMethod creates a new authentication method
func NewAuthMethod(authType AuthType, params map[string]string) (AuthMethod, error) {
	switch authType {
	case AuthTypeNTLM:
		if hash, ok := params["hash"]; ok {
			// Validate NTLM hash format
			if !isValidNTLMHash(hash) {
				logger.Error("Invalid NTLM hash format: %s", hash)
				return nil, fmt.Errorf("invalid NTLM hash format")
			}
			return NewNTLMAuth(params)
		}
		return nil, fmt.Errorf("NTLM hash is required")

	case AuthTypeKerberos:
		if ticketPath, ok := params["ticket_path"]; ok {
			return NewKerberosAuth(params["domain"], params["username"], WithTicketFile(ticketPath)), nil
		}
		return NewKerberosAuth(params["domain"], params["username"]), nil

	default:
		logger.Error("Unsupported authentication type: %v", authType)
		return nil, fmt.Errorf("unsupported authentication type")
	}
}

// isValidNTLMHash validates the format of an NTLM hash
func isValidNTLMHash(hash string) bool {
	// Check if it's just an NT hash (32 characters)
	if len(hash) == 32 && isHexString(hash) {
		return true
	}

	// Check if it's a full LM:NT hash
	parts := strings.Split(hash, ":")
	if len(parts) == 2 {
		lmHash := parts[0]
		ntHash := parts[1]
		return (len(lmHash) == 32 && isHexString(lmHash)) &&
			(len(ntHash) == 32 && isHexString(ntHash))
	}

	return false
}

// isHexString checks if a string contains only hexadecimal characters
func isHexString(s string) bool {
	for _, c := range s {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// ParseHashString parses a hash string in various formats
func ParseHashString(hashStr string) (string, string, string, error) {
	// Format: username::domain:hash
	if strings.Count(hashStr, ":") >= 3 {
		parts := strings.SplitN(hashStr, ":", 4)
		if len(parts) < 4 {
			return "", "", "", fmt.Errorf("%w: invalid hash format", ErrInvalidHash)
		}
		username := parts[0]
		domain := parts[2]
		hash := parts[3]
		return username, domain, hash, nil
	}

	// Format: username:domain:hash
	if strings.Count(hashStr, ":") == 2 {
		parts := strings.SplitN(hashStr, ":", 3)
		username := parts[0]
		domain := parts[1]
		hash := parts[2]
		return username, domain, hash, nil
	}

	// Format: LM:NT
	if strings.Count(hashStr, ":") == 1 {
		// This is just a hash, not a username:domain:hash format
		return "", "", hashStr, nil
	}

	// Format: just the hash
	return "", "", hashStr, nil
}
