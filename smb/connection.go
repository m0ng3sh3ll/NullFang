package smb

import (
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/m0ng3sh3ll/NullFang/auth"
	"github.com/m0ng3sh3ll/NullFang/go-smb2-patch"
	"github.com/m0ng3sh3ll/NullFang/logger"
)

// SMBConfig holds the configuration for SMB connections
type SMBConfig struct {
	Host     string
	Port     int
	Domain   string
	Username string
	Password string
	Timeout  time.Duration

	// Novos campos para compatibilidade
	Dialect uint16 // Dialeto SMB a ser forçado
	Signing *bool  // Se deve forçar signing obrigatório

	// New authentication fields
	AuthMethod auth.AuthMethod
	NTLMHash   string
	UseNTLM    bool
}

// SMBConnection represents an SMB connection
type SMBConnection struct {
	Config        *SMBConfig
	Connection    *smb2.Session
	IsConnected   bool
	stopKeepAlive chan struct{}
}

// NewSMBConnection creates a new SMB connection
func NewSMBConnection(config *SMBConfig) *SMBConnection {
	return &SMBConnection{
		Config:      config,
		IsConnected: false,
	}
}

// validateConfig validates and sets default values for SMBConfig
func validateConfig(config *SMBConfig) error {
	if config.Host == "" {
		return fmt.Errorf("host is required")
	}

	if config.Port == 0 {
		config.Port = 445 // Default SMB port
	}

	if config.Timeout == 0 {
		config.Timeout = 10 * time.Second
	}

	return nil
}

// Connect establishes a connection to the SMB server
func (c *SMBConnection) Connect() error {
	// Validate configuration
	if err := validateConfig(c.Config); err != nil {
		return err
	}

	addr := fmt.Sprintf("%s:%d", c.Config.Host, c.Config.Port)

	timeout := c.Config.Timeout
	if timeout == 0 {
		timeout = 10 * time.Second // valor padrão
	}

	dialer := net.Dialer{
		Timeout:   timeout,
		KeepAlive: 30 * time.Second,
	}

	conn, err := dialer.Dial("tcp", addr)
	if err != nil {
		return fmt.Errorf("Failed to connect: host %s without SMB", c.Config.Host)
	}

	var d *smb2.Dialer

	// If an auth method is provided, use it
	if c.Config.AuthMethod != nil {
		credentials, err := c.Config.AuthMethod.GetCredentials()
		if err != nil {
			return fmt.Errorf("authentication failed: %v", err)
		}

		// Create the appropriate dialer based on the authentication method
		switch credentials.HashType {
		case "NTLM", "NT", "LM:NT":
			// NTLM hash authentication
			hashBytes, err := hex.DecodeString(credentials.Hash)
			if err != nil {
				return fmt.Errorf("invalid NTLM hash format: %v", err)
			}
			d = &smb2.Dialer{
				Initiator: &smb2.NTLMInitiator{
					Domain:   credentials.Domain,
					User:     credentials.Username,
					Password: "",
					Hash:     hashBytes,
				},
			}
		case "Kerberos":
			// Kerberos authentication
			if credentials.Ticket != nil {
				// Use Kerberos ticket
				d = &smb2.Dialer{
					// Note: The go-smb2 library doesn't directly support Kerberos tickets
					// This is a placeholder for future implementation
					Initiator: &smb2.NTLMInitiator{
						Domain:   credentials.Domain,
						User:     credentials.Username,
						Password: credentials.Password,
					},
				}
			} else {
				// Fall back to password authentication
				d = &smb2.Dialer{
					Initiator: &smb2.NTLMInitiator{
						Domain:   credentials.Domain,
						User:     credentials.Username,
						Password: credentials.Password,
					},
				}
			}
		case "MSCHAPv1", "MSCHAPv2", "NETNTLMv2":
			// NetNTLMv2 authentication
			responseBytes, err := hex.DecodeString(credentials.Hash)
			if err != nil {
				return fmt.Errorf("invalid NetNTLMv2 response format: %v", err)
			}
			d = &smb2.Dialer{
				Initiator: &smb2.NTLMInitiator{
					Domain:   credentials.Domain,
					User:     credentials.Username,
					Password: "",
					Hash:     responseBytes, // Usando os bytes decodificados do response
				},
			}
		default:
			// Unknown authentication method, fall back to password
			d = &smb2.Dialer{
				Initiator: &smb2.NTLMInitiator{
					Domain:   credentials.Domain,
					User:     credentials.Username,
					Password: credentials.Password,
				},
			}
		}

		if c.Config.Dialect != 0 {
			d.Negotiator.SpecifiedDialect = c.Config.Dialect
		} else {
			d.Negotiator.SpecifiedDialect = 0x0311 // SMB311 por padrão
		}
		if c.Config.Signing != nil {
			d.Negotiator.RequireMessageSigning = *c.Config.Signing
		} else {
			d.Negotiator.RequireMessageSigning = true // signing obrigatório por padrão
		}
	} else if c.Config.UseNTLM && c.Config.NTLMHash != "" {
		// Legacy support for simple NTLM hash authentication
		d = &smb2.Dialer{
			Initiator: &smb2.NTLMInitiator{
				Domain:   c.Config.Domain,
				User:     c.Config.Username,
				Password: "",
				Hash:     []byte(c.Config.NTLMHash),
			},
		}
		if c.Config.Dialect != 0 {
			d.Negotiator.SpecifiedDialect = c.Config.Dialect
		} else {
			d.Negotiator.SpecifiedDialect = 0x0311
		}
		if c.Config.Signing != nil {
			d.Negotiator.RequireMessageSigning = *c.Config.Signing
		} else {
			d.Negotiator.RequireMessageSigning = true
		}
	} else {
		// Default to username/password authentication
		d = &smb2.Dialer{
			Initiator: &smb2.NTLMInitiator{
				Domain:   c.Config.Domain,
				User:     c.Config.Username,
				Password: c.Config.Password,
			},
		}
		if c.Config.Dialect != 0 {
			d.Negotiator.SpecifiedDialect = c.Config.Dialect
		} else {
			d.Negotiator.SpecifiedDialect = 0x0311
		}
		if c.Config.Signing != nil {
			d.Negotiator.RequireMessageSigning = *c.Config.Signing
		} else {
			d.Negotiator.RequireMessageSigning = true
		}
	}

	session, err := d.Dial(conn)
	if err != nil {
		return fmt.Errorf("SMB authentication failed: %v", err)
	}

	c.stopKeepAlive = make(chan struct{})
	c.Connection = session
	c.IsConnected = true

	// Iniciar keep-alive para manter conexão ativa
	go c.keepAlive()

	return nil
}

// Disconnect closes the SMB connection
func (c *SMBConnection) Disconnect() {
	if c.IsConnected && c.Connection != nil {
		// Parar keep-alive antes de desconectar
		if c.stopKeepAlive != nil {
			close(c.stopKeepAlive)
			c.stopKeepAlive = nil // Evitar double-close
		}

		// Logoff fecha a sessão SMB (o que automaticamente desmonta todos os shares)
		c.Connection.Logoff()
		c.IsConnected = false
	}
}

// ListShares lists available shares on the SMB server
func (c *SMBConnection) ListShares() ([]string, error) {
	if !c.IsConnected {
		return nil, fmt.Errorf("not connected")
	}

	shares, err := c.Connection.ListSharenames()
	if err != nil {
		logger.Error("Failed to list shares: %v", err)
		return nil, err
	}

	return shares, nil
}

// IsShareReadable checks if a share is readable
func (c *SMBConnection) IsShareReadable(shareName string) (bool, error) {
	if !c.IsConnected {
		return false, fmt.Errorf("not connected")
	}

	share, err := c.Connection.Mount(shareName)
	if err != nil {
		return false, err
	}
	defer share.Umount()

	_, err = share.ReadDir(".")
	if err != nil {
		return false, err
	}

	return true, nil
}

// MountShare mounts a share and returns a file system object
func (c *SMBConnection) MountShare(shareName string) (*smb2.Share, error) {
	if !c.IsConnected {
		return nil, fmt.Errorf("not connected")
	}

	share, err := c.Connection.Mount(shareName)
	if err != nil {
		logger.Debug("Failed to mount share %s: %v", shareName, err)
		return nil, err
	}

	return share, nil
}

// CopyFile copies a file from the SMB share to the local file system
func (c *SMBConnection) CopyFile(share *smb2.Share, remotePath, localPath string) (int64, error) {
	// Create the directory structure if it doesn't exist
	err := os.MkdirAll(filepath.Dir(localPath), 0755)
	if err != nil {
		return 0, fmt.Errorf("failed to create directory: %v", err)
	}

	// Open the remote file
	remoteFile, err := share.Open(remotePath)
	if err != nil {
		return 0, fmt.Errorf("failed to open remote file: %v", err)
	}
	defer remoteFile.Close()

	// Create the local file
	localFile, err := os.Create(localPath)
	if err != nil {
		return 0, fmt.Errorf("failed to create local file: %v", err)
	}
	defer localFile.Close()

	// Copy the file content
	written, err := remoteFile.WriteTo(localFile)
	if err != nil {
		return written, fmt.Errorf("error copying file: %v", err)
	}

	return written, nil
}

// keepAlive mantém a conexão SMB ativa fazendo operações periódicas
func (c *SMBConnection) keepAlive() {
	ticker := time.NewTicker(20 * time.Second) // Ping a cada 20 segundos
	defer ticker.Stop()

	for {
		select {
		case <-c.stopKeepAlive:
			logger.Debug("[KEEP-ALIVE] Goroutine exiting for connection to %s", c.Config.Host)
			return
		case <-ticker.C:
			if !c.IsConnected || c.Connection == nil {
				return
			}

			// Fazer operação leve para manter conexão ativa
			_, err := c.Connection.ListSharenames()
			if err != nil {
				logger.Debug("[KEEP-ALIVE] Failed to ping server %s: %v", c.Config.Host, err)
				// Não fechar conexão, apenas logar
			} else {
				logger.Debug("[KEEP-ALIVE] Connection to %s refreshed successfully", c.Config.Host)
			}
		}
	}
}
