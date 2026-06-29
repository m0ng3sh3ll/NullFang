package smb

import (
	"encoding/hex"
	"fmt"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/proxy"

	"github.com/m0ng3sh3ll/NullFang/auth"
	"github.com/m0ng3sh3ll/NullFang/go-smb2-patch"
	"github.com/m0ng3sh3ll/NullFang/logger"
)

// lockoutHalted is set to 1 atomically when the lockout guard fires.
// Any goroutine that reaches d.Dial() after this is set will abort before
// sending NTLM credentials, preventing further lockout increments.
var lockoutHalted int32

// HaltAuth signals all pending Connect() calls to abort before authentication.
func HaltAuth() { atomic.StoreInt32(&lockoutHalted, 1) }

// AuthHalted reports whether authentication has been halted.
func AuthHalted() bool { return atomic.LoadInt32(&lockoutHalted) != 0 }

// workstationName is generated once per process so all connections look like the same client machine.
var (
	workstationName     string
	workstationNameOnce sync.Once
)

func getWorkstationName() string {
	workstationNameOnce.Do(func() {
		prefixes := []string{"DESKTOP", "LAPTOP", "WIN10PC", "WS"}
		const chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
		suffix := make([]byte, 7)
		for i := range suffix {
			suffix[i] = chars[rand.Intn(len(chars))]
		}
		workstationName = prefixes[rand.Intn(len(prefixes))] + "-" + string(suffix)
	})
	return workstationName
}

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

	// SOCKS5 proxy for NTLM relay (ntlmrelayx --socks mode)
	Socks5Proxy string // host:port, empty = direct TCP
}

// SMBConnection represents an SMB connection
type SMBConnection struct {
	Config      *SMBConfig
	Connection  *smb2.Session
	IsConnected bool
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

	var conn net.Conn
	if c.Config.Socks5Proxy != "" {
		// Route through SOCKS5 (ntlmrelayx --socks mode or proxychains).
		// The forward dialer applies the TCP timeout and keepalive to the
		// connection toward the proxy itself.
		forward := &net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second}
		socks5Dialer, err := proxy.SOCKS5("tcp", c.Config.Socks5Proxy, nil, forward)
		if err != nil {
			return fmt.Errorf("failed to create SOCKS5 dialer for %s: %v", c.Config.Socks5Proxy, err)
		}
		conn, err = socks5Dialer.Dial("tcp", addr)
		if err != nil {
			return fmt.Errorf("failed to connect via SOCKS5 (%s) to %s: %v", c.Config.Socks5Proxy, addr, err)
		}
	} else {
		dialer := net.Dialer{
			Timeout:   timeout,
			KeepAlive: 30 * time.Second,
		}
		var err error
		conn, err = dialer.Dial("tcp", addr)
		if err != nil {
			return fmt.Errorf("Failed to connect: host %s without SMB", c.Config.Host)
		}
	}

	// Keepalive agressivo: detecta conexão morta em ~45s em vez de esperar horas.
	// SO_KEEPALIVE com probe a cada 15s detecta TCP RST (wsarecv) antes de operações bloquearem.
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.SetKeepAlive(true)
		tcpConn.SetKeepAlivePeriod(15 * time.Second)
		tcpConn.SetNoDelay(true)
	}

	var d *smb2.Dialer

	// If an auth method is provided, use it
	if c.Config.AuthMethod != nil {
		credentials, err := c.Config.AuthMethod.GetCredentials()
		if err != nil {
			return fmt.Errorf("authentication failed: %v", err)
		}

		// Create the appropriate dialer based on the authentication method
		ws := getWorkstationName()
		switch credentials.HashType {
		case "NTLM", "NT", "LM:NT":
			hashBytes, err := hex.DecodeString(credentials.Hash)
			if err != nil {
				return fmt.Errorf("invalid NTLM hash format: %v", err)
			}
			d = &smb2.Dialer{
				Initiator: &smb2.NTLMInitiator{
					Domain:      credentials.Domain,
					User:        credentials.Username,
					Hash:        hashBytes,
					Workstation: ws,
				},
			}
		case "Kerberos":
			if len(credentials.Ticket) > 0 {
				d = &smb2.Dialer{
					Initiator: &smb2.KerberosInitiator{
						APReq:           credentials.Ticket,
						SessionKeyBytes: credentials.SessionKey,
					},
				}
			} else {
				d = &smb2.Dialer{
					Initiator: &smb2.NTLMInitiator{
						Domain:      credentials.Domain,
						User:        credentials.Username,
						Password:    credentials.Password,
						Workstation: ws,
					},
				}
			}
		case "MSCHAPv1", "MSCHAPv2", "NETNTLMv2":
			return fmt.Errorf("%s is a relay-captured challenge-response, not an NT hash; use -H with an NT hash for pass-the-hash", credentials.HashType)
		default:
			d = &smb2.Dialer{
				Initiator: &smb2.NTLMInitiator{
					Domain:      credentials.Domain,
					User:        credentials.Username,
					Password:    credentials.Password,
					Workstation: ws,
				},
			}
		}

		if c.Config.Dialect != 0 {
			d.Negotiator.SpecifiedDialect = c.Config.Dialect
		} else {
			d.Negotiator.SpecifiedDialect = 0 // auto-negociar: servidor escolhe melhor dialeto (SMB311→SMB202)
		}
		if c.Config.Signing != nil {
			d.Negotiator.RequireMessageSigning = *c.Config.Signing
		} else {
			d.Negotiator.RequireMessageSigning = false // negociar com servidor; forçar somente se ele exigir
		}
	} else if c.Config.UseNTLM && c.Config.NTLMHash != "" {
		ntHashStr := c.Config.NTLMHash
		if idx := strings.LastIndex(ntHashStr, ":"); idx >= 0 {
			ntHashStr = ntHashStr[idx+1:]
		}
		hashBytes, err := hex.DecodeString(ntHashStr)
		if err != nil {
			return fmt.Errorf("invalid NTLM hash: %v", err)
		}
		d = &smb2.Dialer{
			Initiator: &smb2.NTLMInitiator{
				Domain:      c.Config.Domain,
				User:        c.Config.Username,
				Hash:        hashBytes,
				Workstation: getWorkstationName(),
			},
		}
		if c.Config.Dialect != 0 {
			d.Negotiator.SpecifiedDialect = c.Config.Dialect
		}
		if c.Config.Signing != nil {
			d.Negotiator.RequireMessageSigning = *c.Config.Signing
		} else {
			d.Negotiator.RequireMessageSigning = false
		}
	} else {
		// Default to username/password authentication
		d = &smb2.Dialer{
			Initiator: &smb2.NTLMInitiator{
				Domain:      c.Config.Domain,
				User:        c.Config.Username,
				Password:    c.Config.Password,
				Workstation: getWorkstationName(),
			},
		}
		if c.Config.Dialect != 0 {
			d.Negotiator.SpecifiedDialect = c.Config.Dialect
		}
		if c.Config.Signing != nil {
			d.Negotiator.RequireMessageSigning = *c.Config.Signing
		} else {
			d.Negotiator.RequireMessageSigning = false
		}
	}

	// Last-chance lockout guard: abort before sending credentials if halt was
	// triggered by another goroutine after we established the TCP connection.
	if atomic.LoadInt32(&lockoutHalted) != 0 {
		conn.Close()
		return fmt.Errorf("SMB authentication aborted: lockout guard active")
	}
	session, err := d.Dial(conn)
	if err != nil {
		return fmt.Errorf("SMB authentication failed: %v", err)
	}

	c.Connection = session
	c.IsConnected = true

	return nil
}

// Disconnect closes the SMB connection
func (c *SMBConnection) Disconnect() {
	if c.IsConnected && c.Connection != nil {
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

