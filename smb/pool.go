package smb

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/hirochachacha/go-smb2"
)

// ConnectionPool gerencia um pool de conexões SMB
type ConnectionPool struct {
	mu          sync.RWMutex
	connections map[string]*pooledConnection
	config      *PoolConfig
}

// PoolConfig configura o comportamento do pool
type PoolConfig struct {
	MaxConnsPerHost int           // Máximo de conexões por host
	IdleTimeout     time.Duration // Tempo máximo que uma conexão pode ficar ociosa
	MaxRetries      int           // Número máximo de tentativas de reconexão
}

// pooledConnection representa uma conexão no pool
type pooledConnection struct {
	conn       *SMBConnection
	share      *smb2.Share
	lastUsed   time.Time
	inUse      bool
	sharesMu   sync.RWMutex
	shares     map[string]*smb2.Share
	retryCount int
	hostKey    string
}

// DefaultPoolConfig retorna uma configuração padrão para o pool
func DefaultPoolConfig() *PoolConfig {
	return &PoolConfig{
		MaxConnsPerHost: 1,
		IdleTimeout:     5 * time.Minute,
		MaxRetries:      3,
	}
}

// NewConnectionPool cria um novo pool de conexões
func NewConnectionPool(config *PoolConfig) *ConnectionPool {
	if config == nil {
		config = DefaultPoolConfig()
	}

	pool := &ConnectionPool{
		connections: make(map[string]*pooledConnection),
		config:      config,
	}

	// Iniciar goroutine para limpeza de conexões ociosas
	go pool.cleanupIdleConnections()

	return pool
}

// getHostKey gera uma chave única para o host
func getHostKey(host, domain, username string) string {
	return fmt.Sprintf("%s:%s:%s", host, domain, username)
}

// GetConnection obtém uma conexão do pool ou cria uma nova
func (p *ConnectionPool) GetConnection(ctx context.Context, config *SMBConfig) (*SMBConnection, error) {
	hostKey := getHostKey(config.Host, config.Domain, config.Username)

	p.mu.RLock()
	conn, exists := p.connections[hostKey]
	p.mu.RUnlock()

	if exists && conn.inUse {
		// Se já existe uma conexão em uso, tentar criar uma nova se não exceder o limite
		p.mu.Lock()
		count := 0
		for _, c := range p.connections {
			if c.hostKey == hostKey {
				count++
			}
		}
		p.mu.Unlock()

		if count >= p.config.MaxConnsPerHost {
			return nil, fmt.Errorf("maximum connections reached for host %s", config.Host)
		}
	}

	if exists && !conn.inUse {
		conn.inUse = true
		conn.lastUsed = time.Now()
		return conn.conn, nil
	}

	// Criar nova conexão
	newConn := &SMBConnection{
		Config: config,
	}

	err := newConn.Connect()
	if err != nil {
		return nil, fmt.Errorf("failed to create new connection: %v", err)
	}

	pooled := &pooledConnection{
		conn:     newConn,
		lastUsed: time.Now(),
		inUse:    true,
		shares:   make(map[string]*smb2.Share),
		hostKey:  hostKey,
	}

	p.mu.Lock()
	p.connections[hostKey] = pooled
	p.mu.Unlock()

	return newConn, nil
}

// ReleaseConnection libera uma conexão de volta para o pool
func (p *ConnectionPool) ReleaseConnection(config *SMBConfig) {
	hostKey := getHostKey(config.Host, config.Domain, config.Username)

	p.mu.Lock()
	defer p.mu.Unlock()

	if conn, exists := p.connections[hostKey]; exists {
		conn.inUse = false
		conn.lastUsed = time.Now()
	}
}

// cleanupIdleConnections remove conexões ociosas periodicamente
func (p *ConnectionPool) cleanupIdleConnections() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for range ticker.C {
		p.mu.Lock()
		now := time.Now()
		for key, conn := range p.connections {
			if !conn.inUse && now.Sub(conn.lastUsed) > p.config.IdleTimeout {
				conn.conn.Disconnect()
				delete(p.connections, key)
			}
		}
		p.mu.Unlock()
	}
}

// GetShare obtém um share do pool ou cria um novo
func (p *ConnectionPool) GetShare(conn *SMBConnection, shareName string) (*smb2.Share, error) {
	hostKey := getHostKey(conn.Config.Host, conn.Config.Domain, conn.Config.Username)

	p.mu.RLock()
	pooled, exists := p.connections[hostKey]
	p.mu.RUnlock()

	if !exists {
		return nil, fmt.Errorf("connection not found in pool")
	}

	pooled.sharesMu.RLock()
	share, exists := pooled.shares[shareName]
	pooled.sharesMu.RUnlock()

	if exists {
		return share, nil
	}

	// Montar novo share
	share, err := conn.MountShare(shareName)
	if err != nil {
		return nil, err
	}

	pooled.sharesMu.Lock()
	pooled.shares[shareName] = share
	pooled.sharesMu.Unlock()

	return share, nil
}

// Close fecha todas as conexões no pool
func (p *ConnectionPool) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()

	for _, conn := range p.connections {
		conn.sharesMu.Lock()
		for _, share := range conn.shares {
			share.Umount()
		}
		conn.sharesMu.Unlock()
		conn.conn.Disconnect()
	}

	p.connections = make(map[string]*pooledConnection)
}
