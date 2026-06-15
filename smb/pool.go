package smb

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/m0ng3sh3ll/NullFang/go-smb2-patch"
)

// PoolConfig configura o comportamento do pool
type PoolConfig struct {
	MaxConnsPerHost int
	IdleTimeout     time.Duration
	MaxRetries      int
}

// DefaultPoolConfig retorna uma configuração padrão para o pool
func DefaultPoolConfig() *PoolConfig {
	return &PoolConfig{
		MaxConnsPerHost: 5,
		IdleTimeout:     5 * time.Minute,
		MaxRetries:      3,
	}
}

// pooledConnection representa uma conexão no pool
type pooledConnection struct {
	conn     *SMBConnection
	lastUsed time.Time
	inUse    bool
	sharesMu sync.Mutex
	shares   map[string]*smb2.Share
	hostKey  string
}

// ConnectionPool gerencia um pool de conexões SMB.
// Cada host key maps to a slice of connections so MaxConnsPerHost is enforced correctly.
type ConnectionPool struct {
	mu          sync.Mutex
	connections map[string][]*pooledConnection
	config      *PoolConfig
	stop        chan struct{}
	once        sync.Once
}

// NewConnectionPool cria um novo pool de conexões
func NewConnectionPool(config *PoolConfig) *ConnectionPool {
	if config == nil {
		config = DefaultPoolConfig()
	}

	pool := &ConnectionPool{
		connections: make(map[string][]*pooledConnection),
		config:      config,
		stop:        make(chan struct{}),
	}

	go pool.cleanupIdleConnections()

	return pool
}

// getHostKey gera uma chave única para o host
func getHostKey(host, domain, username string) string {
	return fmt.Sprintf("%s:%s:%s", host, domain, username)
}

// GetConnection obtém uma conexão idle do pool ou cria uma nova.
func (p *ConnectionPool) GetConnection(ctx context.Context, config *SMBConfig) (*SMBConnection, error) {
	hostKey := getHostKey(config.Host, config.Domain, config.Username)

	p.mu.Lock()
	slice := p.connections[hostKey]
	for _, c := range slice {
		if !c.inUse {
			c.inUse = true
			c.lastUsed = time.Now()
			p.mu.Unlock()
			return c.conn, nil
		}
	}
	// No idle connection found; check limit before creating.
	if len(slice) >= p.config.MaxConnsPerHost {
		p.mu.Unlock()
		return nil, fmt.Errorf("maximum connections reached for host %s", config.Host)
	}
	p.mu.Unlock()

	// Create new connection outside the lock — network I/O should not hold the mutex.
	newConn := NewSMBConnection(config)
	if err := newConn.Connect(); err != nil {
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
	p.connections[hostKey] = append(p.connections[hostKey], pooled)
	p.mu.Unlock()

	return newConn, nil
}

// ReleaseConnection libera uma conexão de volta para o pool usando identidade de ponteiro.
func (p *ConnectionPool) ReleaseConnection(conn *SMBConnection) {
	p.mu.Lock()
	defer p.mu.Unlock()

	hostKey := getHostKey(conn.Config.Host, conn.Config.Domain, conn.Config.Username)
	for _, c := range p.connections[hostKey] {
		if c.conn == conn {
			c.inUse = false
			c.lastUsed = time.Now()
			return
		}
	}
}

// GetShare obtém um share montado do pool ou monta um novo.
func (p *ConnectionPool) GetShare(conn *SMBConnection, shareName string) (*smb2.Share, error) {
	hostKey := getHostKey(conn.Config.Host, conn.Config.Domain, conn.Config.Username)

	p.mu.Lock()
	var pooled *pooledConnection
	for _, c := range p.connections[hostKey] {
		if c.conn == conn {
			pooled = c
			break
		}
	}
	p.mu.Unlock()

	if pooled == nil {
		return nil, fmt.Errorf("connection not found in pool")
	}

	pooled.sharesMu.Lock()
	share, exists := pooled.shares[shareName]
	pooled.sharesMu.Unlock()

	if exists {
		return share, nil
	}

	share, err := conn.MountShare(shareName)
	if err != nil {
		return nil, err
	}

	pooled.sharesMu.Lock()
	pooled.shares[shareName] = share
	pooled.sharesMu.Unlock()

	return share, nil
}

// cleanupIdleConnections remove conexões ociosas periodicamente.
func (p *ConnectionPool) cleanupIdleConnections() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			p.mu.Lock()
			now := time.Now()
			for key, slice := range p.connections {
				live := slice[:0]
				for _, c := range slice {
					if !c.inUse && now.Sub(c.lastUsed) > p.config.IdleTimeout {
						c.conn.Disconnect()
					} else {
						live = append(live, c)
					}
				}
				if len(live) == 0 {
					delete(p.connections, key)
				} else {
					p.connections[key] = live
				}
			}
			p.mu.Unlock()
		case <-p.stop:
			return
		}
	}
}

// Close fecha todas as conexões no pool e para a goroutine de limpeza.
func (p *ConnectionPool) Close() {
	p.once.Do(func() { close(p.stop) })

	p.mu.Lock()
	defer p.mu.Unlock()

	for _, slice := range p.connections {
		for _, c := range slice {
			c.sharesMu.Lock()
			for _, share := range c.shares {
				share.Umount()
			}
			c.sharesMu.Unlock()
			c.conn.Disconnect()
		}
	}
	p.connections = make(map[string][]*pooledConnection)
}
