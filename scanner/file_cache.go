package scanner

import (
	"sync"

	lru "github.com/hashicorp/golang-lru"
)

// FileContentCache armazena conteúdo de arquivos lidos frequentemente
// O valor pode ser []byte (header, chunk ou arquivo inteiro)
type FileContentCache struct {
	cache *lru.Cache
	mu    sync.RWMutex
}

// NewFileContentCache cria um novo cache LRU para arquivos
func NewFileContentCache(size int) (*FileContentCache, error) {
	cache, err := lru.New(size)
	if err != nil {
		return nil, err
	}
	return &FileContentCache{cache: cache}, nil
}

// Get retorna o conteúdo do arquivo se estiver no cache
func (c *FileContentCache) Get(key string) ([]byte, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	if val, ok := c.cache.Get(key); ok {
		if data, ok := val.([]byte); ok {
			return data, true
		}
	}
	return nil, false
}

// Set armazena o conteúdo do arquivo no cache
func (c *FileContentCache) Set(key string, data []byte) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.cache.Add(key, data)
}
