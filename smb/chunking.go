package smb

import (
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/edsrzf/mmap-go"
)

const (
	defaultChunkSize = 1024 * 1024 // 1MB
)

// Config defines the configuration for chunk processing
type Config struct {
	ChunkSize   int
	MaxChunks   int
	UseMemMap   bool
	ReadTimeout time.Duration
}

// DefaultConfig returns a default configuration
func DefaultConfig() *Config {
	return &Config{
		ChunkSize:   defaultChunkSize,
		MaxChunks:   10,
		UseMemMap:   false,
		ReadTimeout: 30 * time.Second,
	}
}

// ChunkConfig configures the chunking behavior
type ChunkConfig struct {
	ChunkSize  int64 // Size of each chunk in bytes
	MaxChunks  int   // Maximum number of chunks processed simultaneously
	UseMMap    bool  // Use memory-mapped files for reading
	BufferSize int   // Buffer size for non-mmap operations
}

// DefaultChunkConfig returns a default configuration for chunking
func DefaultChunkConfig() *ChunkConfig {
	return &ChunkConfig{
		ChunkSize:  1024 * 1024, // 1MB
		MaxChunks:  5,
		UseMMap:    true,
		BufferSize: 32 * 1024, // 32KB
	}
}

// Chunk represents a piece of a file
type Chunk struct {
	Offset int64
	Size   int64
	Data   []byte
}

var (
	// Buffer pool for reuse
	bufferPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, defaultChunkSize)
		},
	}
)

// ChunkProcessor manages the processing of file chunks
type ChunkProcessor struct {
	config    *Config
	processor func([]byte) error
}

// NewChunkProcessor creates a new chunk processor
func NewChunkProcessor(config *Config, processor func([]byte) error) *ChunkProcessor {
	if config == nil {
		config = DefaultConfig()
	}
	return &ChunkProcessor{
		config:    config,
		processor: processor,
	}
}

// ProcessFile processes a file in chunks
func (p *ChunkProcessor) ProcessFile(file *os.File) error {
	if p.config.UseMemMap {
		return p.processWithMemMap(file)
	}
	return p.processWithBuffers(file)
}

// processWithBuffers processes the file using a buffer pool
func (p *ChunkProcessor) processWithBuffers(file *os.File) error {
	fileInfo, err := file.Stat()
	if err != nil {
		return fmt.Errorf("error getting file information: %w", err)
	}

	if fileInfo.Size() > int64(p.config.MaxChunks*p.config.ChunkSize) {
		return fmt.Errorf("file too large: %d bytes", fileInfo.Size())
	}

	buffer := bufferPool.Get().([]byte)
	defer bufferPool.Put(buffer)

	for {
		done := make(chan error, 1)
		go func() {
			n, err := file.Read(buffer)
			if err != nil && err != io.EOF {
				done <- fmt.Errorf("read error: %w", err)
				return
			}
			if n == 0 {
				done <- io.EOF
				return
			}

			if err := p.processor(buffer[:n]); err != nil {
				done <- fmt.Errorf("processing error: %w", err)
				return
			}
			done <- nil
		}()

		select {
		case err := <-done:
			if err == io.EOF {
				return nil
			}
			if err != nil {
				return err
			}
		case <-time.After(p.config.ReadTimeout):
			return fmt.Errorf("timeout reading file after %v", p.config.ReadTimeout)
		}
	}
}

// processWithMemMap processes the file using memory-mapped IO
func (p *ChunkProcessor) processWithMemMap(file *os.File) error {
	fileInfo, err := file.Stat()
	if err != nil {
		return fmt.Errorf("error getting file information: %w", err)
	}

	if fileInfo.Size() > int64(p.config.MaxChunks*p.config.ChunkSize) {
		return fmt.Errorf("file too large: %d bytes", fileInfo.Size())
	}

	mmapData, err := mmap.Map(file, mmap.RDONLY, 0)
	if err != nil {
		return fmt.Errorf("error mapping file: %w", err)
	}
	defer mmapData.Unmap()

	// Processes memory-mapped chunks
	for offset := 0; offset < len(mmapData); offset += p.config.ChunkSize {
		end := offset + p.config.ChunkSize
		if end > len(mmapData) {
			end = len(mmapData)
		}
		if err := p.processor(mmapData[offset:end]); err != nil {
			return fmt.Errorf("error processing chunk: %w", err)
		}
	}

	return nil
}
