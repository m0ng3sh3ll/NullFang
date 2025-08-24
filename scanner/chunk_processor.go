package scanner

import (
	"context"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/edsrzf/mmap-go"
)

// ChunkProcessor gerencia o processamento de chunks de arquivo
type ChunkProcessor struct {
	chunkSize   int
	maxChunks   int
	useMemMap   bool
	bufferPool  *sync.Pool
	readTimeout time.Duration
}

// NewChunkProcessor cria nova instância do processador de chunks
func NewChunkProcessor(config *ProcessorConfig) *ChunkProcessor {
	return &ChunkProcessor{
		chunkSize:   config.ChunkSize,
		maxChunks:   config.MaxChunks,
		useMemMap:   config.UseMemMap,
		bufferPool:  config.BufferPool,
		readTimeout: config.ReadTimeout,
	}
}

// ProcessorConfig configuração para o processador de chunks
type ProcessorConfig struct {
	ChunkSize   int
	MaxChunks   int
	UseMemMap   bool
	BufferPool  *sync.Pool
	ReadTimeout time.Duration
}

// ProcessFile processa o arquivo em chunks
func (p *ChunkProcessor) ProcessFile(ctx context.Context, file *os.File) <-chan []byte {
	chunks := make(chan []byte)

	go func() {
		defer close(chunks)

		if p.useMemMap {
			p.processWithMemMap(ctx, file, chunks)
		} else {
			p.processWithBuffer(ctx, file, chunks)
		}
	}()

	return chunks
}

// processWithMemMap processa arquivo usando mmap
func (p *ChunkProcessor) processWithMemMap(ctx context.Context, file *os.File, chunks chan<- []byte) {
	mmapped, err := mmap.Map(file, mmap.RDONLY, 0)
	if err != nil {
		// Fallback para processamento com buffer em caso de erro
		p.processWithBuffer(ctx, file, chunks)
		return
	}
	defer mmapped.Unmap()

	for i := 0; i < len(mmapped); i += p.chunkSize {
		select {
		case <-ctx.Done():
			return
		default:
			end := i + p.chunkSize
			if end > len(mmapped) {
				end = len(mmapped)
			}

			// Cria uma cópia do chunk para evitar problemas com o mmap
			chunk := make([]byte, end-i)
			copy(chunk, mmapped[i:end])

			chunks <- chunk
		}
	}
}

// processWithBuffer processa arquivo usando buffer
func (p *ChunkProcessor) processWithBuffer(ctx context.Context, file *os.File, chunks chan<- []byte) {
	buffer := p.bufferPool.Get().([]byte)
	defer p.bufferPool.Put(buffer)

	for {
		select {
		case <-ctx.Done():
			return
		default:
			// Cria contexto com timeout para a leitura
			readCtx, cancel := context.WithTimeout(ctx, p.readTimeout)
			defer cancel()

			// Canal para resultado da leitura
			done := make(chan struct{})
			var n int
			var err error

			// Realiza leitura em goroutine separada
			go func() {
				n, err = file.Read(buffer)
				close(done)
			}()

			// Aguarda leitura ou timeout
			select {
			case <-readCtx.Done():
				return
			case <-done:
				if err == io.EOF {
					return
				}
				if err != nil {
					continue
				}

				// Cria cópia do chunk lido
				chunk := make([]byte, n)
				copy(chunk, buffer[:n])

				chunks <- chunk
			}
		}
	}
}

// ValidateConfig valida a configuração do processador
func (p *ChunkProcessor) ValidateConfig() error {
	if p.chunkSize <= 0 {
		return fmt.Errorf("tamanho do chunk deve ser maior que zero")
	}
	if p.maxChunks <= 0 {
		return fmt.Errorf("número máximo de chunks deve ser maior que zero")
	}
	if p.readTimeout <= 0 {
		return fmt.Errorf("timeout de leitura deve ser maior que zero")
	}
	return nil
}
