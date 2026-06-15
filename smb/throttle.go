package smb

import (
	"context"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// ThrottleConfig configura o comportamento do throttling
type ThrottleConfig struct {
	MaxBandwidth  int64         // Bandwidth limit in bytes per second
	MaxConcurrent int           // Maximum concurrent operations
	BatchSize     int           // Size of operation batches
	BatchTimeout  time.Duration // Maximum time to wait for batch completion
}

// Throttler gerencia o throttling de operações SMB
type Throttler struct {
	limiter    *rate.Limiter
	semaphore  chan struct{}
	batchSize  int
	batchTimer time.Duration
	mu         sync.Mutex
	operations []Operation
	config     *ThrottleConfig
}

// Operation representa uma operação SMB genérica
type Operation struct {
	Type     string      // Tipo da operação (read, write, list)
	Data     interface{} // Dados da operação
	Size     int64       // Tamanho estimado da operação
	Callback func() error
}

// DefaultThrottleConfig retorna uma configuração padrão para throttling
func DefaultThrottleConfig() *ThrottleConfig {
	return &ThrottleConfig{
		MaxBandwidth:  10 * 1024 * 1024, // 10MB/s
		MaxConcurrent: 5,
		BatchSize:     100,
		BatchTimeout:  time.Second * 2,
	}
}

// NewThrottler cria um novo throttler
func NewThrottler(config *ThrottleConfig) *Throttler {
	if config == nil {
		config = DefaultThrottleConfig()
	}

	return &Throttler{
		limiter:    rate.NewLimiter(rate.Limit(config.MaxBandwidth), int(config.MaxBandwidth)),
		semaphore:  make(chan struct{}, config.MaxConcurrent),
		batchSize:  config.BatchSize,
		batchTimer: config.BatchTimeout,
		operations: make([]Operation, 0, config.BatchSize),
		config:     config,
	}
}

// AddOperation adiciona uma operação ao batch
func (t *Throttler) AddOperation(op Operation) {
	t.mu.Lock()
	t.operations = append(t.operations, op)
	shouldProcess := len(t.operations) >= t.batchSize
	t.mu.Unlock()

	if shouldProcess {
		t.ProcessBatch()
	}
}

// ProcessBatch processa um lote de operações
func (t *Throttler) ProcessBatch() {
	t.mu.Lock()
	if len(t.operations) == 0 {
		t.mu.Unlock()
		return
	}

	batch := make([]Operation, len(t.operations))
	copy(batch, t.operations)
	t.operations = t.operations[:0]
	t.mu.Unlock()

	var wg sync.WaitGroup
	for _, op := range batch {
		wg.Add(1)
		go func(operation Operation) {
			defer wg.Done()

			// Adquirir semáforo
			t.semaphore <- struct{}{}
			defer func() { <-t.semaphore }()

			// Aplicar throttling baseado no tamanho da operação
			if operation.Size > 0 {
				err := t.limiter.WaitN(context.Background(), int(operation.Size))
				if err != nil {
					// Log error or handle it appropriately
					return
				}
			}

			// Executar operação
			if operation.Callback != nil {
				_ = operation.Callback()
			}
		}(op)
	}

	wg.Wait()
}

// StartBatchProcessor inicia o processador de batches em background
func (t *Throttler) StartBatchProcessor(ctx context.Context) {
	ticker := time.NewTicker(t.batchTimer)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			t.ProcessBatch()
		}
	}
}

// WaitN espera pela permissão para transferir n bytes
func (t *Throttler) WaitN(ctx context.Context, n int) error {
	return t.limiter.WaitN(ctx, n)
}

// Allow verifica se uma operação pode ser executada imediatamente
func (t *Throttler) Allow() bool {
	return t.limiter.Allow()
}

// Acquire adquire uma vaga no semáforo de operações concorrentes
func (t *Throttler) Acquire() {
	t.semaphore <- struct{}{}
}

// Release libera uma vaga no semáforo de operações concorrentes
func (t *Throttler) Release() {
	<-t.semaphore
}
