package scanner

import (
	"bytes"
	"context"
	"os"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru"
	"github.com/m0ng3sh3ll/NullFang/logger"
)

// PatternPriority define os níveis de prioridade para padrões e cópia
type PatternPriority int

const (
	PriorityLow PatternPriority = iota
	PriorityMedium
	PriorityHigh
	PriorityCritical
)

// CopyPriority define os níveis de prioridade para cópia de arquivos
type CopyPriority struct {
	Level     PatternPriority
	Immediate bool  // Se true, copia imediatamente ao encontrar match
	MaxSize   int64 // Tamanho máximo em bytes para esta prioridade
}

// Scanner interface principal para todos os scanners
type Scanner interface {
	Scan(ctx context.Context, file *os.File, config *ScanConfig) <-chan ScanResult
	AddPattern(pattern Pattern)
	SetCopyPriority(priority CopyPriority)
}

// ScanConfig configuração para o scanner
type ScanConfig struct {
	ChunkSize   int
	MaxChunks   int
	UseMemMap   bool
	Patterns    []Pattern
	BufferPool  *sync.Pool
	ReadTimeout time.Duration
	CopyConfig  *CopyConfig
}

// CopyConfig configuração específica para cópia
type CopyConfig struct {
	DefaultPriority PatternPriority
	PriorityRules   []CopyPriorityRule
	OutputDir       string
	PreservePath    bool
}

// CopyPriorityRule regra para determinar prioridade de cópia
type CopyPriorityRule struct {
	Pattern   string
	Priority  PatternPriority
	Immediate bool
	MaxSize   int64
}

// ScanResult resultado do scan
type ScanResult struct {
	Content    string
	LineNumber int
	MatchType  string
	Pattern    string
	Priority   PatternPriority
	CopyStatus CopyStatus
	Error      error
}

// CopyStatus status da cópia do arquivo
type CopyStatus struct {
	ShouldCopy bool
	Priority   PatternPriority
	Immediate  bool
}

// Pattern define um padrão de busca
type Pattern struct {
	Value    string
	Type     string // regex, text, binary
	Priority PatternPriority
}

// ScannerCache implementa cache para padrões compilados
type ScannerCache struct {
	cache    *lru.Cache
	patterns map[string]*regexp.Regexp
	mu       sync.RWMutex
}

// NewScannerCache cria nova instância do cache
func NewScannerCache(size int) (*ScannerCache, error) {
	cache, err := lru.New(size)
	if err != nil {
		return nil, err
	}
	return &ScannerCache{
		cache:    cache,
		patterns: make(map[string]*regexp.Regexp),
	}, nil
}

// GetPattern retorna padrão compilado do cache
func (c *ScannerCache) GetPattern(pattern string) *regexp.Regexp {
	c.mu.RLock()
	if re, exists := c.patterns[pattern]; exists {
		c.mu.RUnlock()
		return re
	}
	c.mu.RUnlock()

	c.mu.Lock()
	defer c.mu.Unlock()

	re := regexp.MustCompile(pattern)
	c.patterns[pattern] = re
	return re
}

// BaseScanner implementação base para todos os scanners
type BaseScanner struct {
	config    *ScanConfig
	processor *ChunkProcessor
	patterns  []Pattern
	cache     *ScannerCache
	copyRules []CopyPriorityRule
}

// NewBaseScanner cria nova instância do scanner base
func NewBaseScanner(config *ScanConfig) (*BaseScanner, error) {
	cache, err := NewScannerCache(1000) // Cache para 1000 padrões
	if err != nil {
		return nil, err
	}

	return &BaseScanner{
		config:   config,
		cache:    cache,
		patterns: make([]Pattern, 0),
	}, nil
}

// AddPattern adiciona novo padrão ao scanner
func (s *BaseScanner) AddPattern(pattern Pattern) {
	s.patterns = append(s.patterns, pattern)
	// Ordena padrões por prioridade (maior primeiro)
	sort.Slice(s.patterns, func(i, j int) bool {
		return s.patterns[i].Priority > s.patterns[j].Priority
	})
}

// SetCopyPriority configura prioridade de cópia
func (s *BaseScanner) SetCopyPriority(priority CopyPriority) {
	rule := CopyPriorityRule{
		Priority:  priority.Level,
		Immediate: priority.Immediate,
		MaxSize:   priority.MaxSize,
	}
	s.copyRules = append(s.copyRules, rule)
}

// determineCopyStatus determina se e como um arquivo deve ser copiado
func (s *BaseScanner) determineCopyStatus(pattern Pattern, fileSize int64) CopyStatus {
	// Verifica regras específicas primeiro
	for _, rule := range s.copyRules {
		if rule.Pattern != "" && rule.Pattern == pattern.Value {
			if fileSize <= rule.MaxSize {
				return CopyStatus{
					ShouldCopy: true,
					Priority:   rule.Priority,
					Immediate:  rule.Immediate,
				}
			}
		}
	}

	// Aplica regra padrão baseada na prioridade do padrão
	return CopyStatus{
		ShouldCopy: true,
		Priority:   pattern.Priority,
		Immediate:  pattern.Priority >= PriorityHigh,
	}
}

// Scan implementa o scanner assíncrono
func (s *BaseScanner) Scan(ctx context.Context, file *os.File, config *ScanConfig) <-chan ScanResult {
	results := make(chan ScanResult)

	go func() {
		defer close(results)

		chunks := s.processor.ProcessFile(ctx, file)
		var wg sync.WaitGroup
		semaphore := make(chan struct{}, 5) // Limita a 5 goroutines paralelas

		for chunk := range chunks {
			wg.Add(1)
			semaphore <- struct{}{} // Adquire semáforo

			go func(c []byte) {
				defer wg.Done()
				defer func() { <-semaphore }() // Libera semáforo

				for _, pattern := range s.patterns {
					select {
					case <-ctx.Done():
						return
					default:
						if match := s.matchPattern(c, pattern); match != nil {
							copyStatus := s.determineCopyStatus(pattern, int64(len(c)))
							match.CopyStatus = copyStatus

							select {
							case results <- *match:
							case <-ctx.Done():
								return
							}

							// Se cópia imediata é necessária
							if copyStatus.Immediate {
								logger.Info("Iniciando cópia imediata para padrão de alta prioridade: %s", pattern.Value)
								// Implementar lógica de cópia imediata aqui
							}
						}
					}
				}
			}(chunk)
		}

		wg.Wait()
	}()

	return results
}

// matchPattern verifica se um chunk corresponde a um padrão
func (s *BaseScanner) matchPattern(chunk []byte, pattern Pattern) *ScanResult {
	switch pattern.Type {
	case "regex":
		re := s.cache.GetPattern(pattern.Value)
		if match := re.Find(chunk); match != nil {
			return &ScanResult{
				Content:   string(match),
				MatchType: "regex",
				Pattern:   pattern.Value,
				Priority:  pattern.Priority,
			}
		}
	case "text":
		if idx := indexOf(chunk, []byte(pattern.Value)); idx >= 0 {
			return &ScanResult{
				Content:   pattern.Value,
				MatchType: "text",
				Pattern:   pattern.Value,
				Priority:  pattern.Priority,
			}
		}
	case "binary":
		// Implementar lógica para padrões binários
	}
	return nil
}

// indexOf implementa busca de substring em bytes
func indexOf(haystack, needle []byte) int {
	if len(needle) == 0 {
		return 0
	}
	if len(haystack) < len(needle) {
		return -1
	}
	for i := 0; i <= len(haystack)-len(needle); i++ {
		if bytes.Equal(haystack[i:i+len(needle)], needle) {
			return i
		}
	}
	return -1
}

// FileScanner interface para processamento de arquivos
type FileScanner interface {
	Scan(callback func(content string) error) error
}

// FileType representa o tipo de arquivo
type FileType string

const (
	TypeText FileType = "text"
	TypePDF  FileType = "pdf"
	TypeWeb  FileType = "web"
	TypeZip  FileType = "zip"
)

// IsWebFile verifica se o arquivo é um arquivo web (HTML, JS, CSS, PHP, JSP, ASP, etc)
func IsWebFile(header []byte, filename ...string) bool {
	webSignatures := [][]byte{
		[]byte("<!DOCTYPE"),
		[]byte("<html"),
		[]byte("<?php"),
		[]byte("<%@"),
		[]byte("<%="),
		[]byte("function"),
		[]byte(".css"),
		[]byte("<jsp:"),
		[]byte("<asp:"),
		[]byte("<!--#include"),
		[]byte("<script"),
		[]byte("<cfscript"),
		[]byte("<cfoutput"),
		[]byte("<wsdl:"),
		[]byte("<soap:"),
		[]byte("<py:"),
		[]byte("<rb:"),
	}

	for _, sig := range webSignatures {
		if bytes.Contains(bytes.ToLower(header), bytes.ToLower(sig)) {
			return true
		}
	}

	// Detectar por extensão do arquivo, se fornecido
	if len(filename) > 0 {
		name := strings.ToLower(filename[0])
		webExts := []string{
			".php", ".phtml", ".php3", ".php4", ".php5", ".phps",
			".jsp", ".jspx", ".jsw", ".jsv", ".jspf",
			".asp", ".aspx", ".ascx", ".ashx", ".asmx", ".axd",
			".cfm", ".cfml", ".cfc",
			".pl", ".cgi", ".pm",
			".erb", ".rhtml",
			".py", ".rb", ".do", ".action",
			".wsdl", ".xml", ".xsl",
			".html", ".htm", ".shtml", ".dhtml", ".xhtml",
			".js", ".css",
		}
		for _, ext := range webExts {
			if strings.HasSuffix(name, ext) {
				return true
			}
		}
	}

	return false
}

// IsPDF verifica se o arquivo é um PDF
func IsPDF(header []byte) bool {
	return bytes.HasPrefix(header, []byte("%PDF"))
}

// IsZip verifica se o arquivo é um ZIP
func IsZip(header []byte) bool {
	return bytes.HasPrefix(header, []byte("PK\x03\x04"))
}
