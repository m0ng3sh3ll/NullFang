package search

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/m0ng3sh3ll/NullFang/go-smb2-patch"
	"github.com/m0ng3sh3ll/NullFang/logger"
	"github.com/m0ng3sh3ll/NullFang/scanner"
)

// MountedShare represents a mounted SMB share with an optional start path
type MountedShare struct {
	Share     *smb2.Share
	StartPath string
	ShareName string
}

// SearchConfig holds the configuration for file searching
type SearchConfig struct {
	// Search by filename patterns
	SearchFilenames  bool
	FilenamePatterns []string

	// Search by content patterns
	SearchContents  bool
	ContentPatterns []string

	// Search by regex patterns
	SearchRegex   bool
	RegexPatterns []*regexp.Regexp

	// Maximum file size to search (in bytes)
	MaxFileSize int64

	// File extensions to search
	FileExtensions []string

	// Verbose output
	Verbose bool

	// Case sensitive search (default: false)
	CaseSensitive bool

	// Restrict search to share root (default: true)
	RestrictToShareRoot bool

	// Timeout for search operations (default: 5 minutes)
	Timeout time.Duration

	// Skip special shares like IPC$ (default: true)
	SkipSpecialShares bool

	// Maximum directory depth for recursive search (default: 10)
	MaxDepth int

	// Extra verbose logging (default: false)
	ExtraVerbose bool

	// Maximum workers for parallel processing
	MaxWorkers int

	// Buffer size for worker pool
	BufferSize int

	// Directory cache TTL
	DirCacheTTL time.Duration

	// Maximum circuit breaker threshold
	CircuitBreakerThreshold int

	// Enable search in binary files (default: false)
	SearchBinary bool

	// Minimum string length for binary extraction
	MinBinaryStringLen int

	// Maximum cache file size for content (em bytes)
	MaxCacheFileSize int64

	// Adiciona flag para filtrar arquivos grandes no modo no-copy
	FilterLargeFiles bool

	// Lista de shares a serem excluídos da busca (pode ser sobrescrita por config)
	ExcludedShares []string

	// Patterns or extensions to exclude from copy
	ExcludePatterns []string

	// Minimum date for filtering files
	MinDate time.Time

	// Maximum date for filtering files
	MaxDate time.Time

	// Delay entre operações SMB para evitar sobrecarga do servidor
	OperationDelay time.Duration
}

// SearchResult represents a search result
type SearchResult struct {
	ShareName    string
	FilePath     string
	MatchValue   string
	MatchType    string // "filename", "content", "regex", "extension", "large_file"
	FileSize     int64
	IsDirectory  bool
	ContentMatch string // Conteúdo encontrado no arquivo
	RegexMatch   string // Padrão regex que deu match
}

// WorkerPool manages a pool of workers for file processing
type WorkerPool struct {
	numWorkers    int
	jobs          chan *FileJob
	results       chan<- *SearchResult
	wg            sync.WaitGroup
	fileTypeCache sync.Map
}

type FileJob struct {
	fs        *smb2.Share
	shareName string
	filePath  string
	entry     os.FileInfo
	config    *SearchConfig
}

func NewWorkerPool(numWorkers int, results chan<- *SearchResult) *WorkerPool {
	return &WorkerPool{
		numWorkers: numWorkers,
		jobs:       make(chan *FileJob, numWorkers*2),
		results:    results,
	}
}

func (wp *WorkerPool) Start(ctx context.Context, fileContentCache *scanner.FileContentCache) {
	for i := 0; i < wp.numWorkers; i++ {
		logger.Debug("[DEBUG] Starting worker #%d", i)
		wp.wg.Add(1)
		go wp.worker(ctx, fileContentCache)
	}
}

func (wp *WorkerPool) worker(ctx context.Context, fileContentCache *scanner.FileContentCache) {
	defer func() {
		logger.Debug("[DEBUG] Worker finished")
		wp.wg.Done()
	}()

	for job := range wp.jobs {
		select {
		case <-ctx.Done():
			logger.Debug("[DEBUG] Worker received ctx.Done() and will finish")
			return
		default:
			logger.Debug("[DEBUG] Worker processing file: %s", job.filePath)
			processFile(ctx, job, wp.results, fileContentCache)
		}
	}
	logger.Debug("[DEBUG] Worker exited the job loop (channel closed)")
}

// NewSearchConfig creates a new search configuration with default values
func NewSearchConfig() *SearchConfig {
	return &SearchConfig{
		SearchFilenames:         false,
		FilenamePatterns:        []string{},
		SearchContents:          false,
		ContentPatterns:         []string{},
		SearchRegex:             false,
		RegexPatterns:           []*regexp.Regexp{},
		MaxFileSize:             10 * 1024 * 1024, // 10MB default
		FileExtensions:          []string{},
		Verbose:                 true,
		CaseSensitive:           false,
		RestrictToShareRoot:     true,
		Timeout:                 5 * time.Minute, // Default timeout: 5 minutes
		SkipSpecialShares:       true,
		MaxDepth:                10,                     // Default max depth: 10 levels
		ExtraVerbose:            false,                  // Default to normal verbosity
		MaxWorkers:              10,                     // Default value, will be overwritten by -threads flag
		BufferSize:              1024 * 1024,            // 1MB buffer
		DirCacheTTL:             5 * time.Minute,        // Directory cache TTL
		CircuitBreakerThreshold: 5,                      // Retry attempts
		SearchBinary:            false,                  // Default to disabled
		MinBinaryStringLen:      4,                      // Default mínimo para extração binária
		MaxCacheFileSize:        1024 * 1024,            // 1MB default
		FilterLargeFiles:        false,                  // Default to disabled
		OperationDelay:          500 * time.Millisecond, // Delay padrão entre operações
	}
}

// AddFilenamePattern adds a filename pattern to search for
func (c *SearchConfig) AddFilenamePattern(pattern string) {
	if c.CaseSensitive {
		c.FilenamePatterns = append(c.FilenamePatterns, pattern)
	} else {
		c.FilenamePatterns = append(c.FilenamePatterns, strings.ToLower(pattern))
	}
	c.SearchFilenames = true
}

// AddContentPattern adds a content pattern to search for
func (c *SearchConfig) AddContentPattern(pattern string) {
	c.ContentPatterns = append(c.ContentPatterns, pattern)
	c.SearchContents = true
}

// AddRegexPattern adds a regex pattern to search for
func (c *SearchConfig) AddRegexPattern(pattern string) error {
	var regex *regexp.Regexp
	var err error

	if c.CaseSensitive {
		regex, err = regexp.Compile(pattern)
	} else {
		regex, err = regexp.Compile("(?i)" + pattern) // Case insensitive
	}

	if err != nil {
		return fmt.Errorf("invalid regex pattern: %v", err)
	}
	c.RegexPatterns = append(c.RegexPatterns, regex)
	c.SearchRegex = true
	return nil
}

// AddFileExtension adds a file extension to the list of extensions to search
func (c *SearchConfig) AddFileExtension(ext string) {
	// Ensure extension starts with a dot
	if !strings.HasPrefix(ext, ".") {
		ext = "." + ext
	}
	c.FileExtensions = append(c.FileExtensions, strings.ToLower(ext))
}

// SearchShare searches a mounted SMB share for files matching the search criteria
func SearchShare(fs *smb2.Share, shareName string, startPath string, config *SearchConfig, results chan<- *SearchResult, fileContentCache *scanner.FileContentCache) error {
	if config.SkipSpecialShares && isSpecialShare(shareName, config.ExcludedShares) {
		if config.Verbose {
			logger.Debug("[*] Skipping special share: %s\n", shareName)
		}
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), config.Timeout)
	defer cancel()

	wp := NewWorkerPool(config.MaxWorkers, results)
	dc := NewDirCache(config.DirCacheTTL)
	wp.Start(ctx, fileContentCache)

	// --- INÍCIO DO KEEP-ALIVE ---
	done := make(chan struct{})
	logger.Debug("[KEEP-ALIVE] Goroutine launched for share: %s", shareName)
	go func() {
		logger.Debug("[KEEP-ALIVE] Goroutine started for share: %s", shareName)
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		defer logger.Debug("[KEEP-ALIVE] Goroutine exiting for share: %s", shareName)
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				// Verificar novamente se done foi fechado antes de fazer Stat
				select {
				case <-done:
					return
				default:
					logger.Debug("[KEEP-ALIVE] Ticker triggered for share: %s", shareName)
					_, err := fs.Stat(".")
					if err != nil {
						logger.Debug("[KEEP-ALIVE] Error keeping SMB session alive: %v", err)
					} else {
						logger.Debug("[KEEP-ALIVE] SMB session kept alive successfully")
					}
				}
			}
		}
	}()
	// --- FIM DO KEEP-ALIVE ---
	defer close(done) // Parar keep-alive quando SearchShare terminar

	logger.Debug("[DEBUG] Starting recursive search in SearchShare at %s", startPath)
	err := searchDirectoryWithContext(ctx, fs, shareName, startPath, config, results, 0, wp, dc)

	logger.Debug("[DEBUG] Closing job channel after recursive search in SearchShare")
	close(wp.jobs)
	wp.wg.Wait()
	logger.Debug("[DEBUG] All workers finished in SearchShare for %s", shareName)

	// close(results)
	return err
}

// isSpecialShare checks if a share está na lista de exclusão configurável
func isSpecialShare(shareName string, excludedShares []string) bool {
	if len(excludedShares) == 0 {
		excludedShares = []string{"IPC$", "ADMIN$"}
	}
	for _, special := range excludedShares {
		if shareName == special {
			return true
		}
	}
	return false
}

// DiscoverAndSaveShares discovers SMB shares on a host and saves them to a temp file
func DiscoverAndSaveShares(host, username, password string) (string, error) {
	conn, err := net.DialTimeout("tcp", host+":445", 5*time.Second)
	if err != nil {
		return "", fmt.Errorf("failed to connect to SMB host: %v", err)
	}

	d := &smb2.Dialer{
		Initiator: &smb2.NTLMInitiator{
			User:     username,
			Password: password,
		},
	}
	s, err := d.Dial(conn)
	if err != nil {
		return "", fmt.Errorf("failed to negotiate SMB session: %v", err)
	}
	defer s.Logoff()

	names, err := s.ListSharenames()
	if err != nil {
		return "", fmt.Errorf("failed to list share names: %v", err)
	}

	// Create temporary file
	tmpFile, err := os.CreateTemp("", fmt.Sprintf("shares_%s_*.txt", host))
	if err != nil {
		return "", fmt.Errorf("failed to create temp file: %v", err)
	}
	defer tmpFile.Close()

	// Save each share in the format \\host\share
	for _, name := range names {
		shareLine := fmt.Sprintf("\\%s\\%s\n", host, name)
		_, err := tmpFile.WriteString(shareLine)
		if err != nil {
			return "", fmt.Errorf("failed to write to temp file: %v", err)
		}
	}

	return tmpFile.Name(), nil
}

// isPathWithinShare checks if a path is within the share root
// This prevents traversal outside the share into system directories
func isPathWithinShare(path string) bool {
	// Allow root directory
	if path == "." || path == "" {
		return true
	}

	// Normalize path to use forward slashes
	normalizedPath := filepath.ToSlash(path)

	// Check if path starts with a drive letter (Windows style)
	if len(normalizedPath) >= 2 && normalizedPath[1] == ':' {
		return false
	}

	// Check if path is absolute (starts with /)
	if strings.HasPrefix(normalizedPath, "/") {
		return false
	}

	// Check for directory traversal attempts
	if strings.Contains(normalizedPath, "../") || normalizedPath == ".." {
		return false
	}

	return true
}

// cleanSMBName limpa APENAS caracteres de controle realmente problemáticos
// Mantém o nome EXATAMENTE como vem do SMB para garantir correspondência
// Remove apenas null bytes e caracteres de controle que podem causar problemas de encoding
func cleanSMBName(name string) string {
	// Se vazio, retornar como está
	if name == "" {
		return name
	}

	// Remover APENAS null bytes (0x00) e caracteres de controle extremos
	// NÃO remover outros caracteres para manter correspondência com o servidor SMB
	var cleaned strings.Builder
	for _, r := range name {
		// Remover apenas null bytes e caracteres de controle extremos (0x00-0x08, 0x0B, 0x0C, 0x0E-0x1F)
		// Manter tab (0x09), newline (0x0A), carriage return (0x0D) e todos os outros caracteres
		if r == 0x00 || (r >= 0x01 && r <= 0x08) || r == 0x0B || r == 0x0C || (r >= 0x0E && r <= 0x1F) {
			continue // Pular apenas caracteres de controle extremos
		}

		// Manter TODOS os outros caracteres, incluindo espaços, acentos, ç, etc.
		// O SMB já validou esses caracteres, então devemos mantê-los
		cleaned.WriteRune(r)
	}

	result := cleaned.String()

	// Se ficou vazio após remover null bytes, retornar o original
	if result == "" {
		return name
	}

	return result
}

// joinSMBPath constrói um caminho SMB corretamente usando \ como separador
// e preservando o nome exatamente como vem do SMB (sem normalização que pode quebrar caracteres especiais)
func joinSMBPath(elem ...string) string {
	// Filtrar elementos vazios e limpar nomes
	parts := make([]string, 0, len(elem))
	for _, e := range elem {
		if e != "" && e != "." {
			// Limpar o nome antes de adicionar
			cleaned := cleanSMBName(e)
			if cleaned != "" && cleaned != "." {
				parts = append(parts, cleaned)
			}
		}
	}

	if len(parts) == 0 {
		return "."
	}

	// Se o primeiro elemento for ".", remover
	if parts[0] == "." {
		parts = parts[1:]
		if len(parts) == 0 {
			return "."
		}
	}

	// Juntar usando \ (separador SMB)
	result := strings.Join(parts, "\\")

	// Garantir que não comece com \ (caminhos relativos no SMB não devem começar com \)
	result = strings.TrimPrefix(result, "\\")

	// Se ficou vazio, retornar "."
	if result == "" {
		return "."
	}

	return result
}

// DirCache implementation
type DirCache struct {
	cache sync.Map
	ttl   time.Duration
}

type CacheEntry struct {
	entries []os.FileInfo
	expiry  time.Time
}

func NewDirCache(ttl time.Duration) *DirCache {
	return &DirCache{
		ttl: ttl,
	}
}

// CircuitBreaker implementation
type CircuitBreaker struct {
	failures  int32
	threshold int32
	timeout   time.Duration
	lastError time.Time
	mu        sync.RWMutex
}

func NewCircuitBreaker(threshold int32, timeout time.Duration) *CircuitBreaker {
	return &CircuitBreaker{
		threshold: threshold,
		timeout:   timeout,
	}
}

func (cb *CircuitBreaker) Execute(operation func() error) error {
	if !cb.canExecute() {
		return fmt.Errorf("circuit breaker is open")
	}

	err := operation()
	if err != nil {
		cb.recordFailure()
	}
	return err
}

func (cb *CircuitBreaker) canExecute() bool {
	cb.mu.RLock()
	defer cb.mu.RUnlock()

	if cb.failures >= cb.threshold {
		if time.Since(cb.lastError) > cb.timeout {
			cb.failures = 0
			return true
		}
		return false
	}
	return true
}

func (cb *CircuitBreaker) recordFailure() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.failures++
	cb.lastError = time.Now()
}

// Helper functions
func checkFilename(ctx context.Context, job *FileJob, results chan<- *SearchResult) {
	var filename string
	if job.config.CaseSensitive {
		filename = job.entry.Name()
	} else {
		filename = strings.ToLower(job.entry.Name())
	}

	for _, pattern := range job.config.FilenamePatterns {
		if strings.Contains(filename, pattern) {
			if !sendResultSafely(ctx, results, &SearchResult{
				ShareName:   normalizeShareName(job.shareName),
				FilePath:    job.filePath,
				MatchType:   "filename",
				MatchValue:  pattern,
				FileSize:    job.entry.Size(),
				IsDirectory: false,
			}) {
				// Contexto cancelado, parar
				return
			}
		}
	}
}

func checkLine(ctx context.Context, job *FileJob, line string, lineNum int, results chan<- *SearchResult) {
	// Check content patterns
	if job.config.SearchContents {
		for _, pattern := range job.config.ContentPatterns {
			var found bool
			if job.config.CaseSensitive {
				found = strings.Contains(line, pattern)
			} else {
				found = strings.Contains(
					strings.ToLower(line),
					strings.ToLower(pattern),
				)
			}

			if found {
				if !sendResultSafely(ctx, results, &SearchResult{
					ShareName:   normalizeShareName(job.shareName),
					FilePath:    job.filePath,
					MatchType:   "content",
					MatchValue:  fmt.Sprintf("%s (line %d)", pattern, lineNum),
					FileSize:    job.entry.Size(),
					IsDirectory: false,
				}) {
					// Contexto cancelado, parar
					return
				}
			}
		}
	}

	// Check regex patterns
	if job.config.SearchRegex {
		for _, regex := range job.config.RegexPatterns {
			matches := regex.FindAllString(line, -1)
			for _, match := range matches {
				if !sendResultSafely(ctx, results, &SearchResult{
					ShareName:   normalizeShareName(job.shareName),
					FilePath:    job.filePath,
					MatchType:   "regex",
					MatchValue:  fmt.Sprintf("%s (line %d)", match, lineNum),
					FileSize:    job.entry.Size(),
					IsDirectory: false,
					RegexMatch:  regex.String(),
				}) {
					// Contexto cancelado, parar
					return
				}
			}
		}
	}
}

func openFileWithTimeout(ctx context.Context, fs *smb2.Share, path string, timeout time.Duration) (io.ReadCloser, error) {
	fileChan := make(chan io.ReadCloser, 1)
	errChan := make(chan error, 1)

	go func() {
		file, err := fs.Open(path)
		if err != nil {
			errChan <- err
			return
		}
		fileChan <- file
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case err := <-errChan:
		return nil, err
	case file := <-fileChan:
		return file, nil
	case <-time.After(timeout):
		return nil, fmt.Errorf("timeout opening file %s", path)
	}
}

func aggregateErrors(errChan chan error) error {
	var errStrings []string
	seenErrors := make(map[string]bool)

	// Adicionar timeout para evitar travamento
	timeout := time.After(30 * time.Second)

	for {
		select {
		case err, ok := <-errChan:
			if !ok {
				// Canal fechado, sair
				goto done
			}
			if err != nil {
				errStr := err.Error()
				if !seenErrors[errStr] {
					seenErrors[errStr] = true
					errStrings = append(errStrings, errStr)
				}
			}
		case <-timeout:
			// Timeout para evitar travamento
			fmt.Printf("[WARN] Timeout waiting for errors. Proceeding with collected errors.\n")
			goto done
		}
	}

done:
	if len(errStrings) > 0 {
		return fmt.Errorf("multiple errors occurred: %s", strings.Join(errStrings, "; "))
	}
	return nil
}

// aggregateErrorsWithTimeout versão com timeout customizável
func aggregateErrorsWithTimeout(errChan chan error, timeoutDuration time.Duration) error {
	var errStrings []string
	seenErrors := make(map[string]bool)

	timeout := time.After(timeoutDuration)

	for {
		select {
		case err, ok := <-errChan:
			if !ok {
				// Canal fechado, sair
				goto done
			}
			if err != nil {
				errStr := err.Error()
				if !seenErrors[errStr] {
					seenErrors[errStr] = true
					errStrings = append(errStrings, errStr)
				}
			}
		case <-timeout:
			// Timeout para evitar travamento
			fmt.Printf("[WARN] Timeout waiting for errors after %v. Proceeding with collected errors.\n", timeoutDuration)
			goto done
		}
	}

done:
	if len(errStrings) > 0 {
		return fmt.Errorf("multiple errors occurred: %s", strings.Join(errStrings, "; "))
	}
	return nil
}

var excludedDirs = []string{
	"windows", "$windows.~bt", "system volume information", "program files", "programdata", "recycle.bin", "$Recycle.Bin", "Program Files (x86)", "Program Files", "$WinREAgent", "PerfLogs",
}

func shouldExcludeDir(dirName string) bool {
	dirName = strings.ToLower(dirName)
	for _, excl := range excludedDirs {
		if dirName == excl {
			return true
		}
	}
	return false
}

// Cache local por share para evitar reprocessamento
var processedDirs = make(map[string]map[string]bool)
var failedDirs = make(map[string]map[string]bool) // Cache para diretórios que falharam
var processedDirsMutex sync.RWMutex

// searchDirectoryWithContext recursively searches a directory for files matching the search criteria
// with context for timeout and depth tracking
func searchDirectoryWithContext(ctx context.Context, fs *smb2.Share, shareName, dirPath string, config *SearchConfig, results chan<- *SearchResult, depth int, wp *WorkerPool, dc *DirCache) error {
	// Normalizar o caminho para usar \ (separador SMB) em vez de / (separador do sistema)
	// Isso garante que caminhos com caracteres especiais sejam tratados corretamente
	if dirPath != "." && dirPath != "" {
		dirPath = strings.ReplaceAll(dirPath, "/", "\\")
		// Remover barras duplicadas
		for strings.Contains(dirPath, "\\\\") {
			dirPath = strings.ReplaceAll(dirPath, "\\\\", "\\")
		}
		// Remover barra inicial se houver (caminhos relativos no SMB não devem começar com \)
		dirPath = strings.TrimPrefix(dirPath, "\\")
		if dirPath == "" {
			dirPath = "."
		}
	}

	// Cache local por share: evitar reprocessamento
	processedDirsMutex.RLock()
	if _, exists := processedDirs[shareName]; exists {
		if processedDirs[shareName][dirPath] {
			processedDirsMutex.RUnlock()
			return nil // Já processado
		}
	}
	// Verificar se já falhou antes
	if _, exists := failedDirs[shareName]; exists {
		if failedDirs[shareName][dirPath] {
			processedDirsMutex.RUnlock()
			return nil // Já falhou antes, não tentar novamente
		}
	}
	processedDirsMutex.RUnlock()

	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	if depth > config.MaxDepth {
		return nil
	}

	if config.RestrictToShareRoot && !isPathWithinShare(dirPath) {
		return nil
	}

	// Try to get from cache first
	if entries, ok := dc.Get(dirPath); ok {
		// Marcar como processado apenas após sucesso
		processedDirsMutex.Lock()
		if processedDirs[shareName] == nil {
			processedDirs[shareName] = make(map[string]bool)
		}
		processedDirs[shareName][dirPath] = true
		processedDirsMutex.Unlock()

		return processEntries(ctx, fs, shareName, dirPath, entries, config, results, depth, wp, dc)
	}

	// Read directory with retry
	var entries []os.FileInfo
	var lastErr error
	var consecutiveTimeouts int

	for attempt := 1; attempt <= 3; attempt++ {
		entriesChan := make(chan []os.FileInfo, 1)
		errChan := make(chan error, 1)
		go func() {
			// Use Open and Readdir loop instead of ReadDir to avoid blocking for too long
			// and to better handle large directories
			f, err := fs.Open(dirPath)
			if err != nil {
				errChan <- fmt.Errorf("failed to open directory %s: %v", dirPath, err)
				return
			}
			defer f.Close()

			var allEntries []os.FileInfo
			batchSize := 1000

			for {
				select {
				case <-ctx.Done():
					errChan <- ctx.Err()
					return
				default:
				}

				batch, err := f.Readdir(batchSize)
				if len(batch) > 0 {
					allEntries = append(allEntries, batch...)
					// Delay com randomização para evitar detecção de padrão
					randomExtra := time.Duration(rand.Intn(200)) * time.Millisecond
					time.Sleep(config.OperationDelay + randomExtra)
				}
				if err != nil {
					if err == io.EOF {
						break
					}
					errChan <- fmt.Errorf("failed to read directory batch %s: %v", dirPath, err)
					return
				}
			}

			// Sort entries to ensure consistent order (match ReadDir behavior)
			sort.Slice(allEntries, func(i, j int) bool { return allEntries[i].Name() < allEntries[j].Name() })
			entriesChan <- allEntries
		}()

		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-errChan:
			lastErr = err
			consecutiveTimeouts = 0 // Reset timeout counter on non-timeout error

			// Verificar se é erro "invalid parameter" - pode ser caso especial
			errStr := err.Error()
			isInvalidParameter := strings.Contains(errStr, "invalid parameter") ||
				strings.Contains(errStr, "STATUS_INVALID_PARAMETER") ||
				strings.Contains(errStr, "An invalid parameter was passed")

			if isInvalidParameter {
				// Caso especial: diretório com mesmo nome do share (ex: share TI, diretório TI)
				// Extrair nome do share
				shareNameOnly := shareName
				if strings.Contains(shareName, "\\") {
					parts := strings.Split(shareName, "\\")
					if len(parts) > 0 {
						shareNameOnly = parts[len(parts)-1]
					}
				}

				// Se o diretório tem o mesmo nome do share, pode ser problema de path
				if strings.EqualFold(dirPath, shareNameOnly) {
					if config.Verbose {
						fmt.Printf("[WARN] Directory %s matches share name, trying workaround...\n", dirPath)
					}

					// Tentar com retry (pode funcionar na segunda tentativa)
					if attempt < 3 {
						time.Sleep(time.Duration(attempt*2) * time.Second)
						continue
					}
				}

				// Se não é caso especial ou já tentou 3x, pular
				if config.Verbose {
					fmt.Printf("[WARN] Directory %s: %v (skipping - invalid parameter error)\n", dirPath, err)
				}
				processedDirsMutex.Lock()
				if failedDirs[shareName] == nil {
					failedDirs[shareName] = make(map[string]bool)
				}
				failedDirs[shareName][dirPath] = true
				processedDirsMutex.Unlock()
				return nil // Retorna nil para continuar processamento sem erro fatal
			}

			if attempt < 3 {
				if config.Verbose {
					fmt.Printf("[WARN] Directory listing attempt %d failed: %v. Retrying in 2 seconds...\n", attempt, err)
				}
				time.Sleep(2 * time.Second)
				continue
			}
			return err
		case entries = <-entriesChan:
			dc.Set(dirPath, entries) // Store in cache
			// Marcar como processado apenas após sucesso
			processedDirsMutex.Lock()
			if processedDirs[shareName] == nil {
				processedDirs[shareName] = make(map[string]bool)
			}
			processedDirs[shareName][dirPath] = true
			processedDirsMutex.Unlock()
			goto done
		case <-time.After(30 * time.Second):
			consecutiveTimeouts++
			lastErr = fmt.Errorf("timeout reading directory %s", dirPath)

			// Se for o diretório raiz e tiver muitos timeouts consecutivos, parar
			if dirPath == "." && consecutiveTimeouts >= 2 {
				fmt.Printf("[ERROR] Directory %s is consistently timing out. Skipping to avoid infinite loop.\n", dirPath)
				// Marcar como falhou para não tentar novamente
				processedDirsMutex.Lock()
				if failedDirs[shareName] == nil {
					failedDirs[shareName] = make(map[string]bool)
				}
				failedDirs[shareName][dirPath] = true
				processedDirsMutex.Unlock()
				return fmt.Errorf("directory %s consistently timing out", dirPath)
			}

			if attempt < 3 {
				if config.Verbose {
					fmt.Printf("[WARN] Directory listing attempt %d timed out. Retrying in 2 seconds...\n", attempt)
				}
				time.Sleep(2 * time.Second)
				continue
			}
			return lastErr
		}
	}
done:
	if entries == nil {
		return lastErr
	}

	return processEntries(ctx, fs, shareName, dirPath, entries, config, results, depth, wp, dc)
}

// sendResultSafely envia um resultado para o canal de forma segura, verificando se o contexto foi cancelado
// e capturando panic caso o canal esteja fechado
func sendResultSafely(ctx context.Context, results chan<- *SearchResult, result *SearchResult) bool {
	// Verificar se o contexto foi cancelado primeiro
	select {
	case <-ctx.Done():
		// Contexto cancelado, não enviar
		return false
	default:
		// Contexto ainda ativo, tentar enviar
	}

	// Tentar enviar com proteção contra panic (canal fechado)
	var success bool
	func() {
		defer func() {
			if r := recover(); r != nil {
				// Panic capturado - canal provavelmente fechado
				success = false
			}
		}()

		select {
		case <-ctx.Done():
			// Contexto cancelado durante a tentativa
			success = false
		case results <- result:
			// Enviado com sucesso
			success = true
		}
	}()

	return success
}

func processEntries(ctx context.Context, fs *smb2.Share, shareName, dirPath string, entries []os.FileInfo, config *SearchConfig, results chan<- *SearchResult, depth int, wp *WorkerPool, dc *DirCache) error {
	logger.Debug("[DEBUG] processEntries: %d entradas em %s", len(entries), dirPath)
	var wg sync.WaitGroup
	errChan := make(chan error, len(entries))

EntryLoop:
	for _, entry := range entries {
		select {
		case <-ctx.Done():
			logger.Debug("[DEBUG] processEntries: ctx.Done() in %s", dirPath)
			break EntryLoop // Break loop to wait for children
		default:
		}

		entryPath := joinSMBPath(dirPath, entry.Name())

		// Checagem de exclusão de arquivos (flag -exclude)
		if shouldExcludeFile(entryPath, config) {
			logger.Debug("[DEBUG] Excluding file by default: %s", entryPath)
			continue
		}

		if shouldExcludeDir(entry.Name()) {
			logger.Debug("[DEBUG] Skipping excluded directory: %s", entry.Name())
			continue
		}

		if entry.IsDir() {
			logger.Debug("[DEBUG] Found directory: %s", entryPath)
			if config.Verbose {
				if !sendResultSafely(ctx, results, &SearchResult{
					ShareName:   normalizeShareName(shareName),
					FilePath:    entryPath,
					MatchType:   "directory",
					MatchValue:  "",
					FileSize:    0,
					IsDirectory: true,
				}) {
					// Contexto cancelado, parar processamento
					break EntryLoop
				}
			}

			// Filtro por data de modificação
			if !config.MinDate.IsZero() && entry.ModTime().Before(config.MinDate) {
				continue
			}
			if !config.MaxDate.IsZero() && entry.ModTime().After(config.MaxDate) {
				continue
			}

			wg.Add(1)
			go func(path string) {
				defer wg.Done()
				logger.Debug("[DEBUG] Recursion in directory: %s", path)
				if err := searchDirectoryWithContext(ctx, fs, shareName, path, config, results, depth+1, wp, dc); err != nil {
					errChan <- err
				}
			}(entryPath)
		} else {
			logger.Debug("[DEBUG] Sending job to worker pool: %s", entryPath)
			// Flag para controlar se já houve match (para evitar reportar como large file depois)
			matched := false

			// Verificar match por extensão primeiro
			if len(config.FileExtensions) > 0 {
				ext := strings.ToLower(filepath.Ext(entry.Name()))
				if !strings.HasPrefix(ext, ".") {
					ext = "." + ext
				}
				for _, allowedExt := range config.FileExtensions {
					if !strings.HasPrefix(allowedExt, ".") {
						allowedExt = "." + allowedExt
					}
					if strings.EqualFold(ext, allowedExt) {
						if !sendResultSafely(ctx, results, &SearchResult{
							ShareName:   normalizeShareName(shareName),
							FilePath:    entryPath,
							MatchType:   "extension",
							MatchValue:  ext,
							FileSize:    entry.Size(),
							IsDirectory: false,
						}) {
							// Contexto cancelado, parar processamento
							break EntryLoop
						}
						matched = true
						break
					}
				}
			}

			if matched {
				continue
			}

			// Se o arquivo for grande, aplica filtro se necessário
			if entry.Size() > config.MaxFileSize {
				addLargeFile := true
				if config.FilterLargeFiles {
					addLargeFile = false
					// Verifica extensão (suporta múltiplas extensões como .env.prod)
					if len(config.FileExtensions) > 0 {
						if matchesAnyExtension(entry.Name(), config.FileExtensions) {
							addLargeFile = true
						}
					}
					// Verifica padrões de nome
					if !addLargeFile && len(config.FilenamePatterns) > 0 {
						for _, pattern := range config.FilenamePatterns {
							if strings.Contains(entry.Name(), pattern) {
								addLargeFile = true
								break
							}
						}
					}
				}
				if addLargeFile {
					if !sendResultSafely(ctx, results, &SearchResult{
						ShareName:   normalizeShareName(shareName),
						FilePath:    entryPath,
						MatchType:   "large_file",
						MatchValue:  fmt.Sprintf("Large file: %.2f MB", float64(entry.Size())/(1024*1024)),
						FileSize:    entry.Size(),
						IsDirectory: false,
					}) {
						// Contexto cancelado, parar processamento
						break EntryLoop
					}
				}
				continue
			}

			// Filtro por data de modificação
			if !config.MinDate.IsZero() && entry.ModTime().Before(config.MinDate) {
				continue
			}
			if !config.MaxDate.IsZero() && entry.ModTime().After(config.MaxDate) {
				continue
			}

			// Processa o arquivo para outros tipos de match
			logger.Debug("[DEBUG] Sending job to worker pool: %s", entryPath)
			select {
			case <-ctx.Done():
				break EntryLoop
			case wp.jobs <- &FileJob{
				fs:        fs,
				shareName: shareName,
				filePath:  entryPath,
				entry:     entry,
				config:    config,
			}:
			}
		}
	}

	wg.Wait()
	// NÃO feche o canal errChan aqui!
	var firstErr error
	for {
		select {
		case err := <-errChan:
			if err != nil && firstErr == nil {
				firstErr = err
			}
		default:
			// Canal vazio, pode sair
			return firstErr
		}
	}
}

// SearchMultipleShares searches multiple shares concurrently (Legacy: assumes root path)
func SearchMultipleShares(fs map[string]*smb2.Share, config *SearchConfig, fileContentCache *scanner.FileContentCache) ([]*SearchResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), config.Timeout)
	defer cancel()

	resultsChan := make(chan *SearchResult, 1000)
	wp := NewWorkerPool(config.MaxWorkers, resultsChan)
	cb := NewCircuitBreaker(5, time.Minute)

	wp.Start(ctx, fileContentCache)

	var wg sync.WaitGroup
	errChan := make(chan error, len(fs))

	for shareName, share := range fs {
		if config.SkipSpecialShares && isSpecialShare(shareName, config.ExcludedShares) {
			logger.Debug("Skipping special share: %s", shareName)
			continue
		}

		wg.Add(1)
		go func(name string, fs *smb2.Share) {
			defer wg.Done()

			err := cb.Execute(func() error {
				return SearchShare(fs, name, ".", config, resultsChan, fileContentCache)
			})

			if err != nil {
				if config.Verbose {
					logger.Debug("Failed to search share %s: %v", name, err)
				}
				errChan <- err
			}
		}(shareName, share)
	}

	// Fechar o canal de resultados só depois de todas as goroutines terminarem
	go func() {
		wg.Wait()
		logger.Debug("[DEBUG] Closing results and error channels in SearchMultipleShares")
		close(resultsChan)
		close(errChan)
	}()

	var results []*SearchResult
	for result := range resultsChan {
		results = append(results, result)
	}

	return results, aggregateErrors(errChan)
}

// Versão que acumula mensagens no slice messages (Legacy: assumes root path)
func SearchMultipleSharesWithMessages(fs map[string]*smb2.Share, config *SearchConfig, fileContentCache *scanner.FileContentCache, messages *[]string) ([]*SearchResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), config.Timeout)
	defer cancel()

	resultsChan := make(chan *SearchResult, 1000)
	wp := NewWorkerPool(config.MaxWorkers, resultsChan)
	cb := NewCircuitBreaker(5, time.Minute)

	wp.Start(ctx, fileContentCache)

	var wg sync.WaitGroup
	errChan := make(chan error, len(fs))

	for shareName, share := range fs {
		if config.SkipSpecialShares && isSpecialShare(shareName, config.ExcludedShares) {
			logger.Debug("Skipping special share: %s", shareName)
			continue
		}

		wg.Add(1)
		go func(name string, fs *smb2.Share) {
			defer wg.Done()

			err := cb.Execute(func() error {
				return SearchShare(fs, name, ".", config, resultsChan, fileContentCache)
			})

			if err != nil {
				if config.Verbose {
					logger.Debug("Failed to search share %s: %v", name, err)
				} else if messages != nil {
					*messages = append(*messages, fmt.Sprintf("[-] Failed to search share %s: %v", name, err))
				}
				errChan <- err
			}
		}(shareName, share)
	}

	// Fechar o canal de resultados só depois de todas as goroutines terminarem
	go func() {
		wg.Wait()
		logger.Debug("[DEBUG] Closing results and error channels in SearchMultipleSharesWithMessages")
		close(resultsChan)
		close(errChan)
	}()

	var results []*SearchResult
	for result := range resultsChan {
		results = append(results, result)
	}

	return results, aggregateErrors(errChan)
}

// LoadPatternsFromFile loads search patterns from a file
func LoadPatternsFromFile(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to open patterns file: %v", err)
	}
	defer file.Close()

	var patterns []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" && !strings.HasPrefix(line, "#") {
			patterns = append(patterns, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("error reading patterns file: %v", err)
	}

	return patterns, nil
}

func DiscoverShares(host, username, password string, config *SearchConfig) (map[string]*smb2.Share, error) {
	conn, err := net.DialTimeout("tcp", host+":445", 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to SMB host: %v", err)
	}

	d := &smb2.Dialer{
		Initiator: &smb2.NTLMInitiator{
			User:     username,
			Password: password,
		},
	}
	s, err := d.Dial(conn)
	if err != nil {
		return nil, fmt.Errorf("failed to negotiate SMB session: %v", err)
	}

	names, err := s.ListSharenames()
	if err != nil {
		return nil, fmt.Errorf("failed to list share names: %v", err)
	}

	shares := make(map[string]*smb2.Share)
	for _, name := range names {
		share, err := s.Mount(name)
		if err != nil {
			if config != nil && config.Verbose {
				logger.Debug("Failed to mount share %s: %v", name, err)
			}
			continue
		}
		shares[name] = share
	}
	return shares, nil
}

func MountShares(session *smb2.Session, shareNames []string, config *SearchConfig) map[string]*smb2.Share {
	shares := make(map[string]*smb2.Share)
	for _, name := range shareNames {
		share, err := session.Mount(name)
		if err != nil {
			if config != nil && config.Verbose {
				logger.Debug("Failed to mount share %s: %v", name, err)
			}
			continue
		}
		shares[name] = share
	}
	return shares
}

const maxCacheFileSize = 1024 * 1024 // 1MB

func processFile(ctx context.Context, job *FileJob, results chan<- *SearchResult, fileContentCache *scanner.FileContentCache) {
	// Primeiro verificar nome do arquivo e extensão
	if job.config.SearchFilenames {
		checkFilename(ctx, job, results)
	}

	// Se não vamos buscar conteúdo ou regex, retornar aqui
	if !job.config.SearchContents && !job.config.SearchRegex {
		return
	}

	// Se o arquivo for muito grande, não processar
	if job.entry.Size() > job.config.MaxFileSize {
		if job.config.ExtraVerbose {
			logger.Debug("[DEBUG] File too large to process: %s (%d bytes)", job.filePath, job.entry.Size())
		}
		return
	}

	// --- NOVA LÓGICA DE CACHE DE CONTEÚDO COMPLETO ---
	var file io.ReadCloser
	var header []byte
	var err error
	var fileScanner scanner.FileScanner
	var fileInfo os.FileInfo
	var statErr error
	contentKey := job.filePath + ":content"
	fileInfo, statErr = job.fs.Stat(job.filePath)
	if statErr == nil && fileInfo.Size() <= maxCacheFileSize {
		if cached, ok := fileContentCache.Get(contentKey); ok {
			file = &readSeekCloser{bytes.NewReader(cached)}
			header = cached
			// Processa o tipo de arquivo normalmente
			// Check if it's ZIP/DOCX/XLSX
			if len(header) > 4 && header[0] == 0x50 && header[1] == 0x4B && header[2] == 0x03 && header[3] == 0x04 {
				if scanner.IsOfficeFile(header) {
					if job.config.ExtraVerbose {
						logger.Debug("[DEBUG] Office file detected: %s", job.filePath)
					}
					fileScanner = scanner.NewOfficeScanner(file)
				} else {
					if job.config.ExtraVerbose {
						logger.Debug("[DEBUG] ZIP file detected: %s", job.filePath)
					}
					fileScanner = scanner.NewZipScanner(file)
				}
			} else if scanner.IsPDF(header) {
				fileScanner = scanner.NewPDFScanner(file)
			} else if scanner.IsWebFile(header) {
				fileScanner = scanner.NewWebScanner(file)
			} else {
				isText := true
				for _, b := range header[:min(len(header), 512)] {
					if b < 7 || b == 0xFF {
						isText = false
						break
					}
				}
				if isText {
					bufScanner := bufio.NewScanner(file)
					bufScanner.Buffer(make([]byte, job.config.BufferSize), job.config.BufferSize)
					for bufScanner.Scan() {
						select {
						case <-ctx.Done():
							return
						default:
							checkContent(ctx, job, bufScanner.Text(), results)
						}
					}
					err = bufScanner.Err()
					if err != nil && job.config.ExtraVerbose {
						fmt.Printf("[DEBUG] Error processing file %s: %v\n", job.filePath, err)
					}
					return
				} else {
					if job.config.SearchBinary {
						fileScanner = scanner.NewBinaryScanner(file, job.config.MinBinaryStringLen)
					} else {
						if job.config.ExtraVerbose {
							logger.Debug("[DEBUG] Skipping binary file (search in binary disabled): %s", job.filePath)
						}
						return
					}
				}
			}
			if fileScanner != nil {
				err = fileScanner.Scan(func(content string) error {
					checkContent(ctx, job, content, results)
					return nil
				})
				if err != nil && job.config.ExtraVerbose {
					fmt.Printf("[DEBUG] Error processing file %s: %v\n", job.filePath, err)
				}
			}
			return
		}
	}

	// Abrir e processar o arquivo normalmente
	// (mantém lógica de cache de header para arquivos grandes)
	var headerKey = job.filePath + ":header"
	if cached, ok := fileContentCache.Get(headerKey); ok {
		header = cached
		file, err = openFileWithTimeout(ctx, job.fs, job.filePath, job.config.Timeout)
		if err != nil {
			if job.config.ExtraVerbose {
				logger.Debug("[DEBUG] Error opening file %s: %v", job.filePath, err)
			}
			return
		}
		// Avança o ponteiro do arquivo após o header
		if seeker, ok := file.(io.Seeker); ok {
			seeker.Seek(int64(len(header)), 0)
		} else {
			file = &readSeekCloser{bytes.NewReader(header)}
		}
	} else {
		file, err = openFileWithTimeout(ctx, job.fs, job.filePath, job.config.Timeout)
		if err != nil {
			if job.config.ExtraVerbose {
				logger.Debug("[DEBUG] Error opening file %s: %v", job.filePath, err)
			}
			return
		}
		header = make([]byte, 8192)
		n, err := file.Read(header)
		if err != nil && err != io.EOF {
			if job.config.ExtraVerbose {
				logger.Debug("[DEBUG] Error reading file header %s: %v", job.filePath, err)
			}
			return
		}
		header = header[:n]
		fileContentCache.Set(headerKey, header)
		// Retorna ao início do arquivo
		if seeker, ok := file.(io.Seeker); ok {
			seeker.Seek(0, 0)
		} else {
			file = &readSeekCloser{bytes.NewReader(header)}
		}
	}

	// Se o arquivo for pequeno, lê e armazena o conteúdo completo no cache
	if statErr == nil && fileInfo.Size() <= maxCacheFileSize {
		content, err := io.ReadAll(file)
		if err != nil {
			if job.config.ExtraVerbose {
				logger.Debug("[DEBUG] Error reading file %s: %v", job.filePath, err)
			}
			return
		}
		if len(content) == 0 {
			if job.config.ExtraVerbose {
				logger.Debug("[DEBUG] File %s is empty, skipping.", job.filePath)
			}
			return
		}
		fileContentCache.Set(contentKey, content)
		file = &readSeekCloser{bytes.NewReader(content)}
		header = content
	}

	// Process the file based on its type
	// Check if it's ZIP/DOCX/XLSX
	if len(header) > 4 && header[0] == 0x50 && header[1] == 0x4B && header[2] == 0x03 && header[3] == 0x04 {
		if scanner.IsOfficeFile(header) {
			if job.config.ExtraVerbose {
				logger.Debug("[DEBUG] Office file detected: %s", job.filePath)
			}
			fileScanner = scanner.NewOfficeScanner(file)
		} else {
			if job.config.ExtraVerbose {
				logger.Debug("[DEBUG] ZIP file detected: %s", job.filePath)
			}
			fileScanner = scanner.NewZipScanner(file)
		}
	}

	// If not ZIP/Office, check other types
	if fileScanner == nil {
		if scanner.IsPDF(header) {
			fileScanner = scanner.NewPDFScanner(file)
		} else if scanner.IsWebFile(header) {
			fileScanner = scanner.NewWebScanner(file)
		} else {
			// Verifica se é texto
			isText := true
			for _, b := range header[:min(len(header), 512)] {
				if b < 7 || b == 0xFF {
					isText = false
					break
				}
			}

			if isText {
				bufScanner := bufio.NewScanner(file)
				bufScanner.Buffer(make([]byte, job.config.BufferSize), job.config.BufferSize)

				for bufScanner.Scan() {
					select {
					case <-ctx.Done():
						return
					default:
						checkContent(ctx, job, bufScanner.Text(), results)
					}
				}
				err = bufScanner.Err()
				if err != nil && job.config.ExtraVerbose {
					fmt.Printf("[DEBUG] Error processing file %s: %v\n", job.filePath, err)
				}
				return
			} else {
				// Só processa binário se SearchBinary estiver habilitado
				if job.config.SearchBinary {
					fileScanner = scanner.NewBinaryScanner(file, job.config.MinBinaryStringLen)
				} else {
					if job.config.ExtraVerbose {
						logger.Debug("[DEBUG] Skipping binary file (search in binary disabled): %s", job.filePath)
					}
					return
				}
			}
		}
	}

	// Usa o scanner apropriado
	err = fileScanner.Scan(func(content string) error {
		checkContent(ctx, job, content, results)
		return nil
	})

	if err != nil && job.config.ExtraVerbose {
		fmt.Printf("[DEBUG] Error processing file %s: %v\n", job.filePath, err)
	}
}

func checkContent(ctx context.Context, job *FileJob, content string, results chan<- *SearchResult) {
	if job.config.SearchContents {
		for _, pattern := range job.config.ContentPatterns {
			var found bool
			if job.config.CaseSensitive {
				found = strings.Contains(content, pattern)
			} else {
				found = strings.Contains(
					strings.ToLower(content),
					strings.ToLower(pattern),
				)
			}

			if found {
				if !sendResultSafely(ctx, results, &SearchResult{
					ShareName:   normalizeShareName(job.shareName),
					FilePath:    job.filePath,
					MatchType:   "content",
					MatchValue:  pattern,
					FileSize:    job.entry.Size(),
					IsDirectory: false,
				}) {
					// Contexto cancelado, parar
					return
				}
			}
		}
	}

	if job.config.SearchRegex {
		for _, regex := range job.config.RegexPatterns {
			match := regex.FindString(content)
			if match != "" {
				if !sendResultSafely(ctx, results, &SearchResult{
					ShareName:   normalizeShareName(job.shareName),
					FilePath:    job.filePath,
					MatchType:   "regex",
					MatchValue:  match,
					FileSize:    job.entry.Size(),
					IsDirectory: false,
					RegexMatch:  regex.String(),
				}) {
					// Contexto cancelado, parar
					return
				}
			}
		}
	}
}

// Pool de buffers para reutilização
var bufferPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, 0, 1024*1024)
		return &b
	},
}

func (dc *DirCache) Get(path string) ([]os.FileInfo, bool) {
	if entry, ok := dc.cache.Load(path); ok {
		cacheEntry := entry.(CacheEntry)
		if time.Now().Before(cacheEntry.expiry) {
			return cacheEntry.entries, true
		}
		dc.cache.Delete(path)
	}
	return nil, false
}

func (dc *DirCache) Set(path string, entries []os.FileInfo) {
	dc.cache.Store(path, CacheEntry{
		entries: entries,
		expiry:  time.Now().Add(dc.ttl),
	})
}

// FileTypeCache armazena os tipos de arquivo detectados
type FileTypeCache struct {
	cache sync.Map
}

// detectFileTypeWithCache detecta o tipo do arquivo usando cache
func (wp *WorkerPool) detectFileTypeWithCache(filePath string, header []byte) string {
	// Verifica no cache primeiro
	if cachedType, ok := wp.fileTypeCache.Load(filePath); ok {
		return cachedType.(string)
	}

	// Detecta o tipo
	fileType := detectFileType(header)

	// Armazena no cache
	wp.fileTypeCache.Store(filePath, fileType)

	return fileType
}

// Expande a detecção de tipos de arquivo
func detectFileType(header []byte) string {
	if len(header) < 8 {
		return "unknown"
	}

	// ZIP/Office
	if header[0] == 0x50 && header[1] == 0x4B && header[2] == 0x03 && header[3] == 0x04 {
		return "zip"
	}

	// PDF
	if bytes.HasPrefix(header, []byte("%PDF-")) {
		return "pdf"
	}

	// SQLite
	if bytes.HasPrefix(header, []byte("SQLite format")) {
		return "sqlite"
	}

	// Executáveis
	if bytes.HasPrefix(header, []byte("MZ")) {
		return "exe"
	}

	// Imagens
	if bytes.HasPrefix(header, []byte("\xFF\xD8\xFF")) {
		return "jpeg"
	}
	if bytes.HasPrefix(header, []byte("\x89PNG\r\n\x1a\n")) {
		return "png"
	}
	if bytes.HasPrefix(header, []byte("GIF87a")) || bytes.HasPrefix(header, []byte("GIF89a")) {
		return "gif"
	}

	// Arquivos compactados
	if bytes.HasPrefix(header, []byte("\x1F\x8B\x08")) {
		return "gzip"
	}
	if bytes.HasPrefix(header, []byte("BZh")) {
		return "bzip2"
	}
	if bytes.HasPrefix(header, []byte("\x37\x7A\xBC\xAF\x27\x1C")) {
		return "7zip"
	}

	// Verifica conteúdo web
	if scanner.IsWebFile(header) {
		return "web"
	}

	// Verifica se é texto
	isText := true
	for _, b := range header[:min(len(header), 512)] {
		if b < 7 || b == 0xFF {
			isText = false
			break
		}
	}

	if isText {
		return "text"
	}

	return "binary"
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Função utilitária para padronizar o nome do share
func normalizeShareName(shareName string) string {
	shareName = strings.ReplaceAll(shareName, "/", "\\")
	if !strings.HasPrefix(shareName, "\\") {
		shareName = "\\" + shareName
	}
	if !strings.HasPrefix(shareName, "\\\\") {
		shareName = "\\" + shareName
	}
	return shareName
}

// readSeekCloser é um wrapper para bytes.Reader que implementa io.ReadCloser e io.Seeker
// para compatibilidade com scanners que exigem io.Seeker
type readSeekCloser struct {
	*bytes.Reader
}

func (r *readSeekCloser) Close() error { return nil }

// matchesAnyExtension verifica se o arquivo corresponde a qualquer extensão fornecida
// Suporta múltiplas extensões como .env.prod, .config.json, etc.
func matchesAnyExtension(filename string, extensions []string) bool {
	if len(extensions) == 0 {
		return true
	}

	filenameLower := strings.ToLower(filename)

	// Dividir o nome do arquivo por pontos para pegar todas as extensões
	// Ex: "config.env.prod" -> ["config", "env", "prod"]
	parts := strings.Split(filenameLower, ".")

	for _, ext := range extensions {
		extLower := strings.ToLower(ext)
		// Remover ponto inicial se houver
		extLower = strings.TrimPrefix(extLower, ".")

		// Verificar se o arquivo termina com esta extensão
		if strings.HasSuffix(filenameLower, "."+extLower) {
			return true
		}

		// Verificar se alguma das partes do arquivo corresponde à extensão
		for _, part := range parts {
			if part == extLower {
				return true
			}
		}
	}

	return false
}

// shouldExcludeFile verifica se o arquivo deve ser excluído com base nos padrões de exclusão
func shouldExcludeFile(path string, config *SearchConfig) bool {
	if len(config.ExcludePatterns) == 0 {
		return false
	}
	filename := strings.ToLower(filepath.Base(path))
	for _, pattern := range config.ExcludePatterns {
		pattern = strings.ToLower(strings.TrimSpace(pattern))
		if pattern == "" {
			continue
		}
		if strings.HasPrefix(pattern, ".") {
			// Excluir por extensão
			if strings.HasSuffix(filename, pattern) {
				return true
			}
		} else if strings.Contains(filename, pattern) {
			// Excluir por substring
			return true
		}
	}
	return false
}

// SearchMultipleSharesStream faz busca em múltiplos shares e envia resultados em tempo real para o canal
func SearchMultipleSharesStream(fs map[string]*MountedShare, config *SearchConfig, fileContentCache *scanner.FileContentCache, resultsChan chan<- *SearchResult) error {
	ctx, cancel := context.WithTimeout(context.Background(), config.Timeout)
	defer cancel()

	wp := NewWorkerPool(config.MaxWorkers, resultsChan)
	cb := NewCircuitBreaker(5, time.Minute)

	wp.Start(ctx, fileContentCache)

	var wg sync.WaitGroup
	errChan := make(chan error, len(fs))
	timeoutCount := 0
	var errChanMutex sync.Mutex
	errChanClosed := false

	for shareName, shareInfo := range fs {
		if config.SkipSpecialShares && isSpecialShare(shareName, config.ExcludedShares) {
			logger.Debug("Skipping special share: %s", shareName)
			continue
		}

		wg.Add(1)
		go func(name string, ms *MountedShare) {
			defer wg.Done()

			err := cb.Execute(func() error {
				return SearchShare(ms.Share, name, ms.StartPath, config, resultsChan, fileContentCache)
			})

			if err != nil {
				if config.Verbose {
					logger.Debug("Failed to search share %s: %v", name, err)
				}
				// Contar timeouts consecutivos
				if strings.Contains(err.Error(), "directory . consistently timing out") {
					timeoutCount++
				}

				// Proteger envio no canal
				errChanMutex.Lock()
				if !errChanClosed {
					select {
					case errChan <- err:
					default:
						// Canal cheio, ignorar erro
					}
				}
				errChanMutex.Unlock()
			}
		}(shareName, shareInfo)
	}

	// Aguardar com timeout para evitar travamento
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		logger.Debug("[DEBUG] All shares finished, closing error channel")
	case <-time.After(5 * time.Minute):
		logger.Debug("[DEBUG] Timeout waiting for shares to finish, forcing exit")
	}

	// Fechar errChan exatamente uma vez
	errChanMutex.Lock()
	if !errChanClosed {
		close(errChan)
		errChanClosed = true
	}
	errChanMutex.Unlock()

	// NÃO fechar resultsChan aqui - ele é fechado pelo chamador

	// Se há muitos timeouts, retornar erro simples
	if timeoutCount >= 3 {
		return fmt.Errorf("multiple shares timing out on host")
	}

	// aggregateErrorsWithTimeout lê do canal já fechado
	return aggregateErrorsWithTimeout(errChan, 10*time.Second)
}
