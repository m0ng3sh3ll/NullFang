package copy

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/m0ng3sh3ll/NullFang/auth"
	"github.com/m0ng3sh3ll/NullFang/database"
	"github.com/m0ng3sh3ll/NullFang/go-smb2-patch"
	"github.com/m0ng3sh3ll/NullFang/logger"
	"github.com/m0ng3sh3ll/NullFang/search"
	"github.com/m0ng3sh3ll/NullFang/smb"
)

// CopyConfig holds the configuration for file copying
type CopyConfig struct {
	// Base directory to save copied files
	OutputDir string

	// Organize files by share name
	OrganizeByShare bool

	// Organize files by match type (filename, content, regex)
	OrganizeByMatchType bool

	// Preserve directory structure from source
	PreserveStructure bool

	// Add timestamp to output directory
	AddTimestamp bool

	// Verbose output
	Verbose bool

	// User information for logging
	Username string
	Domain   string

	// Authentication method used
	AuthMethod string
	AuthObject auth.AuthMethod // Novo campo: objeto de autenticação

	// Novos campos para SMB avançado
	Dialect     uint16 // Dialeto SMB a ser forçado
	Signing     *bool  // Se deve forçar signing obrigatório
	Socks5Proxy string // host:port SOCKS5 proxy for relay; empty = direct TCP

	// No copy mode - apenas listar arquivos
	NoCopy bool

	// Deep copy mode - copy files even if they are not in the original directory
	NoCopyDeep bool

	// ScanMode: "recon", "search", "exfil" — tracks how the file was found (stored in DB)
	ScanMode string

	// Filename patterns to match for large files
	FilenamePatterns []string

	// File extensions to match for large files
	FileExtensions []string

	// Max file size for large files
	MaxFileSize int64

	// Leet speak enabled
	LeetSpeak bool

	// Content patterns to match for large files
	ContentPatterns []string

	// Regex patterns to match for large files
	RegexPatterns []*regexp.Regexp

	// BatchMode - true = processamento em lote, false = imediato
	BatchMode bool

	// MiniBatchSize - Tamanho do mini-lote para processamento batch
	MiniBatchSize int

	// ChunkSize - Tamanho do chunk para processamento em lote
	ChunkSize int

	// BufferSize - Tamanho do buffer para cópia
	BufferSize int

	// BatchSize - Tamanho do lote para processamento batch
	BatchSize int

	// BatchTimeout - Tempo limite para processamento batch
	BatchTimeout time.Duration
}

// CopyResult represents the result of a file copy operation
type CopyResult struct {
	ShareName  string
	RemotePath string
	LocalPath  string
	Size       int64
	Success    bool
	Error      error
}

// Estrutura para fila de cópia persistente
// Cada entrada representa um arquivo a ser copiado
// Status: pending, copied, error

type CopyQueueEntry struct {
	ShareName        string `json:"share_name"`
	RemotePath       string `json:"remote_path"`
	LocalPath        string `json:"local_path"`
	Size             int64  `json:"size"`
	SizeFormatted    string `json:"size_formatted"`
	LargeFile        bool   `json:"large_file,omitempty"`
	Status           string `json:"status"` // pending, copied, error
	ErrorMsg         string `json:"error_msg,omitempty"`
	FileType         string `json:"file_type,omitempty"`
	MatchPattern     string `json:"match_pattern,omitempty"`
	MatchType        string `json:"match_type,omitempty"`
	LeetSpeak        bool   `json:"leet_speak,omitempty"`
	SearchParamType  string `json:"search_param_type,omitempty"`
	SearchParamValue string `json:"search_param_value,omitempty"`
}

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

type CopyQueue struct {
	Host    string           `json:"host"`
	Entries []CopyQueueEntry `json:"entries"`
}

// CopyHistory representa o histórico de cópias
type CopyHistory struct {
	Host                  string         `json:"host"`
	SearchPattern         string         `json:"search_pattern"`
	SearchPatternsHistory []string       `json:"search_patterns_history"`
	LeetSpeak             bool           `json:"leet_speak"`
	ScanTime              time.Time      `json:"scan_time"`
	User                  string         `json:"user"`
	Domain                string         `json:"domain"`
	AuthMethod            string         `json:"auth_method"`
	AuthMethodsUsed       []string       `json:"auth_methods_history"`
	DateTime              string         `json:"datetime"`
	NewFiles              int            `json:"new_files"`
	Entries               []HistoryEntry `json:"entries"`
}

// ErrorLog representa o log de erros
type ErrorLog struct {
	Host            string       `json:"host"`
	ScanTime        time.Time    `json:"scan_time"`
	User            string       `json:"user"`
	Domain          string       `json:"domain"`
	AuthMethod      string       `json:"auth_method"`
	AuthMethodsUsed []string     `json:"auth_methods_history"`
	DateTime        string       `json:"datetime"`
	Entries         []ErrorEntry `json:"entries"`
}

// LargeFilesList representa a lista de arquivos grandes que não foram copiados
type LargeFilesList struct {
	Host            string           `json:"host"`
	SearchPattern   string           `json:"search_pattern"`
	LeetSpeak       bool             `json:"leet_speak"`
	ScanTime        time.Time        `json:"scan_time"`
	User            string           `json:"user"`
	Domain          string           `json:"domain"`
	AuthMethod      string           `json:"auth_method"`
	AuthMethodsUsed []string         `json:"auth_methods_history"`
	Entries         []LargeFileEntry `json:"entries"`
}

// LargeFileEntry representa um arquivo grande que não foi copiado
type LargeFileEntry struct {
	Host          string `json:"host"`
	Path          string `json:"path"`
	Size          int64  `json:"size"`
	SizeFormatted string `json:"size_formatted"`
	LargeFile     bool   `json:"large_file,omitempty"`
	DateTime      string `json:"datetime"`
	MatchType     string `json:"match_type"`
	Pattern       string `json:"pattern"`
}

// HistoryEntry representa uma entrada no histórico de cópias
type HistoryEntry struct {
	ShareName     string    `json:"share_name"`
	RemotePath    string    `json:"remote_path"`
	LocalPath     string    `json:"local_path"`
	Size          int64     `json:"size"`
	SizeFormatted string    `json:"size_formatted"`
	LargeFile     bool      `json:"large_file,omitempty"`
	CopiedAt      time.Time `json:"copied_at"`
	ModTime       time.Time `json:"mod_time"`
}

// ErrorEntry representa uma entrada com erro na cópia
type ErrorEntry struct {
	ShareName     string    `json:"share_name"`
	RemotePath    string    `json:"remote_path"`
	LocalPath     string    `json:"local_path"`
	Size          int64     `json:"size"`
	SizeFormatted string    `json:"size_formatted"`
	LargeFile     bool      `json:"large_file,omitempty"`
	ErrorMsg      string    `json:"error_msg"`
	ErrorAt       time.Time `json:"error_at"`
}

// NocopyScanResult representa o resultado da varredura sem cópia
type NocopyScanResult struct {
	Host            string    `json:"host"`
	SearchPattern   string    `json:"search_pattern"`
	LeetSpeak       bool      `json:"leet_speak"`
	NoCopy          bool      `json:"no_copy"` // Indica se foi usado -no-copy
	DeepScan        bool      `json:"no_copy_deep"`
	ScanTime        time.Time `json:"scan_time"`
	User            string    `json:"user"`
	Domain          string    `json:"domain"`
	AuthMethod      string    `json:"auth_method"`          // Método atual
	AuthMethodsUsed []string  `json:"auth_methods_history"` // Histórico de métodos bem-sucedidos
	Files           []FileRef `json:"files"`
	PreviousCount   int       `json:"previous_count"` // Total de arquivos da execução anterior
	NewFiles        int       `json:"new_files"`      // Número de arquivos novos encontrados nesta execução
}

// FileRef representa uma referência a um arquivo encontrado
type FileRef struct {
	Path          string    `json:"path"`
	ShareName     string    `json:"share_name"`
	Size          int64     `json:"size"`
	SizeFormatted string    `json:"size_formatted"`
	LargeFile     bool      `json:"large_file,omitempty"` // Indica se é arquivo grande
	Found         time.Time `json:"found"`
	MatchType     string    `json:"match_type"` // "filename", "content", "regex", "extension"
	Pattern       string    `json:"pattern"`    // Padrão que causou o match
}

// Estruturas para o worker pool
type copyJob struct {
	entry  CopyQueueEntry
	share  *smb2.Share
	hostIP string
	index  int
}

type copyResult struct {
	result       *CopyResult
	hostIP       string
	historyEntry *HistoryEntry
	errorEntry   *ErrorEntry
}

// Estrutura para armazenar erros de acesso negado
// Cada host terá um arquivo com lista de caminhos negados

type AccessDeniedLog struct {
	Host    string   `json:"host"`
	Entries []string `json:"entries"`
}

// Funções utilitárias para salvar/carregar fila de cópia
func SaveCopyQueue(filename string, queue *CopyQueue) error {
	data, err := json.MarshalIndent(queue, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filename, data, 0644)
}

func LoadCopyQueue(filename string) (*CopyQueue, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	var queue CopyQueue
	if err := json.Unmarshal(data, &queue); err != nil {
		return nil, err
	}
	return &queue, nil
}

// Funções utilitárias para arquivos grandes
func SaveLargeFilesList(filename string, list *LargeFilesList) error {
	// Verificar se já existe um arquivo
	var existingList LargeFilesList
	existingFiles := make(map[string]bool)

	// Tentar ler o arquivo existente
	if data, err := os.ReadFile(filename); err == nil {
		if err := json.Unmarshal(data, &existingList); err == nil {
			// Criar mapa de arquivos existentes
			for _, entry := range existingList.Entries {
				key := fmt.Sprintf("%s:%s", entry.Host, entry.Path)
				existingFiles[key] = true
			}

			// Manter histórico de métodos de autenticação
			if existingList.AuthMethodsUsed != nil {
				list.AuthMethodsUsed = existingList.AuthMethodsUsed
			}
		}
	}

	// Se o método atual não está no histórico, adicionar
	if list.AuthMethodsUsed == nil {
		list.AuthMethodsUsed = []string{}
	}
	methodExists := false
	for _, method := range list.AuthMethodsUsed {
		if method == list.AuthMethod {
			methodExists = true
			break
		}
	}
	if !methodExists {
		list.AuthMethodsUsed = append(list.AuthMethodsUsed, list.AuthMethod)
	}

	// Adicionar apenas arquivos novos
	var updatedEntries []LargeFileEntry
	updatedEntries = append(updatedEntries, existingList.Entries...)

	for _, entry := range list.Entries {
		key := fmt.Sprintf("%s:%s", entry.Host, entry.Path)
		if !existingFiles[key] {
			updatedEntries = append(updatedEntries, entry)
		}
	}

	// Atualizar a lista com todas as entradas
	list.Entries = updatedEntries

	// Serializar e salvar
	data, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filename, data, 0644)
}

func LoadLargeFilesList(filename string) (*LargeFilesList, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	var list LargeFilesList
	if err := json.Unmarshal(data, &list); err != nil {
		return nil, err
	}
	return &list, nil
}

// SaveCopyHistory saves the copy history to a file
func SaveCopyHistory(filename string, history *CopyHistory) error {
	// Zerar o contador de novos arquivos no início da execução
	history.NewFiles = 0

	// Verificar se já existe um arquivo de histórico
	var existingHistory CopyHistory
	var existingEntries = make(map[string]bool)
	var existingPatterns = make(map[string]bool)

	// Tentar carregar arquivo existente
	if data, err := os.ReadFile(filename); err == nil {
		if err := json.Unmarshal(data, &existingHistory); err == nil {
			// Criar mapa das entradas existentes
			for _, entry := range existingHistory.Entries {
				key := fmt.Sprintf("%s:%s", entry.ShareName, entry.RemotePath)
				existingEntries[key] = true
			}

			// Manter configurações do arquivo existente
			history.AuthMethodsUsed = existingHistory.AuthMethodsUsed
			history.ScanTime = existingHistory.ScanTime

			// Manter histórico de padrões de busca
			for _, pattern := range existingHistory.SearchPatternsHistory {
				existingPatterns[pattern] = true
			}
		}
	}

	// Adicionar apenas arquivos novos ao histórico
	var updatedEntries []HistoryEntry
	updatedEntries = append(updatedEntries, existingHistory.Entries...)
	for _, entry := range history.Entries {
		key := fmt.Sprintf("%s:%s", entry.ShareName, entry.RemotePath)
		if !existingEntries[key] {
			updatedEntries = append(updatedEntries, entry)
			history.NewFiles++
		}
	}

	history.Entries = updatedEntries

	// Atualizar histórico de métodos de autenticação
	if history.AuthMethodsUsed == nil {
		history.AuthMethodsUsed = []string{}
	}
	methodExists := false
	for _, method := range history.AuthMethodsUsed {
		if method == history.AuthMethod {
			methodExists = true
			break
		}
	}
	if !methodExists {
		history.AuthMethodsUsed = append(history.AuthMethodsUsed, history.AuthMethod)
	}

	// Atualizar histórico de padrões de busca
	if history.SearchPatternsHistory == nil {
		history.SearchPatternsHistory = []string{}
	}
	if !existingPatterns[history.SearchPattern] && history.SearchPattern != "" {
		history.SearchPatternsHistory = append(history.SearchPatternsHistory, history.SearchPattern)
	}
	for _, pattern := range existingHistory.SearchPatternsHistory {
		if pattern != history.SearchPattern {
			history.SearchPatternsHistory = append(history.SearchPatternsHistory, pattern)
		}
	}

	// Serializar e salvar
	data, err := json.MarshalIndent(history, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to serialize history: %v", err)
	}

	return os.WriteFile(filename, data, 0644)
}

// Função para salvar os erros
func SaveErrorLog(filename string, errorLog *ErrorLog) error {
	// Verificar se já existe um arquivo de log
	var existingLog ErrorLog
	if data, err := os.ReadFile(filename); err == nil {
		if err := json.Unmarshal(data, &existingLog); err == nil {
			// Manter histórico de métodos de autenticação
			if existingLog.AuthMethodsUsed != nil {
				errorLog.AuthMethodsUsed = existingLog.AuthMethodsUsed
			}
		}
	}

	// Se o método atual não está no histórico, adicionar
	if errorLog.AuthMethodsUsed == nil {
		errorLog.AuthMethodsUsed = []string{}
	}
	methodExists := false
	for _, method := range errorLog.AuthMethodsUsed {
		if method == errorLog.AuthMethod {
			methodExists = true
			break
		}
	}
	if !methodExists {
		errorLog.AuthMethodsUsed = append(errorLog.AuthMethodsUsed, errorLog.AuthMethod)
	}

	// Adicionar novas entradas ao log existente
	errorLog.Entries = append(existingLog.Entries, errorLog.Entries...)

	// Serializar e salvar
	data, err := json.MarshalIndent(errorLog, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filename, data, 0644)
}

// Função para processar e separar as entradas da fila
func ProcessCopyQueue(queue *CopyQueue) (*CopyQueue, *CopyHistory, *ErrorLog) {
	// Nova fila apenas com pending
	newQueue := &CopyQueue{
		Host:    queue.Host,
		Entries: make([]CopyQueueEntry, 0),
	}

	// Histórico de sucessos
	history := &CopyHistory{
		Host:     queue.Host,
		Entries:  make([]HistoryEntry, 0),
		DateTime: time.Now().Format("2006-01-02 15:04:05"),
	}

	// Log de erros
	errorLog := &ErrorLog{
		Host:     queue.Host,
		Entries:  make([]ErrorEntry, 0),
		DateTime: time.Now().Format("2006-01-02 15:04:05"),
	}

	// Processar cada entrada
	for _, entry := range queue.Entries {
		switch entry.Status {
		case "copied":
			// Adicionar ao histórico
			history.Entries = append(history.Entries, HistoryEntry{
				ShareName:     entry.ShareName,
				RemotePath:    entry.RemotePath,
				LocalPath:     entry.LocalPath,
				Size:          entry.Size,
				SizeFormatted: entry.SizeFormatted,
				CopiedAt:      time.Now(),
			})

		case "error":
			// Adicionar ao log de erros
			errorLog.Entries = append(errorLog.Entries, ErrorEntry{
				ShareName:     entry.ShareName,
				RemotePath:    entry.RemotePath,
				LocalPath:     entry.LocalPath,
				Size:          entry.Size,
				SizeFormatted: entry.SizeFormatted,
				ErrorMsg:      entry.ErrorMsg,
				ErrorAt:       time.Now(),
			})

		case "pending":
			// Manter na fila
			newQueue.Entries = append(newQueue.Entries, entry)
		}
	}

	return newQueue, history, errorLog
}

// NewCopyConfig creates a new copy configuration with default values
func NewCopyConfig() *CopyConfig {
	return &CopyConfig{
		OutputDir:           "low-hanging_fruit_output",
		OrganizeByShare:     true,
		OrganizeByMatchType: true,
		PreserveStructure:   true, //default true
		Verbose:             true,
		LeetSpeak:           false,
		ScanMode:            "exfil",
	}
}

// Função auxiliar para formatar o tamanho
func formatSize(size int64) string {
	if size < 1024*1024 {
		return fmt.Sprintf("%.2f KB", float64(size)/1024)
	} else if size < 1024*1024*1024 {
		return fmt.Sprintf("%.2f MB", float64(size)/(1024*1024))
	}
	return fmt.Sprintf("%.2f GB", float64(size)/(1024*1024*1024))
}

// extractHostIP extrai o IP do host do nome do share
func extractHostIP(shareName string) string {
	sharePath := strings.TrimPrefix(shareName, "\\\\")
	sharePath = strings.TrimPrefix(sharePath, "\\")
	parts := strings.Split(sharePath, "\\")
	if len(parts) > 0 {
		return parts[0]
	}
	return ""
}

// Configurações do worker pool
const (
	defaultNumWorkers = 10        // Aumentado de 5 para 10
	defaultBatchSize  = 100       // Tamanho do lote para processamento
	defaultBufferSize = 32 * 1024 // 32KB buffer para cópia
)

// Pool de buffers para reuso
var bufferPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, defaultBufferSize)
	},
}

// copyFile copia um arquivo de um share SMB para o filesystem local, retornando também o SHA-256.
func copyFile(fs *smb2.Share, remotePath, localPath string, shareName string, config *CopyConfig) (int64, time.Time, string, error) {
	written, modTime, hash, err := copyFileOnce(fs, remotePath, localPath)
	if err == nil {
		return written, modTime, hash, nil
	}
	// On EOF / connection error: retry once with a fresh session.
	if strings.Contains(strings.ToLower(err.Error()), "eof") || strings.Contains(strings.ToLower(err.Error()), "connection error") {
		host := extractHostIP(shareName)
		smbConfig := &smb.SMBConfig{
			Host:        host,
			Port:        445,
			Domain:      config.Domain,
			Username:    config.Username,
			Timeout:     10 * time.Second,
			AuthMethod:  config.AuthObject,
			Socks5Proxy: config.Socks5Proxy,
		}
		conn := smb.NewSMBConnection(smbConfig)
		if errConn := conn.Connect(); errConn != nil {
			return 0, time.Time{}, "", errConn
		}
		defer conn.Disconnect()
		shareNameOnly := shareName
		if idx := strings.Index(shareName, "\\"); idx != -1 {
			parts := strings.Split(shareName, "\\")
			if len(parts) > 1 {
				shareNameOnly = parts[len(parts)-1]
			}
		}
		share, errMount := conn.MountShare(shareNameOnly)
		if errMount != nil {
			return 0, time.Time{}, "", errMount
		}
		defer share.Umount()
		return copyFileOnce(share, remotePath, localPath)
	}
	return written, modTime, hash, err
}

// copyFileOnce realiza a cópia real (1 tentativa) e computa SHA-256 durante a transferência.
func copyFileOnce(fs *smb2.Share, remotePath, localPath string) (int64, time.Time, string, error) {
	remoteFile, err := fs.Open(remotePath)
	if err != nil {
		return 0, time.Time{}, "", fmt.Errorf("failed to open remote file: %v", err)
	}
	defer remoteFile.Close()

	localFile, err := os.Create(localPath)
	if err != nil {
		return 0, time.Time{}, "", fmt.Errorf("failed to create local file: %v", err)
	}
	defer localFile.Close()

	buf := bufferPool.Get().([]byte)
	defer bufferPool.Put(buf)

	hasher := sha256.New()
	written, err := io.CopyBuffer(io.MultiWriter(localFile, hasher), remoteFile, buf)
	if err != nil {
		return written, time.Time{}, "", fmt.Errorf("error copying file: %v", err)
	}
	fileHash := hex.EncodeToString(hasher.Sum(nil))

	modTime := time.Now()
	if fi, err := fs.Stat(remotePath); err == nil {
		modTime = fi.ModTime().UTC().Truncate(time.Second)
	}
	if chtimesErr := os.Chtimes(localPath, modTime, modTime); chtimesErr != nil {
		logger.Warning("Failed to set local modtime: %v", chtimesErr)
	} else {
		logger.Debug("Set local modtime to %v", modTime)
	}

	return written, modTime, fileHash, nil
}

// Processamento em lote dos resultados
func processBatchResults(batch []copyResult, historyByHost map[string]*CopyHistory, errorLogByHost map[string]*ErrorLog, historyMutex, errorLogMutex *sync.Mutex) {
	for _, res := range batch {
		if res.historyEntry != nil {
			historyMutex.Lock()
			history := historyByHost[res.hostIP]
			if history == nil {
				history = &CopyHistory{
					Host:     res.hostIP,
					Entries:  []HistoryEntry{},
					DateTime: time.Now().Format("2006-01-02 15:04:05"),
				}
				historyByHost[res.hostIP] = history
			}
			history.Entries = append(history.Entries, *res.historyEntry)
			historyMutex.Unlock()
		}
		if res.errorEntry != nil {
			errorLogMutex.Lock()
			errorLog := errorLogByHost[res.hostIP]
			if errorLog == nil {
				errorLog = &ErrorLog{
					Host:     res.hostIP,
					Entries:  []ErrorEntry{},
					DateTime: time.Now().Format("2006-01-02 15:04:05"),
				}
				errorLogByHost[res.hostIP] = errorLog
			}
			errorLog.Entries = append(errorLog.Entries, *res.errorEntry)
			errorLogMutex.Unlock()
		}
	}
}

// CopyMatchedFiles copia os arquivos encontrados para o diretório de saída
func CopyMatchedFiles(ctx context.Context, db *sql.DB, shares map[string]*smb2.Share, searchResults []*search.SearchResult, config *CopyConfig, scanHost string, throttler *smb.Throttler) ([]*CopyResult, int, error) {
	var (
		results       []*CopyResult
		historyMutex  sync.Mutex
		errorLogMutex sync.Mutex
		newQueueMutex sync.Mutex
	)
	newLHFCount := 0
	if config.Verbose {
		logger.Debug("Starting file copy process")
		logger.Debug("Base output directory: %s", config.OutputDir)
		logger.Debug("Total search results: %d", len(searchResults))
		logger.Debug("Using authentication method: %s", config.AuthMethod)
	}

	// // Criar diretórios de controle
	// for _, dir := range []string{
	// 	filepath.Join("targets"),
	// 	filepath.Join("history", "copy"),
	// 	filepath.Join("errors", "copy"),
	// } {
	// 	if err := os.MkdirAll(dir, 0755); err != nil {
	// 		return nil, 0, fmt.Errorf("failed to create directory %s: %v", dir, err)
	// 	}
	// }

	if config.Verbose {
		logger.Debug("Control directories created successfully")
	}

	// Mapa para fila de cópia por host
	copyQueues := make(map[string]*CopyQueue)
	// largeFilesByHost := make(map[string]*LargeFilesList)
	processedLargeFiles := make(map[string]map[string]bool)
	nocopyScansByHost := make(map[string]*NocopyScanResult)

	// Processar cada resultado
	for _, result := range searchResults {
		if config.Verbose {
			logger.Debug("[COPY-DEBUG] Evaluating file: %s", result.FilePath)
			logger.Debug("  - ShareName: %s", result.ShareName)
			logger.Debug("  - MatchType: %s", result.MatchType)
			logger.Debug("  - FileSize: %d", result.FileSize)
			logger.Debug("  - IsDirectory: %v", result.IsDirectory)
		}

		if result.IsDirectory {
			if config.Verbose {
				logger.Debug("[COPY-DEBUG] Skipping directory: %s", result.FilePath)
			}
			continue
		}

		hostIP := extractHostIP(result.ShareName)
		if scanHost == "" {
			if config.Verbose {
				logger.Debug("[COPY-DEBUG] scanHost não definido para: %s", result.ShareName)
			}
			continue
		}

		if config.Verbose {
			logger.Debug("Processing file from host %s: %s", hostIP, result.FilePath)
			logger.Debug("    Share: %s", result.ShareName)
			logger.Debug("    Size: %s", formatSize(result.FileSize))
			logger.Debug("    Match type: %s", result.MatchType)
		}

		// Inicializar mapa de arquivos processados para este host se não existir
		if _, ok := processedLargeFiles[scanHost]; !ok {
			processedLargeFiles[scanHost] = make(map[string]bool)
		}

		// Se estiver em modo no-copy, adicionar ao resultado da varredura
		if config.NoCopy || config.NoCopyDeep {
			lhfMode := "no-copy"
			if config.NoCopyDeep {
				lhfMode = "no-copy-deep"
			}
			inserted, err := database.InsertLowHangingFruit(
				db,
				result.FilePath,
				scanHost,
				result.ShareName,
				config.Domain,
				config.Username,
				result.FileSize,
				time.Now(),
				"",
				result.MatchValue,
				result.MatchType,
				formatSize(result.FileSize),
				lhfMode,
				result.FileSize > config.MaxFileSize,
			)
			if err != nil {
				logger.Error("Error saving low-hanging fruit to database: %v", err)
			}
			if inserted {
				newLHFCount++
			}
			// Also save to files table so nfdb queries (hosts/users/shares) work
			dbErr := database.InsertFile(
				db,
				result.FilePath,
				scanHost,
				result.ShareName,
				config.Domain,
				config.Username,
				result.FileSize,
				time.Now(),
				"",
				result.MatchValue,
				result.MatchType,
				"",
				"",
				formatSize(result.FileSize),
				result.FileSize > config.MaxFileSize,
				config.LeetSpeak,
				"",
				"",
				nil,
				config.ScanMode,
			)
			if dbErr != nil {
				logger.Error("Error saving file record to database: %v", dbErr)
			}
			continue
		}

		// Se for um arquivo grande (identificado durante a busca)
		if result.FileSize > config.MaxFileSize {
			fileKey := fmt.Sprintf("%s:%s", result.ShareName, result.FilePath)

			if config.Verbose {
				logger.Debug("Large file detected: %s", fileKey)
				logger.Debug("    Size: %s (max allowed: %s)",
					formatSize(result.FileSize),
					formatSize(config.MaxFileSize))
			}

			// Verificar se o arquivo já foi processado
			if processedLargeFiles[scanHost][fileKey] {
				if config.Verbose {
					logger.Debug("Large file already processed, skipping: %s", fileKey)
				}
				continue
			}

			// Verificar se o arquivo também corresponde a algum critério de busca
			matchesCriteria := false

			// Verificar correspondência por nome do arquivo
			fileName := filepath.Base(result.FilePath)
			for _, pattern := range config.FilenamePatterns {
				if strings.Contains(strings.ToLower(fileName), strings.ToLower(pattern)) {
					matchesCriteria = true
					if config.Verbose {
						logger.Debug("File matches filename pattern: %s", pattern)
					}
					break
				}
			}

			// Verificar correspondência por extensão (suporta .env.prod, etc.)
			if !matchesCriteria && len(config.FileExtensions) > 0 {
				if matchesAnyExtension(filepath.Base(result.FilePath), config.FileExtensions) {
					matchesCriteria = true
					if config.Verbose {
						logger.Debug("[COPY-DEBUG] File %s matches extension filter", result.FilePath)
					}
				}
			}

			// Verificar correspondência por conteúdo
			if !matchesCriteria && result.ContentMatch != "" {
				matchesCriteria = true
				if config.Verbose {
					logger.Debug("File matches content pattern: %s", result.ContentMatch)
				}
			}

			// Verificar correspondência por regex
			if !matchesCriteria && result.RegexMatch != "" {
				matchesCriteria = true
				if config.Verbose {
					logger.Debug("File matches regex pattern: %s", result.RegexMatch)
				}
			}

			// Só registrar se corresponder aos critérios de busca
			if matchesCriteria {
				if config.Verbose {
					logger.Debug("Adding large file to low_hanging_fruit: %s", result.FilePath)
				}
				scanMode := "large-file"
				inserted, err := database.InsertLowHangingFruit(
					db,
					result.FilePath,
					scanHost,
					result.ShareName,
					config.Domain,
					config.Username,
					result.FileSize,
					time.Now(),
					"",
					result.MatchValue,
					result.MatchType,
					formatSize(result.FileSize),
					scanMode,
					true,
				)
				if err != nil {
					logger.Error("Error saving large file to low_hanging_fruit: %v", err)
				}
				if inserted {
					newLHFCount++
				}
				processedLargeFiles[scanHost][fileKey] = true
			} else if config.Verbose {
				logger.Debug("Large file does not match any criteria, skipping: %s", result.FilePath)
			}
			continue
		}

		// Processar arquivo normal
		queue, ok := copyQueues[scanHost]
		if !ok {
			queue = &CopyQueue{Host: scanHost}
			copyQueues[scanHost] = queue
			if config.Verbose {
				logger.Debug("Created new copy queue for host: %s", scanHost)
			}
		}

		// Verificar se o arquivo já existe no diretório de saída
		localPath := determineLocalPath(config.OutputDir, result, config)
		if _, err := os.Stat(localPath); err == nil {
			// Só faz versionamento físico no modo normal
			if !config.NoCopy && !config.NoCopyDeep {
				// Obter informações do arquivo remoto (no alvo)
				remoteModTime := time.Time{}
				remoteSize := int64(0)
				if share, ok := shares[result.ShareName]; ok {
					if fi, err := share.Stat(result.FilePath); err == nil {
						remoteModTime = fi.ModTime().UTC().Truncate(time.Second)
						remoteSize = fi.Size()
					}
				}
				// Obter informações do arquivo local
				localInfo, _ := os.Stat(localPath)
				localModTime := localInfo.ModTime().UTC().Truncate(time.Second)
				if config.Verbose {
					logger.Debug("[COPY-DEBUG] Comparando remoteModTime=%v, localModTime=%v, diff=%v, remoteSize=%d, localSize=%d", remoteModTime, localModTime, absDuration(remoteModTime.Sub(localModTime)), remoteSize, localInfo.Size())
				}
				if !remoteModTime.IsZero() && (absDuration(remoteModTime.Sub(localModTime)) > 2*time.Second || remoteSize != localInfo.Size()) {
					// Criar novo nome com timestamp
					dir := filepath.Dir(localPath)
					base := filepath.Base(localPath)
					ext := filepath.Ext(base)
					name := strings.TrimSuffix(base, ext)
					timestamp := time.Now().Format("20060102_150405")
					newName := fmt.Sprintf("%s_%s%s", name, timestamp, ext)
					newPath := filepath.Join(dir, newName)
					if config.Verbose {
						logger.Info("file changed detected, saving new version: %s", newPath)
					}
					// Copiar o arquivo remoto para o novo caminho (timestamp) apenas se não existir
					if _, err := os.Stat(newPath); os.IsNotExist(err) {
						_, _, _, _ = copyFile(shares[result.ShareName], result.FilePath, newPath, result.ShareName, config)
					}
					// Antes de sobrescrever o arquivo base, se ele já existir, salva snapshot do conteúdo antigo
					if _, err := os.Stat(localPath); err == nil {
						oldInfo, _ := os.Stat(localPath)
						oldModTime := oldInfo.ModTime().UTC().Truncate(time.Second)
						oldTimestamp := oldModTime.Format("20060102_150405")
						dir := filepath.Dir(localPath)
						base := filepath.Base(localPath)
						ext := filepath.Ext(base)
						name := strings.TrimSuffix(base, ext)
						oldSnapshot := filepath.Join(dir, fmt.Sprintf("%s_%s%s", name, oldTimestamp, ext))
						if _, err := os.Stat(oldSnapshot); os.IsNotExist(err) {
							_ = copyFileLocal(localPath, oldSnapshot)
							baseID := getBaseFileID(db, result.FilePath, scanHost, result.ShareName)
							dbErr := database.InsertFile(
								db,
								result.FilePath,  // path
								scanHost,         // host
								result.ShareName, // share
								config.Domain,    // domain
								config.Username,  // user
								oldInfo.Size(),   // size
								oldModTime,       // mod_time
								strings.TrimPrefix(strings.ToLower(filepath.Ext(result.FilePath)), "."), // file_type
								result.MatchValue,                      // match_pattern
								result.MatchType,                       // match_type
								"",                                     // hash
								oldSnapshot,                            // local_path
								formatSize(oldInfo.Size()),             // size_formatted
								oldInfo.Size() > config.MaxFileSize,    // large_file
								config.LeetSpeak,                       // leet_speak
								inferSearchParamType(result.MatchType), // search_param_type
								getSearchParamValue(result.MatchType, config, result.RegexMatch), // search_param_value
									baseID, // parent_id
								config.ScanMode,
							)
							if dbErr != nil {
								logger.Error("[DB-ERROR] Failed to insert snapshot in database: %v", dbErr)
							} else if config.Verbose {
								logger.Debug("[DB-DEBUG] Inserted snapshot in database: %s", oldSnapshot)
							}
						}
					}
					// Sempre sobrescreve o arquivo base com o conteúdo atualizado
					if _, _, _, err2 := copyFile(shares[result.ShareName], result.FilePath, localPath, result.ShareName, config); err2 == nil {
						_ = os.Chtimes(localPath, remoteModTime, remoteModTime)
					}
				}
				return []*CopyResult{{
					ShareName:  result.ShareName,
					RemotePath: result.FilePath,
					LocalPath:  localPath,
					Size:       remoteSize,
					Success:    true,
					Error:      nil,
				}}, 0, nil
			}
			if config.Verbose {
				logger.Debug("[COPY-DEBUG] File already exists locally, skipping: %s", localPath)
			}
			continue
		}

		// Verificar se o arquivo deve ser copiado com base no tipo de match
		shouldCopy := false
		// Permitir cópia para qualquer tipo de match relevante
		switch result.MatchType {
		case "filename", "content", "regex", "extension":
			if result.FileSize <= config.MaxFileSize {
				shouldCopy = true
				if config.Verbose {
					logger.Debug("[COPY-DEBUG] File eligible for copy: %s", result.FilePath)
				}
			} else {
				if config.Verbose {
					logger.Debug("[COPY-DEBUG] File exceeds maximum size: %s (%d > %d)", result.FilePath, result.FileSize, config.MaxFileSize)
				}
			}
		default:
			// Permitir cópia para qualquer matchType não vazio (exceto diretórios)
			if result.MatchType != "" && !result.IsDirectory && result.FileSize <= config.MaxFileSize {
				shouldCopy = true
				if config.Verbose {
					logger.Debug("[COPY-DEBUG] Copying file with matchType different from filename, content, regex or extension: %s (%s)", result.FilePath, result.MatchType)
				}
			} else if config.Verbose {
				logger.Debug("[COPY-DEBUG] Match type not eligible for copy: %s (%s)", result.FilePath, result.MatchType)
			}
		}

		if shouldCopy {
			exists := false
			for _, entry := range queue.Entries {
				if entry.RemotePath == result.FilePath && entry.ShareName == result.ShareName {
					exists = true
					if config.Verbose {
						logger.Debug("[COPY-DEBUG] File already in queue: %s", result.FilePath)
					}
					break
				}
			}

			if !exists {
				queue.Entries = append(queue.Entries, CopyQueueEntry{
					ShareName:        result.ShareName,
					RemotePath:       result.FilePath,
					LocalPath:        localPath,
					Size:             result.FileSize,
					SizeFormatted:    formatSize(result.FileSize),
					Status:           "pending",
					FileType:         strings.TrimPrefix(strings.ToLower(filepath.Ext(result.FilePath)), "."),
					MatchPattern:     result.MatchValue,
					MatchType:        result.MatchType,
					LeetSpeak:        config.LeetSpeak,
					SearchParamType:  inferSearchParamType(result.MatchType),
					SearchParamValue: getSearchParamValue(result.MatchType, config, result.RegexMatch), // search_param_value
				})
				if config.Verbose {
					logger.Debug("[COPY-DEBUG] Added to queue: %s", result.FilePath)
				}
			}
		}
	}

	// Se estiver em modo no-copy, salvar os resultados
	if config.NoCopy || config.NoCopyDeep {
		for _, scan := range nocopyScansByHost {
			// Garantir que o método de autenticação seja definido
			scan.AuthMethod = config.AuthMethod
			if scan.AuthMethodsUsed == nil {
				scan.AuthMethodsUsed = []string{config.AuthMethod}
			}
		}
		if config.Verbose {
			if newLHFCount > 0 {
				fmt.Printf("\n🍏 %d new interesting files found in this scan!\n", newLHFCount)
			} else {
				fmt.Printf("\nℹ️ No new interesting files were found in this scan.\n")
			}
		}
		return results, newLHFCount, nil
	}

	// --- INÍCIO DO WORKER POOL DE CÓPIA ---
	numWorkers := defaultNumWorkers
	jobs := make(chan copyJob, defaultBatchSize*2)
	resultsChan := make(chan copyResult, defaultBatchSize*2)

	var wg sync.WaitGroup
	var batchMutex sync.Mutex
	var resultsWg sync.WaitGroup

	// Inicializar estruturas de controle
	historyByHost := make(map[string]*CopyHistory)
	errorLogByHost := make(map[string]*ErrorLog)
	newQueueByHost := make(map[string]*CopyQueue)

	// --- NOVO: Controle de progresso por host ---
	hostCopyTotal := make(map[string]int)
	hostCopyDone := make(map[string]int)
	var progressMutex sync.Mutex
	for hostIP, queue := range copyQueues {
		hostCopyTotal[hostIP] = len(queue.Entries)
		hostCopyDone[hostIP] = 0
	}

	// Inicializar estruturas para cada host
	// Montar todos os padrões de busca utilizados
	var allPatterns []string
	for _, pattern := range config.FilenamePatterns {
		allPatterns = append(allPatterns, fmt.Sprintf("m:%s", pattern))
	}
	for _, ext := range config.FileExtensions {
		allPatterns = append(allPatterns, fmt.Sprintf("e:%s", ext))
	}
	for _, pattern := range config.ContentPatterns {
		allPatterns = append(allPatterns, fmt.Sprintf("c:%s", pattern))
	}
	// RegexPatterns pode ser slice de *regexp.Regexp, então converte para string
	if config.RegexPatterns != nil {
		for _, regex := range config.RegexPatterns {
			allPatterns = append(allPatterns, fmt.Sprintf("r:%s", regex.String()))
		}
	}
	searchPattern := strings.Join(allPatterns, ",")

	newQueueByHost[scanHost] = &CopyQueue{
		Host:    scanHost,
		Entries: make([]CopyQueueEntry, 0),
	}
	historyByHost[scanHost] = &CopyHistory{
		Host:            scanHost,
		SearchPattern:   searchPattern,
		LeetSpeak:       config.LeetSpeak,
		ScanTime:        time.Now(),
		User:            config.Username,
		Domain:          config.Domain,
		AuthMethod:      config.AuthMethod,
		AuthMethodsUsed: []string{config.AuthMethod},
		DateTime:        time.Now().Format("2006-01-02 15:04:05"),
		Entries:         make([]HistoryEntry, 0),
	}
	errorLogByHost[scanHost] = &ErrorLog{
		Host:            scanHost,
		ScanTime:        time.Now(),
		User:            config.Username,
		Domain:          config.Domain,
		AuthMethod:      config.AuthMethod,
		AuthMethodsUsed: []string{config.AuthMethod},
		DateTime:        time.Now().Format("2006-01-02 15:04:05"),
		Entries:         make([]ErrorEntry, 0),
	}

	// Batch processing
	results = make([]*CopyResult, 0, len(searchResults))
	resultsBatch := make([]copyResult, 0, defaultBatchSize)

	// Goroutine para processar resultados em lote
	resultsWg.Add(1)
	go func() {
		defer resultsWg.Done()
		for res := range resultsChan {
			batchMutex.Lock()
			resultsBatch = append(resultsBatch, res)

			// --- NOVO: Atualizar progresso por host ---
			if !config.Verbose && res.hostIP != "" {
				progressMutex.Lock()
				hostCopyDone[res.hostIP]++
				done := hostCopyDone[res.hostIP]

				total := hostCopyTotal[res.hostIP]
				percent := 0
				if total > 0 {
					percent = int(float64(done) / float64(total) * 100)
				}
				fmt.Printf("\r[Host: %s] ⏳ Copy progress: %d/%d (%d%%)", res.hostIP, done, total, percent)
				if done == total {
					fmt.Printf("\n")
				}
				progressMutex.Unlock()
			}

			// Processar lote quando atingir o tamanho máximo
			if len(resultsBatch) >= defaultBatchSize {
				processBatchResults(resultsBatch, historyByHost, errorLogByHost, &historyMutex, &errorLogMutex)
				// Adicionar resultados processados
				for _, r := range resultsBatch {
					if r.result != nil {
						results = append(results, r.result)
					}
				}
				// Limpar lote
				resultsBatch = resultsBatch[:0]
			}
			batchMutex.Unlock()
		}

		// Processar último lote
		batchMutex.Lock()
		if len(resultsBatch) > 0 {
			processBatchResults(resultsBatch, historyByHost, errorLogByHost, &historyMutex, &errorLogMutex)
			for _, r := range resultsBatch {
				if r.result != nil {
					results = append(results, r.result)
				}
			}
		}
		batchMutex.Unlock()
	}()

	// Iniciar workers
	for w := 0; w < numWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for job := range jobs {
				func() {
					defer func() {
						if r := recover(); r != nil {
							// Loga o panic como erro
							resultsChan <- copyResult{
								errorEntry: &ErrorEntry{
									ShareName:     job.entry.ShareName,
									RemotePath:    job.entry.RemotePath,
									LocalPath:     job.entry.LocalPath,
									Size:          job.entry.Size,
									SizeFormatted: job.entry.SizeFormatted,
									ErrorMsg:      fmt.Sprintf("panic: %v", r),
									ErrorAt:       time.Now(),
								},
								hostIP: job.hostIP,
							}
						}
					}()
					select {
					case <-ctx.Done():
						resultsChan <- copyResult{
							errorEntry: &ErrorEntry{
								ShareName:     job.entry.ShareName,
								RemotePath:    job.entry.RemotePath,
								LocalPath:     job.entry.LocalPath,
								Size:          job.entry.Size,
								SizeFormatted: job.entry.SizeFormatted,
								ErrorMsg:      "copy aborted: context canceled",
								ErrorAt:       time.Now(),
							},
							hostIP: job.hostIP,
						}
						return
					default:
						// Criar diretório local para o arquivo em lote
						dirPath := filepath.Dir(job.entry.LocalPath)
						batchMutex.Lock()
						if err := os.MkdirAll(dirPath, 0755); err != nil {
							// Verificar se é erro de permissão negada
							errMsg := strings.ToLower(err.Error())
							if strings.Contains(errMsg, "permission denied") || strings.Contains(errMsg, "acesso negado") || strings.Contains(errMsg, "access is denied") {
								_ = SaveAccessDeniedLog(job.hostIP, job.entry.RemotePath)
								fmt.Printf("[!] access denied to create directory for %s in %s\n", job.entry.RemotePath, job.hostIP)
							}
							batchMutex.Unlock()
							resultsChan <- copyResult{
								errorEntry: &ErrorEntry{
									ShareName:     job.entry.ShareName,
									RemotePath:    job.entry.RemotePath,
									LocalPath:     job.entry.LocalPath,
									Size:          job.entry.Size,
									SizeFormatted: job.entry.SizeFormatted,
									ErrorMsg:      fmt.Sprintf("failed to create directory: %v", err),
									ErrorAt:       time.Now(),
								},
								hostIP: job.hostIP,
							}
							return
						}
						batchMutex.Unlock()

						if throttler != nil {
							_ = throttler.WaitN(ctx, config.ChunkSize)
						}

						size, _, _, err := copyFile(job.share, job.entry.RemotePath, job.entry.LocalPath, job.entry.ShareName, config)
						if err == nil {
							sizeFormatted := formatSize(size)
							resultsChan <- copyResult{
								result: &CopyResult{
									ShareName:  job.entry.ShareName,
									RemotePath: job.entry.RemotePath,
									LocalPath:  job.entry.LocalPath,
									Size:       size,
									Success:    true,
								},
								hostIP: job.hostIP,
								historyEntry: &HistoryEntry{
									ShareName:     job.entry.ShareName,
									RemotePath:    job.entry.RemotePath,
									LocalPath:     job.entry.LocalPath,
									Size:          size,
									SizeFormatted: sizeFormatted,
									CopiedAt:      time.Now(),
								},
							}
							// Dentro do worker, ao salvar arquivo copiado:
							var parentID *int
							isSnapshot := strings.Contains(job.entry.LocalPath, "_")
							if isSnapshot {
								parentID = getBaseFileID(db, job.entry.RemotePath, job.hostIP, job.entry.ShareName)
							}
							if !isSnapshot {
								// Arquivo base: verifica se já existe base
								baseID := getBaseFileID(db, job.entry.RemotePath, job.hostIP, job.entry.ShareName)
								if baseID != nil {
									// Atualiza o registro base existente
									_, errUpdate := db.Exec("UPDATE files SET size=?, mod_time=?, file_type=?, match_pattern=?, match_type=?, hash=?, local_path=?, size_formatted=?, large_file=?, leet_speak=?, search_param_type=?, search_param_value=? WHERE id=?",
										size,
										time.Now(),
										job.entry.FileType,
										job.entry.MatchPattern,
										job.entry.MatchType,
										"",
										job.entry.LocalPath,
										sizeFormatted,
										size > config.MaxFileSize,
										job.entry.LeetSpeak,
										job.entry.SearchParamType,
										job.entry.SearchParamValue,
										*baseID,
									)
									if errUpdate != nil {
										logger.Error("[DB-ERROR] Failed to update base file in database: %v", errUpdate)
									}
								} else {
									// Não existe base, insere novo
									dbErr := database.InsertFile(
										db,
										job.entry.RemotePath,
										job.hostIP,
										job.entry.ShareName,
										config.Domain,
										config.Username,
										size,
										time.Now(),
										job.entry.FileType,
										job.entry.MatchPattern,
										job.entry.MatchType,
										"",
										job.entry.LocalPath,
										sizeFormatted,
										size > config.MaxFileSize,
										job.entry.LeetSpeak,
										job.entry.SearchParamType,
										job.entry.SearchParamValue,
										nil, // parent_id = nil
										config.ScanMode,
									)
									if dbErr != nil {
										logger.Error("[DB-ERROR] Failed to insert base file in database: %v", dbErr)
									}
								}
							} else {
								// Snapshot: insere normalmente com parent_id do base
								dbErr := database.InsertFile(
									db,
									job.entry.RemotePath,
									job.hostIP,
									job.entry.ShareName,
									config.Domain,
									config.Username,
									size,
									time.Now(),
									job.entry.FileType,
									job.entry.MatchPattern,
									job.entry.MatchType,
									"",
									job.entry.LocalPath,
									sizeFormatted,
									size > config.MaxFileSize,
									job.entry.LeetSpeak,
									job.entry.SearchParamType,
									job.entry.SearchParamValue,
									parentID, // parent_id do base
								config.ScanMode,
								)
								if dbErr != nil {
									logger.Error("[DB-ERROR] Failed to insert snapshot in database: %v", dbErr)
								}
							}
						} else {
							// Verificar se é erro de permissão negada
							errMsg := strings.ToLower(err.Error())
							if strings.Contains(errMsg, "permission denied") || strings.Contains(errMsg, "acesso negado") || strings.Contains(errMsg, "access is denied") {
								_ = SaveAccessDeniedLog(job.hostIP, job.entry.RemotePath)
								fmt.Printf("[!] access denied to copy %s in %s\n", job.entry.RemotePath, job.hostIP)
							}
							resultsChan <- copyResult{
								errorEntry: &ErrorEntry{
									ShareName:     job.entry.ShareName,
									RemotePath:    job.entry.RemotePath,
									LocalPath:     job.entry.LocalPath,
									Size:          job.entry.Size,
									SizeFormatted: job.entry.SizeFormatted,
									ErrorMsg:      err.Error(),
									ErrorAt:       time.Now(),
								},
								hostIP: job.hostIP,
							}
						}
					}
				}()
			}
		}()
	}

	// Enviar jobs para os workers
	for _, queue := range copyQueues {
		for _, entry := range queue.Entries {
			if entry.Status == "copied" {
				continue
			}
			// Verifica se o arquivo já existe localmente
			if _, err := os.Stat(entry.LocalPath); err == nil {
				entry.Status = "copied"
				if config.Verbose {
					logger.Debug("[COPY-DEBUG] File already exists locally, marking as copied: %s", entry.LocalPath)
				}
				continue
			}
			share, ok := shares[entry.ShareName]
			if !ok {
				entry.Status = "error"
				resultsChan <- copyResult{
					errorEntry: &ErrorEntry{
						ShareName:     entry.ShareName,
						RemotePath:    entry.RemotePath,
						LocalPath:     entry.LocalPath,
						Size:          entry.Size,
						SizeFormatted: entry.SizeFormatted,
						ErrorMsg:      "share not found",
						ErrorAt:       time.Now(),
					},
					hostIP: scanHost,
				}
				continue
			}
			// Só envia para o worker se está pendente
			jobs <- copyJob{entry: entry, share: share, hostIP: scanHost}
		}
	}

	// Fechar canal de jobs e esperar workers terminarem
	close(jobs)
	wg.Wait()

	// Fechar canal de resultados e esperar processamento terminar
	close(resultsChan)
	resultsWg.Wait()

	// Salvar os arquivos de controle (histórico, erros, filas)
	newQueueMutex.Lock()
	if len(newQueueByHost[scanHost].Entries) > 0 {
		queueFile := filepath.Join("targets", scanHost+"_copyqueue.json")
		if err := SaveCopyQueue(queueFile, newQueueByHost[scanHost]); err != nil {
			logger.Warning("Error saving copy queue %s: %v", queueFile, err)
		} else if config.Verbose {
			logger.Info("Copy queue updated with %d pending entries: %s", len(newQueueByHost[scanHost].Entries), queueFile)
		}
	}
	newQueueMutex.Unlock()

	// Garante que sempre haverá um histórico salvo, mesmo sem novas entradas
	historyMutex.Lock()
	history := historyByHost[scanHost]
	if history == nil {
		history = &CopyHistory{
			Host:     scanHost,
			Entries:  []HistoryEntry{},
			DateTime: time.Now().Format("2006-01-02 15:04:05"),
		}
		historyByHost[scanHost] = history
	}
	// Se não houver entradas novas, NewFiles já estará zerado
	historyFile := filepath.Join("history/copy", scanHost+"_history.json")
	if err := SaveCopyHistory(historyFile, history); err != nil {
		logger.Warning("Error saving history %s: %v", historyFile, err)
	} else if config.Verbose {
		logger.Info("History saved with %d total entries: %s", len(history.Entries), historyFile)
	}

	if config.NoCopy || config.NoCopyDeep {
		if newLHFCount > 0 {
			fmt.Printf("\n🍏 %d new interesting files found in this scan!\n", newLHFCount)
		} else {
			fmt.Printf("\nℹ️ No new interesting files were found in this scan.\n")
		}
	}

	return results, newLHFCount, nil
}

func absDuration(d time.Duration) time.Duration {
	if d < 0 {
		return -d
	}
	return d
}

// Função auxiliar para copiar arquivo localmente
func copyFileLocal(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}

// Função auxiliar para inferir o tipo do parâmetro de busca
func inferSearchParamType(matchType string) string {
	switch matchType {
	case "filename", "content":
		return "string"
	case "regex":
		return "regex"
	case "extension":
		return "ext"
	default:
		return matchType
	}
}

// Função auxiliar para obter o valor original do parâmetro de busca
func getSearchParamValue(matchType string, config *CopyConfig, regexMatch string) string {
	var searchParamValue string
	switch matchType {
	case "filename":
		if len(config.FilenamePatterns) > 0 {
			searchParamValue = strings.Join(config.FilenamePatterns, ",")
		} else if len(config.ContentPatterns) > 0 {
			searchParamValue = strings.Join(config.ContentPatterns, ",")
		}
	case "content":
		if len(config.ContentPatterns) > 0 {
			searchParamValue = strings.Join(config.ContentPatterns, ",")
		} else if len(config.FilenamePatterns) > 0 {
			searchParamValue = strings.Join(config.FilenamePatterns, ",")
		}
	case "extension":
		if len(config.FileExtensions) > 0 {
			searchParamValue = strings.Join(config.FileExtensions, ",")
		}
	case "regex":
		if len(config.RegexPatterns) > 0 {
			var regexes []string
			for _, r := range config.RegexPatterns {
				regexes = append(regexes, r.String())
			}
			searchParamValue = strings.Join(regexes, ",")
		} else if regexMatch != "" {
			searchParamValue = regexMatch
		} else {
			searchParamValue = ""
		}
	}
	return searchParamValue
}

// Função auxiliar para buscar o id do arquivo base (sem timestamp)
func getBaseFileID(db *sql.DB, path, host, share string) *int {
	var id int
	err := db.QueryRow("SELECT id FROM files WHERE path=? AND host=? AND share=? AND parent_id IS NULL LIMIT 1", path, host, share).Scan(&id)
	if err == nil {
		return &id
	}
	return nil
}

// CopySingleMatch processa um único resultado de busca imediatamente
func CopySingleMatch(ctx context.Context, db *sql.DB, shares map[string]*smb2.Share, result *search.SearchResult, config *CopyConfig, scanHost string, throttler *smb.Throttler) (*CopyResult, error) {
	if result.IsDirectory {
		if config.Verbose {
			logger.Debug("[COPY-DEBUG] Skipping directory: %s", result.FilePath)
		}
		return nil, nil
	}

	hostIP := extractHostIP(result.ShareName)
	if scanHost == "" {
		if config.Verbose {
			logger.Debug("[COPY-DEBUG] scanHost not defined for: %s", result.ShareName)
		}
		return nil, nil
	}

	if config.Verbose {
		logger.Debug("Processing file from host %s: %s", hostIP, result.FilePath)
		logger.Debug("    Share: %s", result.ShareName)
		logger.Debug("    Size: %s", formatSize(result.FileSize))
		logger.Debug("    Match type: %s", result.MatchType)
	}

	// Se estiver em modo no-copy, adicionar ao resultado da varredura
	if config.NoCopy || config.NoCopyDeep {
		scanMode := "no-copy"
		if config.NoCopyDeep {
			scanMode = "no-copy-deep"
		}
		// Usar o padrão de busca real em vez de MatchValue genérico
		matchPattern := result.MatchValue
		if matchPattern == "" || matchPattern == "Large File" {
			matchPattern = getSearchParamValue(result.MatchType, config, result.RegexMatch)
		}
		_, err := database.InsertLowHangingFruit(
			db,
			result.FilePath,
			scanHost,
			result.ShareName,
			config.Domain,
			config.Username,
			result.FileSize,
			time.Now(),
			"",
			matchPattern,
			result.MatchType,
			formatSize(result.FileSize),
			scanMode,
			result.FileSize > config.MaxFileSize,
		)
		if err != nil {
			logger.Error("Error saving low-hanging fruit to database: %v", err)
		}
		return nil, nil
	}

	// Se for um arquivo grande (identificado durante a busca)
	if result.FileSize > config.MaxFileSize {
		matchesCriteria := false
		fileName := filepath.Base(result.FilePath)
		for _, pattern := range config.FilenamePatterns {
			if strings.Contains(strings.ToLower(fileName), strings.ToLower(pattern)) {
				matchesCriteria = true
				break
			}
		}
		if !matchesCriteria && len(config.FileExtensions) > 0 {
			if matchesAnyExtension(filepath.Base(result.FilePath), config.FileExtensions) {
				matchesCriteria = true
			}
		}
		if !matchesCriteria && result.ContentMatch != "" {
			matchesCriteria = true
		}
		if !matchesCriteria && result.RegexMatch != "" {
			matchesCriteria = true
		}
		if matchesCriteria {
			scanMode := "large-file"
			// Usar o padrão de busca real em vez de MatchValue genérico
			matchPattern := result.MatchValue
			if matchPattern == "" || matchPattern == "Large File" {
				matchPattern = getSearchParamValue(result.MatchType, config, result.RegexMatch)
			}
			_, err := database.InsertLowHangingFruit(
				db,
				result.FilePath,
				scanHost,
				result.ShareName,
				config.Domain,
				config.Username,
				result.FileSize,
				time.Now(),
				"",
				matchPattern,
				result.MatchType,
				formatSize(result.FileSize),
				scanMode,
				true,
			)
			if err != nil {
				logger.Error("Error saving large file to low_hanging_fruit: %v", err)
			}
		}
		return nil, nil
	}

	// Throttler: rate-limit copy bandwidth before SMB ops
	if throttler != nil {
		_ = throttler.WaitN(ctx, int(result.FileSize))
	}

	share, ok := shares[result.ShareName]
	if !ok {
		logger.Error("Share not mounted: %s", result.ShareName)
		return nil, fmt.Errorf("share not mounted: %s", result.ShareName)
	}
	localPath := determineLocalPath(config.OutputDir, result, config)
	if err := os.MkdirAll(filepath.Dir(localPath), 0755); err != nil {
		logger.Error("Error creating local directory: %v", err)
		return nil, err
	}

	// --- INÍCIO LÓGICA DE VERSIONAMENTO CORRIGIDA ---
	// 1. Buscar registro base do arquivo no banco (parent_id nulo)
	var baseID *int
	var basePath string
	row := db.QueryRow("SELECT id, local_path FROM files WHERE path=? AND host=? AND share=? AND parent_id IS NULL LIMIT 1", result.FilePath, scanHost, result.ShareName)
	var id int
	var localPathDB string
	err := row.Scan(&id, &localPathDB)
	if err == nil {
		baseID = &id
		basePath = localPathDB
		// Normalize stale DB path to current output schema.
		// Prior runs may have used a different domain prefix (e.g. "WORKSTATION" or
		// the raw IP) that has since been normalised to "LOCAL". Re-home to the
		// freshly-computed localPath so all files converge on the canonical path.
		if basePath != localPath {
			if config.Verbose {
				logger.Debug("[COPY-DEBUG] Stale DB path detected, re-homing: %s → %s", basePath, localPath)
			}
			basePath = localPath
		}
	}

	// 2. Obter info do arquivo remoto
	remoteModTime := time.Time{}
	remoteSize := int64(0)
	if fi, err := share.Stat(result.FilePath); err == nil {
		remoteModTime = fi.ModTime().UTC().Truncate(time.Second)
		remoteSize = fi.Size()
	} else {
		if config.Verbose {
			logger.Debug("[COPY-DEBUG] Failed to stat remote file %s: %v", result.FilePath, err)
		}
	}

	// 3. Obter info do arquivo base local (se existir)
	localModTime := time.Time{}
	localSize := int64(0)
	if basePath != "" {
		if localInfo, err := os.Stat(basePath); err == nil {
			localModTime = localInfo.ModTime().UTC().Truncate(time.Second)
			localSize = localInfo.Size()
		}
	}

	if config.Verbose {
		logger.Debug("[COPY-DEBUG] Comparing remoteModTime=%v, localModTime=%v, diff=%v, remoteSize=%d, localSize=%d", remoteModTime, localModTime, absDuration(remoteModTime.Sub(localModTime)), remoteSize, localSize)
	}

	// 4. Se já existe registro base e NÃO mudou, não faz nada
	if baseID != nil && !remoteModTime.IsZero() && absDuration(remoteModTime.Sub(localModTime)) <= 2*time.Second && remoteSize == localSize {
		if config.Verbose {
			logger.Debug("[COPY-DEBUG] File already up-to-date, skipping: %s", basePath)
		}
		return nil, nil
	}

	// 5. Se já existe registro base e o arquivo mudou, criar snapshot do antigo antes de sobrescrever
	if baseID != nil && basePath != "" && (!remoteModTime.IsZero() && (absDuration(remoteModTime.Sub(localModTime)) > 2*time.Second || remoteSize != localSize)) {
		// Gerar nome do snapshot com timestamp do arquivo base antigo
		oldInfo, errStat := os.Stat(basePath)
		if errStat == nil {
			oldModTime := oldInfo.ModTime().UTC().Truncate(time.Second)
			oldTimestamp := oldModTime.Format("20060102_150405")
			dir := filepath.Dir(basePath)
			base := filepath.Base(basePath)
			ext := filepath.Ext(base)
			name := strings.TrimSuffix(base, ext)
			oldSnapshot := filepath.Join(dir, fmt.Sprintf("%s_%s%s", name, oldTimestamp, ext))
			if _, err := os.Stat(oldSnapshot); os.IsNotExist(err) {
				_ = copyFileLocal(basePath, oldSnapshot)
				// Registrar snapshot no banco
				dbErr := database.InsertFile(
					db,
					result.FilePath,  // path
					scanHost,         // host
					result.ShareName, // share
					config.Domain,    // domain
					config.Username,  // user
					oldInfo.Size(),   // size
					oldModTime,       // mod_time
					strings.TrimPrefix(strings.ToLower(filepath.Ext(result.FilePath)), "."), // file_type
					result.MatchValue,                      // match_pattern
					result.MatchType,                       // match_type
					"",                                     // hash
					oldSnapshot,                            // local_path
					formatSize(oldInfo.Size()),             // size_formatted
					oldInfo.Size() > config.MaxFileSize,    // large_file
					config.LeetSpeak,                       // leet_speak
					inferSearchParamType(result.MatchType), // search_param_type
				getSearchParamValue(result.MatchType, config, result.RegexMatch), // search_param_value
				baseID, // parent_id sempre aponta para o base
				config.ScanMode,
				)
				if dbErr != nil {
					logger.Error("[DB-ERROR] Failed to insert snapshot in database: %v", dbErr)
				} else if config.Verbose {
					logger.Debug("[DB-DEBUG] Inserted snapshot in database: %s", oldSnapshot)
				}
			}
		}
		// Sobrescreve o arquivo base com o conteúdo atualizado
		// basePath came from DB and may point to a directory that no longer exists.
		_ = os.MkdirAll(filepath.Dir(basePath), 0755)
		size, _, fileHash, err2 := copyFile(share, result.FilePath, basePath, result.ShareName, config)
		if err2 == nil {
			_ = os.Chtimes(basePath, remoteModTime, remoteModTime)
			_, errUpdate := db.Exec("UPDATE files SET size=?, mod_time=?, file_type=?, match_pattern=?, match_type=?, hash=?, local_path=?, size_formatted=?, large_file=?, leet_speak=?, search_param_type=?, search_param_value=? WHERE id=?",
				size,
				remoteModTime,
				strings.TrimPrefix(strings.ToLower(filepath.Ext(result.FilePath)), "."),
				result.MatchValue,
				result.MatchType,
				fileHash,
				basePath,
				formatSize(size),
				size > config.MaxFileSize,
				config.LeetSpeak,
				inferSearchParamType(result.MatchType),
				getSearchParamValue(result.MatchType, config, result.RegexMatch),
				*baseID,
			)
			if errUpdate != nil {
				logger.Error("[DB-ERROR] Failed to update base file in database: %v", errUpdate)
			}
		}
		return &CopyResult{
			ShareName:  result.ShareName,
			RemotePath: result.FilePath,
			LocalPath:  basePath,
			Size:       size,
			Success:    err2 == nil,
			Error:      err2,
		}, err2
	}

	// 6. Se não existe registro base, copiar e verificar dedup por hash.
	if baseID == nil {
		size, _, fileHash, err := copyFile(share, result.FilePath, localPath, result.ShareName, config)
		if err != nil {
			logger.Error("Error copying file: %v", err)
			return &CopyResult{
				ShareName:  result.ShareName,
				RemotePath: result.FilePath,
				LocalPath:  localPath,
				Size:       result.FileSize,
				Success:    false,
				Error:      err,
			}, err
		}
		// Hash dedup: if an identical file was already copied (same SHA-256),
		// remove our redundant copy and point this DB record at the existing one.
		if fileHash != "" {
			var dupLocalPath string
			dupErr := db.QueryRow(
				"SELECT local_path FROM files WHERE hash = ? AND hash != '' AND local_path != '' LIMIT 1",
				fileHash,
			).Scan(&dupLocalPath)
			if dupErr == nil && dupLocalPath != "" && dupLocalPath != localPath {
				os.Remove(localPath) // discard duplicate
				localPath = dupLocalPath
				if config.Verbose {
					logger.Debug("[HASH-DEDUP] %s already copied at %s — reusing", result.FilePath, dupLocalPath)
				}
			}
		}
		fileType := strings.TrimPrefix(strings.ToLower(filepath.Ext(result.FilePath)), ".")
		_, _ = database.InsertFileReturnID(
			db,
			result.FilePath,
			scanHost,
			result.ShareName,
			config.Domain,
			config.Username,
			size,
			remoteModTime,
			fileType,
			result.MatchValue,
			result.MatchType,
			fileHash,
			localPath,
			formatSize(size),
			size > config.MaxFileSize,
			config.LeetSpeak,
			inferSearchParamType(result.MatchType),
			getSearchParamValue(result.MatchType, config, result.RegexMatch),
			nil,
			config.ScanMode,
		)
		return &CopyResult{
			ShareName:  result.ShareName,
			RemotePath: result.FilePath,
			LocalPath:  localPath,
			Size:       size,
			Success:    true,
			Error:      nil,
		}, nil
	}

	return nil, nil
}

// determineLocalPath determina o caminho local para um arquivo copiado
func determineLocalPath(baseDir string, result *search.SearchResult, config *CopyConfig) string {
	// Limpar e normalizar o caminho do compartilhamento
	sharePath := strings.TrimPrefix(result.ShareName, "\\\\")
	sharePath = strings.TrimPrefix(sharePath, "\\")
	parts := strings.Split(sharePath, "\\")

	// Valores padrão caso não consiga extrair as informações
	hostIP := "unknown"
	shareName := "unknown"

	// Tentar extrair IP e nome do compartilhamento com segurança
	if len(parts) > 0 {
		hostIP = parts[0]
		if len(parts) > 1 {
			shareName = parts[1]
		}
	}

	// Path: baseDir/DOMAIN/USER/HOST/SHARE
	// When domain equals the host IP (local-auth scenario), use "LOCAL" to avoid
	// duplicating the IP in the path (e.g. output/LOCAL/user/192.168.1.1/share).
	domainDir := strings.ToUpper(config.Domain)
	if domainDir == "" || strings.EqualFold(domainDir, hostIP) {
		domainDir = "LOCAL"
	}
	pathParts := []string{baseDir, domainDir, strings.ToLower(config.Username), hostIP, shareName}

	// Pegar o caminho completo do arquivo
	filePath := result.FilePath

	// Adicionar o caminho completo mantendo todas as subpastas
	if filepath.Dir(filePath) != "." {
		pathParts = append(pathParts, filepath.Dir(filePath))
	}

	return filepath.Join(append(pathParts, filepath.Base(filePath))...)
}

// Função para salvar erro de acesso negado
func SaveAccessDeniedLog(host, path string) error {
	dir := filepath.Join("errors", "access_denied")
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}
	file := filepath.Join(dir, host+"_access_denied.json")

	var log AccessDeniedLog
	// Tentar carregar log existente
	if data, err := os.ReadFile(file); err == nil {
		_ = json.Unmarshal(data, &log)
	}
	log.Host = host
	// Evitar duplicidade
	for _, entry := range log.Entries {
		if entry == path {
			return nil
		}
	}
	log.Entries = append(log.Entries, path)
	data, err := json.MarshalIndent(log, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(file, data, 0644)
}

// Função auxiliar para montar o caminho de large_files
func LargeFilesOutputPath(domain, user, host string) string {
	dir := filepath.Join("targets", "large_files", strings.ToUpper(domain), strings.ToLower(user))
	_ = os.MkdirAll(dir, 0755)
	return filepath.Join(dir, host+"_large_files.json")
}
