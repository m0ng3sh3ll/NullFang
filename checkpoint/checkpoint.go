package checkpoint

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type CheckpointData struct {
	StartTime       time.Time             `json:"start_time"`
	LastUpdate      time.Time             `json:"last_update"`
	Network         string                `json:"network"`
	User            string                `json:"user"`
	Domain          string                `json:"domain"`
	SearchPattern   string                `json:"search_pattern"`
	LeetSpeak       bool                  `json:"leet_speak"`
	NoCopy          bool                  `json:"no_copy"`
	NoCopyDeep      bool                  `json:"no_copy_deep"`
	ProcessedHosts  []string              `json:"processed_hosts"`
	PendingHosts    []string              `json:"pending_hosts"`
	FoundFiles      map[string][]FileInfo `json:"found_files"`  // host -> []FileInfo
	FailedHosts     map[string]string     `json:"failed_hosts"` // host -> erro
	OutputDir       string                `json:"output_dir"`
	ExcludePatterns []string              `json:"exclude_patterns,omitempty"`
	ExcludedShares  []string              `json:"excluded_shares,omitempty"`
	MinDate         string                `json:"min_date,omitempty"`
	MaxDate         string                `json:"max_date,omitempty"`
}

type FileInfo struct {
	Path        string    `json:"path"`
	ShareName   string    `json:"share_name"`
	Size        int64     `json:"size"`
	Found       time.Time `json:"found"`
	Occurrences []Match   `json:"occurrences,omitempty"` // Lista de ocorrências encontradas no arquivo
}

type Match struct {
	LineNumber int    `json:"line_number,omitempty"` // Número da linha onde foi encontrado
	Content    string `json:"content,omitempty"`     // Conteúdo encontrado
	Pattern    string `json:"pattern,omitempty"`     // Padrão que matched
}

type Checkpoint struct {
	data     *CheckpointData
	filename string
	mu       sync.Mutex
}

// SimplifiedLogEntry representa uma entrada simplificada para o log
type SimplifiedLogEntry struct {
	Path      string    `json:"path"`
	ShareName string    `json:"share_name"`
	Size      int64     `json:"size"`
	Found     time.Time `json:"found"`
	Pattern   string    `json:"pattern,omitempty"`
	Content   string    `json:"content,omitempty"`
	NoCopy    bool      `json:"no_copy"`
}

func New(network, user, domain, pattern string, hosts []string, outputDir string, excludePatterns, excludedShares []string, minDate, maxDate string) *Checkpoint {
	return &Checkpoint{
		data: &CheckpointData{
			StartTime:       time.Now(),
			LastUpdate:      time.Now(),
			Network:         network,
			User:            user,
			Domain:          domain,
			SearchPattern:   pattern,
			ProcessedHosts:  make([]string, 0),
			PendingHosts:    hosts,
			FoundFiles:      make(map[string][]FileInfo),
			FailedHosts:     make(map[string]string),
			OutputDir:       outputDir,
			ExcludePatterns: excludePatterns,
			ExcludedShares:  excludedShares,
			MinDate:         minDate,
			MaxDate:         maxDate,
		},
		filename: fmt.Sprintf("nullfang_resume_%s.json", time.Now().Format("20060102_150405")),
	}
}

func (c *Checkpoint) Save() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Atualizar timestamp
	c.data.LastUpdate = time.Now()

	// Criar diretório se não existir
	dir := filepath.Dir(c.filename)
	if dir != "." {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return fmt.Errorf("Error creating directory %s: %v", dir, err)
		}
	}

	// Serializar dados
	data, err := json.MarshalIndent(c.data, "", "  ")
	if err != nil {
		return fmt.Errorf("Error serializing data: %v", err)
	}

	// Salvar arquivo
	if err := os.WriteFile(c.filename, data, 0600); err != nil {
		return fmt.Errorf("Error writing file: %v", err)
	}

	return nil
}

func Load(filename string) (*Checkpoint, error) {
	// Verifica se o arquivo existe
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		return nil, fmt.Errorf("checkpoint file not found: %s", filename)
	}

	// Lê o arquivo
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read checkpoint file: %v", err)
	}

	var checkpointData CheckpointData
	if err := json.Unmarshal(data, &checkpointData); err != nil {
		return nil, fmt.Errorf("failed to parse checkpoint data: %v", err)
	}

	return &Checkpoint{
		data:     &checkpointData,
		filename: filename,
		mu:       sync.Mutex{},
	}, nil
}

func (c *Checkpoint) MarkHostProcessed(host string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Remove from pending
	newPending := make([]string, 0, len(c.data.PendingHosts))
	for _, h := range c.data.PendingHosts {
		if h != host {
			newPending = append(newPending, h)
		}
	}
	c.data.PendingHosts = newPending

	// Add to processed if not already there
	for _, h := range c.data.ProcessedHosts {
		if h == host {
			return
		}
	}
	c.data.ProcessedHosts = append(c.data.ProcessedHosts, host)
	c.data.LastUpdate = time.Now()
}

func (c *Checkpoint) AddFoundFile(host string, fileInfo *FileInfo) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Verificar se já existe um arquivo com mesmo path e share
	if files, exists := c.data.FoundFiles[host]; exists {
		for i, existing := range files {
			if existing.Path == fileInfo.Path && existing.ShareName == fileInfo.ShareName {
				// Atualizar o arquivo existente
				if len(fileInfo.Occurrences) > 0 {
					// Adicionar novas ocorrências
					files[i].Occurrences = append(files[i].Occurrences, fileInfo.Occurrences...)
				}
				// Atualizar timestamp se mais recente
				if fileInfo.Found.After(files[i].Found) {
					files[i].Found = fileInfo.Found
				}
				// Atualizar tamanho se diferente
				if fileInfo.Size != files[i].Size {
					files[i].Size = fileInfo.Size
				}
				c.data.FoundFiles[host] = files
				return
			}
		}
		// Se não encontrou, adiciona como novo arquivo
		c.data.FoundFiles[host] = append(files, *fileInfo)
	} else {
		// Se não existe entrada para o host, cria uma nova
		c.data.FoundFiles[host] = []FileInfo{*fileInfo}
	}
}

func (c *Checkpoint) GetFoundFiles(host string) []FileInfo {
	c.mu.Lock()
	defer c.mu.Unlock()

	if files, exists := c.data.FoundFiles[host]; exists {
		return files
	}
	return nil
}

func (c *Checkpoint) GetAllFoundFiles() map[string][]FileInfo {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Criar uma cópia do mapa para evitar condições de corrida
	files := make(map[string][]FileInfo)
	for host, fileInfos := range c.data.FoundFiles {
		files[host] = append([]FileInfo{}, fileInfos...)
	}
	return files
}

func (c *Checkpoint) GetPendingHosts() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string{}, c.data.PendingHosts...)
}

func (c *Checkpoint) GetProcessedHosts() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string{}, c.data.ProcessedHosts...)
}

func ListCheckpoints() ([]string, error) {
	files, err := filepath.Glob("nullfang_resume_*.json")
	if err != nil {
		return nil, err
	}
	return files, nil
}

func (c *Checkpoint) GetFilename() string {
	return c.filename
}

func (c *Checkpoint) SetFilename(filename string) {
	c.filename = filename
}

func (c *Checkpoint) GetNetwork() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.data.Network
}

func (c *Checkpoint) GetUser() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.data.User
}

func (c *Checkpoint) GetSearchPattern() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.data.SearchPattern
}

func (c *Checkpoint) AddFailedHost(host, reason string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.data.FailedHosts[host] = reason
}

func (c *Checkpoint) GetFailedHosts() map[string]string {
	c.mu.Lock()
	defer c.mu.Unlock()
	result := make(map[string]string)
	for host, reason := range c.data.FailedHosts {
		result[host] = reason
	}
	return result
}

func (c *Checkpoint) GetDomain() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.data.Domain
}

// GetFoundFilesCount retorna o número real de arquivos únicos encontrados
func (c *Checkpoint) GetFoundFilesCount() int {
	c.mu.Lock()
	defer c.mu.Unlock()

	count := 0
	seen := make(map[string]bool)

	for _, files := range c.data.FoundFiles {
		for _, file := range files {
			key := fmt.Sprintf("%s:%s", file.ShareName, file.Path)
			if !seen[key] {
				seen[key] = true
				count++
			}
		}
	}

	return count
}

// CreateSimplifiedLog cria uma versão simplificada do log para relatórios
func (c *Checkpoint) CreateSimplifiedLog(outputPath string) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Criar o objeto final do log
	logData := struct {
		StartTime     time.Time         `json:"start_time"`
		User          string            `json:"user"`
		Domain        string            `json:"domain"`
		SearchPattern string            `json:"search_pattern"`
		LeetSpeak     bool              `json:"leet_speak"`
		NoCopy        bool              `json:"no_copy"`
		FoundFiles    map[string]string `json:"found_files"` // host -> caminho do arquivo de cópia
	}{
		StartTime:     c.data.StartTime,
		User:          c.data.User,
		Domain:        c.data.Domain,
		SearchPattern: c.data.SearchPattern,
		LeetSpeak:     c.data.LeetSpeak,
		NoCopy:        c.data.NoCopy,
		FoundFiles:    make(map[string]string),
	}

	// Para cada host, apontar para o arquivo de cópia correspondente
	for host := range c.data.FoundFiles {
		logData.FoundFiles[host] = fmt.Sprintf("copy/%s.json", host)
	}

	// Serializar para JSON com indentação
	data, err := json.MarshalIndent(logData, "", "  ")
	if err != nil {
		return fmt.Errorf("Error serializing simplified log: %v", err)
	}

	// Salvar arquivo
	if err := os.WriteFile(outputPath, data, 0600); err != nil {
		return fmt.Errorf("Error writing simplified log: %v", err)
	}

	return nil
}

// GetLeetSpeak retorna se a busca usa leet speak
func (c *Checkpoint) GetLeetSpeak() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.data.LeetSpeak
}

// SetLeetSpeak define se a busca usa leet speak
func (c *Checkpoint) SetLeetSpeak(useLeet bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.data.LeetSpeak = useLeet
}

// GetNoCopy retorna se a execução está em modo no-copy
func (c *Checkpoint) GetNoCopy() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.data.NoCopy
}

// SetNoCopy define se a execução está em modo no-copy
func (c *Checkpoint) SetNoCopy(noCopy bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.data.NoCopy = noCopy
}

func (c *Checkpoint) GetMinDate() string {
	return c.data.MinDate
}

func (c *Checkpoint) GetMaxDate() string {
	return c.data.MaxDate
}

// GetNoCopyDeep retorna se a execução está em modo no-copy-deep
func (c *Checkpoint) GetNoCopyDeep() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.data.NoCopyDeep
}

// SetNoCopyDeep define se a execução está em modo no-copy-deep
func (c *Checkpoint) SetNoCopyDeep(noCopyDeep bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.data.NoCopyDeep = noCopyDeep
}
