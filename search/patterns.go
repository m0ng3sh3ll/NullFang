package search

import (
	"os"
	"unicode"

	"gopkg.in/yaml.v3"
)

// LeetSpeakMap define o mapeamento de caracteres para suas variações leet speak
type LeetSpeakMap map[string][]string

type SearchPatterns struct {
	Patterns struct {
		Credentials  []string     `yaml:"credentials"`
		Sensitive    []string     `yaml:"sensitive"`
		Extensions   []string     `yaml:"extensions"`
		Regex        []string     `yaml:"regex"`
		LeetSpeakMap LeetSpeakMap `yaml:"leet_speak_map"`
		SearchConfig struct {
			CaseSensitive  bool     `yaml:"case_sensitive"`
			MaxFileSize    int64    `yaml:"max_file_size"`
			Exclude        []string `yaml:"exclude"`
			ExcludedShares []string `yaml:"excluded_shares"`
			MaxDepth       int      `yaml:"max_depth"`
		} `yaml:"search_config"`
	} `yaml:"patterns"`

	// Settings holds advanced execution configuration.
	// All fields are optional — unset fields keep their compiled-in defaults.
	// Populated from the `settings:` section of the -config YAML file.
	Settings ScanSettings `yaml:"settings"`
}

// ScanSettings is the structured form of the `settings:` block in nullfang.yaml.
// CLI flags and --stealth always take precedence over values here.
type ScanSettings struct {
	Performance struct {
		// Threads: concurrent host scan goroutines. Default: 10.
		// Lower for stealth; raise only on fast internal networks.
		Threads int `yaml:"threads"`

		// Timeout: per-host scan timeout (e.g. "5m", "30s"). Default: "5m".
		Timeout string `yaml:"timeout"`

		// CopyTimeout: per-file copy timeout. Default: "2m".
		CopyTimeout string `yaml:"copy_timeout"`

		// AuthTimeout: SMB session-setup timeout. Default: "30s".
		AuthTimeout string `yaml:"auth_timeout"`

		// MaxConnsPerHost: SMB connection pool size per host. Default: 5.
		// Set to 1 for stealth (single persistent session).
		MaxConnsPerHost int `yaml:"max_conns_per_host"`

		// MaxConcurrent: global in-flight SMB operations cap. Default: 10.
		MaxConcurrent int `yaml:"max_concurrent"`

		// ChunkSize: read chunk for large files (e.g. "256k", "1m", "4m"). Default: "1m".
		ChunkSize string `yaml:"chunk_size"`

		// BufferSize: I/O buffer per operation (e.g. "8k", "32k"). Default: "32k".
		BufferSize string `yaml:"buffer_size"`

		// LRUCacheSize: in-memory file content cache entries. Default: 512.
		// Increase on hosts with many repeated small files.
		LRUCacheSize int `yaml:"lru_cache_size"`

		// BatchSize: operations per batch flush. Default: 100.
		BatchSize int `yaml:"batch_size"`

		// MiniBatchSize: files per mini-batch in batch mode. Default: 10.
		MiniBatchSize int `yaml:"mini_batch_size"`

		// BatchTimeout: batch flush interval. Default: "2s".
		BatchTimeout string `yaml:"batch_timeout"`

		// BatchMode: enable batched copy (reduces SMB round-trips). Default: false.
		BatchMode bool `yaml:"batch_mode"`

		// PerHostLimit: enable per-host bandwidth throttling. Default: false.
		PerHostLimit bool `yaml:"per_host_limit"`

		// MaxHostBandwidth: bandwidth cap per host when per_host_limit is true
		// (e.g. "512k", "5m", "10m"). Default: "10m".
		MaxHostBandwidth string `yaml:"max_host_bandwidth"`
	} `yaml:"performance"`

	Search struct {
		// MaxSize: max file size in bytes to inspect. Default: 10485760 (10 MB).
		// Files above this are reported but not content-searched.
		MaxSize int64 `yaml:"max_size"`

		// MaxDepth: max directory recursion depth. Default: 10.
		// Set to 1-3 for shallow recon of share roots.
		MaxDepth int `yaml:"max_depth"`

		// CaseSensitive: match patterns case-sensitively. Default: false.
		CaseSensitive bool `yaml:"case_sensitive"`

		// LeetSpeak: auto-generate leet-speak variants of -m patterns. Default: false.
		LeetSpeak bool `yaml:"leet_speak"`

		// Binary: extract printable strings from binary files. Default: false.
		// Slow; only enable when targeting executables or firmware.
		Binary bool `yaml:"binary"`

		// MinBinaryString: min printable-string length during binary extraction. Default: 4.
		MinBinaryString int `yaml:"min_binary_string"`

		// MaxCacheFileSize: max file size (bytes) to keep in the LRU content cache. Default: 1048576 (1 MB).
		MaxCacheFileSize int64 `yaml:"max_cache_file_size"`

		// ExcludePatterns: file name/extension patterns to skip during copy.
		// Supports globs: ["*.ini", "thumbs.db", "desktop.ini"]
		ExcludePatterns []string `yaml:"exclude_patterns"`

		// MinDate: only process files modified on or after this date (YYYY-MM-DD). Default: "".
		MinDate string `yaml:"min_date"`

		// MaxDate: only process files modified on or before this date (YYYY-MM-DD). Default: "".
		MaxDate string `yaml:"max_date"`

		// DirConcurrency: max concurrent directory opens during recursive scan. Default: 4.
		// Higher values speed up deep trees but increase concurrent SMB ops.
		DirConcurrency int `yaml:"dir_concurrency"`
	} `yaml:"search"`

	Stealth struct {
		// OperationDelayMs: base delay in ms between directory entries; feeds humanBrowseDelay()
		// which adds asymmetric jitter (70% fast, 25% medium, 5% long pause).
		// Default: 0 (disabled). --stealth sets 500.
		// Rule of thumb: 200 = light, 500 = realistic human, 1000 = very slow.
		OperationDelayMs int `yaml:"operation_delay_ms"`

		// ShareJitterMs: max random delay in ms between share mounts. Default: 0.
		// --stealth sets 500. Independent from operation_delay_ms.
		ShareJitterMs int `yaml:"share_jitter_ms"`

		// PreserveAtime: restore file atime after content read. Default: false.
		// Requires write-attr permission. --stealth enables.
		PreserveAtime bool `yaml:"preserve_atime"`

		// DisableRandomize: set true to scan shares/dirs in fixed order. Default: false.
		// Randomized order is the default (stealth-friendly).
		DisableRandomize bool `yaml:"disable_randomize"`

		// DisableCanarySkip: set true to process honeypot/canary files. Default: false.
		// By default canary files are skipped to avoid triggering traps.
		DisableCanarySkip bool `yaml:"disable_canary_skip"`
	} `yaml:"stealth"`

	Network struct {
		// SMBDialect: force a specific SMB dialect. Default: "" (auto-negotiate).
		// Valid values: SMB311, SMB302, SMB300, SMB210, SMB202.
		// Only set if the target has compatibility issues with SMB3.1.1.
		SMBDialect string `yaml:"smb_dialect"`

		// SMBSigning: force signing. Default: "" (follow server policy).
		// Valid values: "on", "off". Leave empty unless debugging relay issues.
		SMBSigning string `yaml:"smb_signing"`
	} `yaml:"network"`
}

func LoadPatterns(filename string) (*SearchPatterns, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var patterns SearchPatterns
	if err := yaml.Unmarshal(data, &patterns); err != nil {
		return nil, err
	}

	return &patterns, nil
}

// MergePatterns combina padrões da linha de comando com padrões do arquivo
// Se flags de busca (-m, -e, -r) forem passadas, só o leet_speak_map do arquivo é mantido
func MergePatterns(cmdPatterns, filePatterns *SearchPatterns) *SearchPatterns {
	result := &SearchPatterns{}

	// Prioriza padrões da linha de comando
	if len(cmdPatterns.Patterns.Credentials) > 0 {
		result.Patterns.Credentials = cmdPatterns.Patterns.Credentials
	} else {
		result.Patterns.Credentials = filePatterns.Patterns.Credentials
	}

	if len(cmdPatterns.Patterns.Extensions) > 0 {
		result.Patterns.Extensions = cmdPatterns.Patterns.Extensions
	} else {
		result.Patterns.Extensions = filePatterns.Patterns.Extensions
	}

	if len(cmdPatterns.Patterns.Regex) > 0 {
		result.Patterns.Regex = cmdPatterns.Patterns.Regex
	} else {
		result.Patterns.Regex = filePatterns.Patterns.Regex
	}

	// Copiar o mapeamento leet speak do arquivo de padrões
	result.Patterns.LeetSpeakMap = filePatterns.Patterns.LeetSpeakMap

	return result
}

// ProcessLeetSpeak gera variações de uma palavra usando o mapeamento leet speak
func (sp *SearchPatterns) ProcessLeetSpeak(word string) []string {
	variations := make(map[string]bool)
	variations[word] = true // Adiciona a palavra original

	// Converte a palavra em um slice de caracteres para manipulação
	chars := []rune(word)

	// Função recursiva para gerar todas as combinações possíveis
	var generateVariations func(current []rune, position int, depth int)
	generateVariations = func(current []rune, position int, depth int) {
		// Adiciona a variação atual ao mapa
		variations[string(current)] = true

		// Se chegamos ao final da palavra ou atingimos profundidade máxima, retornamos
		if position >= len(chars) || depth > 10 {
			return
		}

		// Para cada posição, tentamos todas as substituições possíveis
		for pos := position; pos < len(chars); pos++ {
			char := string(unicode.ToLower(current[pos]))

			// Tenta substituições leet speak
			if replacements, ok := sp.Patterns.LeetSpeakMap[char]; ok {
				for _, replacement := range replacements {
					// Cria uma nova variação com a substituição atual
					newVariation := make([]rune, len(current))
					copy(newVariation, current)
					newVariation[pos] = []rune(replacement)[0]

					// Adiciona a nova variação
					variations[string(newVariation)] = true

					// Continua gerando variações a partir desta posição
					generateVariations(newVariation, pos+1, depth+1)
				}
			}

			// Tenta variações de caso (maiúsculo/minúsculo)
			if unicode.IsLetter(current[pos]) {
				// Variação em maiúsculo
				upperVariation := make([]rune, len(current))
				copy(upperVariation, current)
				upperVariation[pos] = unicode.ToUpper(upperVariation[pos])
				variations[string(upperVariation)] = true
				generateVariations(upperVariation, pos+1, depth+1)

				// Variação em minúsculo
				lowerVariation := make([]rune, len(current))
				copy(lowerVariation, current)
				lowerVariation[pos] = unicode.ToLower(lowerVariation[pos])
				variations[string(lowerVariation)] = true
				generateVariations(lowerVariation, pos+1, depth+1)
			}
		}

		// Gera variações combinando substituições em diferentes posições
		for i := position; i < len(chars)-1; i++ {
			for j := i + 1; j < len(chars); j++ {
				char1 := string(unicode.ToLower(current[i]))
				char2 := string(unicode.ToLower(current[j]))

				if replacements1, ok1 := sp.Patterns.LeetSpeakMap[char1]; ok1 {
					if replacements2, ok2 := sp.Patterns.LeetSpeakMap[char2]; ok2 {
						for _, repl1 := range replacements1 {
							for _, repl2 := range replacements2 {
								newVariation := make([]rune, len(current))
								copy(newVariation, current)
								newVariation[i] = []rune(repl1)[0]
								newVariation[j] = []rune(repl2)[0]
								variations[string(newVariation)] = true
							}
						}
					}
				}
			}
		}
	}

	// Inicia a geração de variações com a palavra original
	generateVariations(chars, 0, 0)

	// Converte o map para slice
	result := make([]string, 0, len(variations))
	for v := range variations {
		result = append(result, v)
	}

	return result
}
