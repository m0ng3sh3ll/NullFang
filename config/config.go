package config

import (
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// SearchPatterns representa a estrutura do arquivo YAML de padrões
type SearchPatterns struct {
	Patterns struct {
		Credentials  []string `yaml:"credentials"`
		Sensitive    []string `yaml:"sensitive"`
		Extensions   []string `yaml:"extensions"`
		Regex        []string `yaml:"regex"`
		SearchConfig struct {
			CaseSensitive bool  `yaml:"case_sensitive"`
			MaxFileSize   int64 `yaml:"max_file_size"`
		} `yaml:"search_config"`
	} `yaml:"patterns"`
}

// LoadPatterns carrega os padrões de busca de um arquivo YAML
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

// LoadDefaultPatterns carrega os padrões padrão do arquivo default.yaml
func LoadDefaultPatterns() (*SearchPatterns, error) {
	// Tenta encontrar o arquivo default.yaml no diretório patterns
	defaultPath := filepath.Join("patterns", "default.yaml")
	return LoadPatterns(defaultPath)
}

// MergePatterns combina padrões da linha de comando com padrões do arquivo
// Prioriza os padrões da linha de comando se existirem
func MergePatterns(cmdPatterns, filePatterns *SearchPatterns) *SearchPatterns {
	result := &SearchPatterns{}

	// Se existem padrões na linha de comando, usa eles
	// Caso contrário, usa os padrões do arquivo
	if cmdPatterns != nil && len(cmdPatterns.Patterns.Credentials) > 0 {
		result.Patterns.Credentials = cmdPatterns.Patterns.Credentials
	} else {
		result.Patterns.Credentials = filePatterns.Patterns.Credentials
	}

	// Mesmo processo para outros tipos de padrões...

	return result
}
