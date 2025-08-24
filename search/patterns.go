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
