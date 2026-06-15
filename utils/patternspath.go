package utils

import (
	"os"
	"path/filepath"
	"runtime"
)

func EnsureDefaultPatternsFile() (string, error) {
	home, _ := os.UserHomeDir()
	var baseDir string
	if runtime.GOOS == "windows" {
		appData := os.Getenv("APPDATA")
		if appData != "" {
			baseDir = filepath.Join(appData, "nullfang")
		} else {
			baseDir = filepath.Join(home, "AppData", "Roaming", "nullfang")
		}
	} else {
		baseDir = filepath.Join(home, ".local", "nullfang")
	}
	patternsDir := filepath.Join(baseDir, "patterns")
	err := os.MkdirAll(patternsDir, 0755)
	if err != nil {
		return "", err
	}
	defaultYamlPath := filepath.Join(patternsDir, "default.yaml")
	if _, err := os.Stat(defaultYamlPath); os.IsNotExist(err) {
		// Conteúdo padrão do YAML
		defaultContent := `patterns:
  # Senhas e credenciais
  credentials:
    - "password"
    - "senha"
    - "secret"
    - "credentials"
    - "admin"
    - "root"

  # Informações sensíveis
  sensitive:
    - "cpf"
    - "cnpj"
    - "ssn"
    - "credit card"
    - "cartao de credito"

  # Extensões de arquivo para buscar
  extensions:
    - ".txt"
    - ".doc"
    - ".docx"
    - ".xls"
    - ".xlsx"
    - ".pdf"
    - ".conf"
    - ".ini"
    - ".env"
    - ".config"
    - ".php"
    - ".html"
    - ".asp"
    - ".aspx"

  # Expressões regulares
  regex:
    - "[0-9]{3}\\.[0-9]{3}\\.[0-9]{3}-[0-9]{2}"  # CPF
    - "[0-9]{2}\\.[0-9]{3}\\.[0-9]{3}/[0-9]{4}-[0-9]{2}"  # CNPJ
    - "smtp\\.(gmail|outlook|yahoo)\\.com"  # Servidores de email
    - "\\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\\d{3})\\d{11})\\b"  # Cartões de crédito

  # Mapa de substituições leet speak
  leet_speak_map:
    a: ["4", "@", "A", "a"]
    b: ["8", "B", "b"]
    d: ["D", "d"]
    e: ["3", "E", "e"]
    g: ["6", "9", "G", "g"]
    h: ["H", "h", "#"]
    i: ["1", "!", "I", "i"]
    l: ["1", "L", "l"]
    n: ["N", "n"]
    o: ["0", "O", "o"]
    p: ["P", "p"]
    r: ["R", "r", "2"]
    s: ["5", "$", "S", "s"]
    t: ["7", "T", "t"]
    w: ["W", "vv", "w"]
    z: ["2", "Z", "z"]

  # Configurações de busca
  search_config:
    case_sensitive: false
    max_file_size: 10485760  # 10MB
    # Lista de shares a serem excluídos da busca (remova ou edite conforme necessário)
    excluded_shares:
      - "IPC$"
      - "ADMIN$"
    exclude:
      - "*.tmp"
    max_depth: 5
`
		err = os.WriteFile(defaultYamlPath, []byte(defaultContent), 0644)
		if err != nil {
			return "", err
		}
	}
	return defaultYamlPath, nil
}
