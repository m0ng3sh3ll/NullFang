package scanner

import (
	"bufio"
	"io"
	"strings"
)

// WebScanner implementa o scanner para arquivos web (HTML, JS, CSS)
type WebScanner struct {
	reader io.ReadCloser
}

// NewWebScanner cria um novo scanner para arquivos web
func NewWebScanner(reader io.ReadCloser) FileScanner {
	return &WebScanner{reader: reader}
}

// Scan processa o conteúdo do arquivo web
func (s *WebScanner) Scan(callback func(content string) error) error {
	defer s.reader.Close()

	scanner := bufio.NewScanner(s.reader)
	for scanner.Scan() {
		line := scanner.Text()

		// Remove comentários HTML
		if idx := strings.Index(line, "<!--"); idx >= 0 {
			if endIdx := strings.Index(line, "-->"); endIdx >= 0 {
				line = line[:idx] + line[endIdx+3:]
			}
		}

		// Remove tags HTML
		line = stripHTMLTags(line)

		// Remove comentários JS
		line = stripJSComments(line)

		// Remove comentários CSS
		line = stripCSSComments(line)

		// Se ainda houver conteúdo após a limpeza
		if cleanLine := strings.TrimSpace(line); len(cleanLine) > 0 {
			if err := callback(cleanLine); err != nil {
				return err
			}
		}
	}

	return scanner.Err()
}

// stripHTMLTags remove tags HTML do texto
func stripHTMLTags(text string) string {
	var result strings.Builder
	var inTag bool

	for _, char := range text {
		if char == '<' {
			inTag = true
			continue
		}
		if char == '>' {
			inTag = false
			continue
		}
		if !inTag {
			result.WriteRune(char)
		}
	}

	return result.String()
}

// stripJSComments remove comentários JavaScript
func stripJSComments(text string) string {
	// Remove comentários de linha única
	if idx := strings.Index(text, "//"); idx >= 0 {
		text = text[:idx]
	}

	// Remove comentários multilinhas (simplificado)
	if startIdx := strings.Index(text, "/*"); startIdx >= 0 {
		if endIdx := strings.Index(text, "*/"); endIdx >= 0 {
			text = text[:startIdx] + text[endIdx+2:]
		}
	}

	return text
}

// stripCSSComments remove comentários CSS
func stripCSSComments(text string) string {
	// Remove comentários CSS (simplificado)
	if startIdx := strings.Index(text, "/*"); startIdx >= 0 {
		if endIdx := strings.Index(text, "*/"); endIdx >= 0 {
			text = text[:startIdx] + text[endIdx+2:]
		}
	}

	return text
}
