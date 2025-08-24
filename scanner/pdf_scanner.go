package scanner

import (
	"bufio"
	"bytes"
	"io"
)

// PDFScanner implementa o scanner para arquivos PDF
type PDFScanner struct {
	reader io.ReadCloser
}

// NewPDFScanner cria um novo scanner para arquivos PDF
func NewPDFScanner(reader io.ReadCloser) FileScanner {
	return &PDFScanner{reader: reader}
}

// Scan processa o conteúdo do arquivo PDF
func (s *PDFScanner) Scan(callback func(content string) error) error {
	defer s.reader.Close()

	scanner := bufio.NewScanner(s.reader)
	scanner.Split(func(data []byte, atEOF bool) (advance int, token []byte, err error) {
		if atEOF && len(data) == 0 {
			return 0, nil, nil
		}

		// Procura por texto entre parênteses (comum em PDFs)
		if i := bytes.Index(data, []byte("(")); i >= 0 {
			if j := bytes.Index(data[i:], []byte(")")); j > 0 {
				return i + j + 1, data[i+1 : i+j], nil
			}
		}

		// Se não encontrou texto entre parênteses, avança
		if atEOF {
			return len(data), data, nil
		}

		return 0, nil, nil
	})

	for scanner.Scan() {
		text := scanner.Text()
		// Remove caracteres de controle e mantém apenas texto legível
		if len(text) > 0 && isPrintableText(text) {
			if err := callback(text); err != nil {
				return err
			}
		}
	}

	return scanner.Err()
}

// isPrintableText verifica se o texto contém caracteres legíveis
func isPrintableText(text string) bool {
	if len(text) < 3 { // Ignora strings muito curtas
		return false
	}

	printable := 0
	for _, r := range text {
		if r >= 32 && r < 127 { // ASCII printável
			printable++
		}
	}

	// Retorna true se pelo menos 80% dos caracteres são legíveis
	return float64(printable)/float64(len(text)) > 0.8
}
