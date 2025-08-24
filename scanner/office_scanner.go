package scanner

import (
	"archive/zip"
	"encoding/xml"
	"io"
	"path/filepath"
	"strings"
)

// OfficeScanner implementa o scanner para arquivos Office (DOCX, XLSX, PPTX)
type OfficeScanner struct {
	reader io.ReadCloser
}

// NewOfficeScanner cria um novo scanner para arquivos Office
func NewOfficeScanner(reader io.ReadCloser) FileScanner {
	return &OfficeScanner{reader: reader}
}

// Scan processa o conteúdo do arquivo Office
func (s *OfficeScanner) Scan(callback func(content string) error) error {
	defer s.reader.Close()

	seeker := s.reader.(io.Seeker)
	size, err := seeker.Seek(0, io.SeekEnd)
	if err != nil {
		return err
	}

	zipReader, err := zip.NewReader(s.reader.(io.ReaderAt), size)
	if err != nil {
		return err
	}

	for _, file := range zipReader.File {
		// Ignora diretórios e arquivos ocultos
		if file.FileInfo().IsDir() || strings.HasPrefix(file.Name, ".") {
			continue
		}

		// Processa apenas arquivos relevantes baseado na extensão
		switch filepath.Ext(file.Name) {
		case ".xml": // Arquivos XML principais
			if err := s.processXMLFile(file, callback); err != nil {
				return err
			}
		case ".rels": // Arquivos de relacionamento
			if err := s.processXMLFile(file, callback); err != nil {
				return err
			}
		}
	}

	return nil
}

// processXMLFile processa um arquivo XML dentro do documento Office
func (s *OfficeScanner) processXMLFile(file *zip.File, callback func(content string) error) error {
	rc, err := file.Open()
	if err != nil {
		return err
	}
	defer rc.Close()

	decoder := xml.NewDecoder(rc)
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		switch t := token.(type) {
		case xml.CharData:
			text := string(t)
			if cleanText := strings.TrimSpace(text); len(cleanText) > 0 {
				if err := callback(cleanText); err != nil {
					return err
				}
			}
		}
	}

	return nil
}

// IsOfficeFile verifica se o arquivo é um documento Office
func IsOfficeFile(header []byte) bool {
	// Verifica se é um arquivo ZIP (todos os arquivos Office modernos são ZIPs)
	if len(header) < 4 {
		return false
	}

	if header[0] != 0x50 || header[1] != 0x4B || header[2] != 0x03 || header[3] != 0x04 {
		return false
	}

	// Converte os primeiros bytes em string para procurar marcadores Office
	headerStr := string(header)
	officeMarkers := []string{
		"[Content_Types].xml",
		"word/",
		"xl/",
		"ppt/",
	}

	for _, marker := range officeMarkers {
		if strings.Contains(headerStr, marker) {
			return true
		}
	}

	return false
}
