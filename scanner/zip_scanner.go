package scanner

import (
	"archive/zip"
	"bufio"
	"io"
	"strings"
)

// ZipScanner implementa o scanner para arquivos ZIP
type ZipScanner struct {
	reader io.ReadCloser
}

// NewZipScanner cria um novo scanner para arquivos ZIP
func NewZipScanner(reader io.ReadCloser) FileScanner {
	return &ZipScanner{reader: reader}
}

// Scan processa o conteúdo do arquivo ZIP
func (s *ZipScanner) Scan(callback func(content string) error) error {
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
		// Ignora diretórios
		if file.FileInfo().IsDir() {
			continue
		}

		// Ignora arquivos ocultos
		if strings.HasPrefix(file.Name, ".") {
			continue
		}

		rc, err := file.Open()
		if err != nil {
			continue
		}

		scanner := bufio.NewScanner(rc)
		for scanner.Scan() {
			if err := callback(scanner.Text()); err != nil {
				rc.Close()
				return err
			}
		}

		rc.Close()
		if err := scanner.Err(); err != nil {
			return err
		}
	}

	return nil
}
