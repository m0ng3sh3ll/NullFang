package scanner

import (
	"bufio"
	"bytes"
	"io"
	"strings"

	"github.com/bodgit/sevenzip"
)

// SevenZScanner implements FileScanner for 7-Zip archives.
// Reads the entire archive into memory (bounded by MaxFileSize) then iterates entries.
type SevenZScanner struct {
	reader io.ReadCloser
}

func NewSevenZScanner(reader io.ReadCloser) FileScanner {
	return &SevenZScanner{reader: reader}
}

func (s *SevenZScanner) Scan(callback func(content string) error) error {
	defer s.reader.Close()

	// sevenzip.NewReader requires io.ReaderAt + size; read into memory once.
	content, err := io.ReadAll(s.reader)
	if err != nil {
		return err
	}

	r, err := sevenzip.NewReader(bytes.NewReader(content), int64(len(content)))
	if err != nil {
		return err
	}

	for _, f := range r.File {
		if f.FileInfo().IsDir() || strings.HasPrefix(f.Name, ".") {
			continue
		}

		rc, err := f.Open()
		if err != nil {
			continue
		}

		sc := bufio.NewScanner(rc)
		for sc.Scan() {
			if err := callback(sc.Text()); err != nil {
				rc.Close()
				return err
			}
		}
		rc.Close()
	}
	return nil
}
