package scanner

import (
	"bufio"
	"io"
	"strings"

	"github.com/nwaples/rardecode"
)

// RarScanner implements FileScanner for RAR archives.
// Iterates over each file entry and streams text content to the callback.
type RarScanner struct {
	reader io.ReadCloser
}

func NewRarScanner(reader io.ReadCloser) FileScanner {
	return &RarScanner{reader: reader}
}

func (s *RarScanner) Scan(callback func(content string) error) error {
	defer s.reader.Close()

	r, err := rardecode.NewReader(s.reader, "")
	if err != nil {
		return err
	}

	for {
		hdr, err := r.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
		if hdr.IsDir || strings.HasPrefix(hdr.Name, ".") {
			continue
		}

		sc := bufio.NewScanner(r)
		for sc.Scan() {
			if err := callback(sc.Text()); err != nil {
				return err
			}
		}
		// scanner.Err() returns nil after EOF or an unexpected error.
		// Non-fatal per entry — move on to the next file in the archive.
	}
	return nil
}
