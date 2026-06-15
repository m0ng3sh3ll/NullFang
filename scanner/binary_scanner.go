package scanner

import (
	"bufio"
	"io"
	"unicode/utf16"
	"unicode/utf8"
)

// BinaryScanner implementa a extração de strings de arquivos binários
// Implementa a interface FileScanner

type BinaryScanner struct {
	reader io.ReadCloser
	minLen int // tamanho mínimo da string
}

func NewBinaryScanner(reader io.ReadCloser, minLen int) FileScanner {
	if minLen < 2 {
		minLen = 4
	}
	return &BinaryScanner{reader: reader, minLen: minLen}
}

// Scan extrai strings legíveis do binário (ASCII e UTF-16) e chama o callback para cada uma
func (s *BinaryScanner) Scan(callback func(content string) error) error {
	defer s.reader.Close()
	buf := bufio.NewReader(s.reader)
	var (
		asciiBuf   []byte
		utf8Buf    []byte
		latin1Buf  []byte
		utf16leBuf []uint16
		utf16beBuf []uint16
	)
	flush := func() error {
		if len(asciiBuf) >= s.minLen {
			if err := callback(string(asciiBuf)); err != nil {
				return err
			}
		}
		if len(utf8Buf) >= s.minLen {
			if utf8.Valid(utf8Buf) {
				if err := callback(string(utf8Buf)); err != nil {
					return err
				}
			}
		}
		if len(latin1Buf) >= s.minLen {
			str := string(latin1Buf)
			if err := callback(str); err != nil {
				return err
			}
		}
		if len(utf16leBuf) >= s.minLen {
			str := string(utf16.Decode(utf16leBuf))
			if err := callback(str); err != nil {
				return err
			}
		}
		if len(utf16beBuf) >= s.minLen {
			str := string(utf16.Decode(utf16beBuf))
			if err := callback(str); err != nil {
				return err
			}
		}
		asciiBuf = asciiBuf[:0]
		utf8Buf = utf8Buf[:0]
		latin1Buf = latin1Buf[:0]
		utf16leBuf = utf16leBuf[:0]
		utf16beBuf = utf16beBuf[:0]
		return nil
	}
	for {
		b, err := buf.ReadByte()
		if err != nil {
			_ = flush()
			if err == io.EOF {
				return nil
			}
			return err
		}
		// ASCII
		if b >= 32 && b <= 126 {
			asciiBuf = append(asciiBuf, b)
			utf8Buf = append(utf8Buf, b)
			latin1Buf = append(latin1Buf, b)
		} else if b >= 0xA0 && b <= 0xFF { // Latin1/Win1252 extended
			latin1Buf = append(latin1Buf, b)
			utf8Buf = append(utf8Buf, b)
		} else {
			if err := flush(); err != nil {
				return err
			}
		}
		// UTF-8 multibyte
		if b >= 0xC2 && b <= 0xF4 { // Início de sequência UTF-8 válida
			utf8Buf = append(utf8Buf, b)
			for i := 1; i < 4; i++ {
				nb, err := buf.Peek(i)
				if err == nil && utf8.FullRune(nb) {
					utf8Buf = append(utf8Buf, nb...)
					_, _ = buf.Discard(i)
					break
				}
			}
		}
		// UTF-16LE
		b2, err2 := buf.Peek(1)
		if err2 == nil {
			// Little Endian
			if b2[0] == 0x00 && b >= 32 && b <= 126 {
				utf16leBuf = append(utf16leBuf, uint16(b)|uint16(b2[0])<<8)
				_, _ = buf.ReadByte() // consumir o segundo byte
				continue
			}
			// Big Endian
			if b == 0x00 && b2[0] >= 32 && b2[0] <= 126 {
				utf16beBuf = append(utf16beBuf, uint16(b)<<8|uint16(b2[0]))
				_, _ = buf.ReadByte() // consumir o segundo byte
				continue
			}
		}
	}
}
