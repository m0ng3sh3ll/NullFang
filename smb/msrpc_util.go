package smb

import (
	"encoding/binary"
	"fmt"
	"io"
	"strings"

	"github.com/m0ng3sh3ll/NullFang/go-smb2-patch"
)

// GetRemoteHostnameSRVSVC faz uma chamada NetServerGetInfo via SRVSVC para obter o NetBIOS name real do host
func GetRemoteHostnameSRVSVC(session *smb2.Session, host string) (string, error) {
	if session == nil {
		return "", fmt.Errorf("session SMB2 is nil")
	}
	// Monta o IPC$ e abre a pipe srvsvc
	fs, err := session.Mount("IPC$")
	if err != nil {
		return "", fmt.Errorf("error mounting IPC$: %v", err)
	}
	defer fs.Umount()

	f, err := fs.OpenFile("srvsvc", 2, 0666) // os.O_RDWR = 2
	if err != nil {
		return "", fmt.Errorf("error opening srvsvc pipe: %v", err)
	}
	defer f.Close()

	callId := uint32(1)

	// BIND
	bind := buildSRVSVCBind(callId)
	if _, err := f.Write(bind); err != nil {
		return "", fmt.Errorf("error sending bind: %v", err)
	}
	bindResp := make([]byte, 256)
	if _, err := io.ReadFull(f, bindResp); err != nil {
		return "", fmt.Errorf("error reading bind response: %v", err)
	}
	if bindResp[2] != 12 { // BIND_ACK
		return "", fmt.Errorf("bind failed, type: %d", bindResp[2])
	}

	callId++

	// REQUEST NetServerGetInfo (opnum 21, nível 102)
	serverUNC := toUNC(host)
	request := buildNetServerGetInfoRequest(callId, serverUNC)
	if _, err := f.Write(request); err != nil {
		return "", fmt.Errorf("error sending NetServerGetInfo: %v", err)
	}
	resp := make([]byte, 4096)
	if _, err := io.ReadFull(f, resp); err != nil {
		return "", fmt.Errorf("error reading NetServerGetInfo response: %v", err)
	}
	// Decodifica sv102_name
	name := parseNetServerGetInfoResponse(resp)
	if name == "" {
		return "", fmt.Errorf("error extracting hostname from SRVSVC response")
	}
	return name, nil
}

func buildSRVSVCBind(callId uint32) []byte {
	// BIND para SRVSVC (copiado do impacket e msrpc.go)
	bind := make([]byte, 72)
	bind[0] = 5                                        // RPC_VERSION
	bind[1] = 0                                        // RPC_VERSION_MINOR
	bind[2] = 11                                       // RPC_TYPE_BIND
	bind[3] = 3                                        // FIRST|LAST
	binary.LittleEndian.PutUint16(bind[8:10], 72)      // frag len
	binary.LittleEndian.PutUint32(bind[12:16], callId) // call id
	binary.LittleEndian.PutUint16(bind[16:18], 4280)   // max xmit
	binary.LittleEndian.PutUint16(bind[18:20], 4280)   // max recv
	binary.LittleEndian.PutUint32(bind[24:28], 1)      // num ctx items
	binary.LittleEndian.PutUint16(bind[28:30], 0)      // ctx id
	binary.LittleEndian.PutUint16(bind[30:32], 1)      // num trans items
	// SRVSVC UUID
	copy(bind[32:48], []byte{0xc8, 0x4f, 0x32, 0x4b, 0x70, 0x16, 0xd3, 0x01, 0x12, 0x78, 0x5a, 0x47, 0xbf, 0x6e, 0xe1, 0x88})
	binary.LittleEndian.PutUint16(bind[48:50], 3) // SRVSVC_VERSION
	binary.LittleEndian.PutUint16(bind[50:52], 0)
	// NDR UUID
	copy(bind[52:68], []byte{0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11, 0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60})
	binary.LittleEndian.PutUint32(bind[68:72], 2) // NDR_VERSION
	return bind
}

func buildNetServerGetInfoRequest(callId uint32, serverUNC string) []byte {
	// Monta o pacote NetServerGetInfo (opnum 21, nível 102)
	unc16 := utf16le(serverUNC)
	count := len(unc16)/2 + 1
	buf := make([]byte, 40+len(unc16)+2+4+4+4+4+4+4+4) // tamanho suficiente
	buf[0] = 5                                         // RPC_VERSION
	buf[1] = 0                                         // RPC_VERSION_MINOR
	buf[2] = 0                                         // RPC_TYPE_REQUEST
	buf[3] = 3                                         // FIRST|LAST
	binary.LittleEndian.PutUint32(buf[12:16], callId)
	binary.LittleEndian.PutUint16(buf[22:24], 21) // opnum NetServerGetInfo
	// pointer to server UNC
	binary.LittleEndian.PutUint32(buf[24:28], 0x20000)
	binary.LittleEndian.PutUint32(buf[28:32], uint32(count))
	binary.LittleEndian.PutUint32(buf[32:36], 0)
	binary.LittleEndian.PutUint32(buf[36:40], uint32(count))
	copy(buf[40:], unc16)
	// pointer level
	off := 40 + len(unc16) + 2
	binary.LittleEndian.PutUint32(buf[off:off+4], 102) // nível 102
	return buf[:off+4]
}

func utf16le(s string) []byte {
	// Codifica string em UTF-16LE + null terminator
	b := make([]byte, len(s)*2+2)
	for i, r := range s {
		binary.LittleEndian.PutUint16(b[i*2:], uint16(r))
	}
	return b
}

func toUNC(host string) string {
	if i := strings.Index(host, ":"); i > 0 {
		host = host[:i]
	}
	return "\\" + host
}

func parseNetServerGetInfoResponse(resp []byte) string {
	// Procura por o nome NetBIOS (sv102_name) na resposta
	// O nome geralmente aparece como UTF-16LE logo após o header
	for i := 0; i < len(resp)-32; i++ {
		if resp[i] == 0 && resp[i+1] == 0 && resp[i+2] != 0 && resp[i+3] == 0 {
			// Possível início do nome
			name := decodeUTF16LE(resp[i+2 : i+32])
			name = strings.Trim(name, "\x00")
			if len(name) > 0 && len(name) < 32 {
				return name
			}
		}
	}
	return ""
}

// GetShareTypes returns a map of share name → share type for the given host.
// Share types: 0=disk, 1=printer, 2=device, 3=IPC; upper bits are flags (0x80000000=hidden).
// Returns nil on error (caller should fall back to mount-and-check).
func GetShareTypes(session *smb2.Session, host string) map[string]uint32 {
	infos, err := session.ListSharesWithTypes()
	if err != nil {
		return nil
	}
	m := make(map[string]uint32, len(infos))
	for _, info := range infos {
		m[info.Name] = info.Type
	}
	return m
}

// IsSearchableShare returns true if the share type represents a disk share
// (and not a printer, communication device, or IPC share).
// Hidden disk shares (STYPE_HIDDEN = 0x80000000) are included.
func IsSearchableShare(shareType uint32) bool {
	baseType := shareType & 0x0FFFFFFF
	return baseType == 0 // STYPE_DISKTREE
}

func decodeUTF16LE(b []byte) string {
	runes := make([]rune, 0, len(b)/2)
	for i := 0; i+1 < len(b); i += 2 {
		c := binary.LittleEndian.Uint16(b[i:])
		if c == 0 {
			break
		}
		runes = append(runes, rune(c))
	}
	return string(runes)
}
