package smb

import (
	"fmt"
	"net"
	"time"
)

// NetbiosNameFromNBNS tenta obter o NetBIOS name de um host via NBNS (porta 137 UDP)
func NetbiosNameFromNBNS(ip string) (string, error) {
	// Monta pacote NBNS Name Query padrão
	query := []byte{
		0x82, 0x28, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x20, 0x43, 0x4b, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
		0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x00, 0x00, 0x21, 0x00, 0x01,
	}
	conn, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.ParseIP(ip), Port: 137})
	if err != nil {
		return "", err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Second))
	_, err = conn.Write(query)
	if err != nil {
		return "", err
	}
	buf := make([]byte, 512)
	n, _, err := conn.ReadFrom(buf)
	if err != nil {
		return "", err
	}
	// Parse resposta NBNS
	if n > 57 {
		name := string(buf[57 : 57+15])
		return name, nil
	}
	return "", fmt.Errorf("no NBNS name found")
}
