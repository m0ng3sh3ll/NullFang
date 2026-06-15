package main

import (
	"fmt"
	"math/rand"
	"os"
	"strconv"
	"strings"
	"time"
)

func levenshtein(a, b string) int {
	la := len(a)
	lb := len(b)
	d := make([][]int, la+1)
	for i := range d {
		d[i] = make([]int, lb+1)
	}
	for i := 0; i <= la; i++ {
		d[i][0] = i
	}
	for j := 0; j <= lb; j++ {
		d[0][j] = j
	}
	for i := 1; i <= la; i++ {
		for j := 1; j <= lb; j++ {
			cost := 0
			if a[i-1] != b[j-1] {
				cost = 1
			}
			d[i][j] = min(
				d[i-1][j]+1,
				d[i][j-1]+1,
				d[i-1][j-1]+cost,
			)
		}
	}
	return d[la][lb]
}

func min(a, b, c int) int {
	if a < b && a < c {
		return a
	}
	if b < c {
		return b
	}
	return c
}

func suggestFlag(flagName string, validFlags map[string]bool) string {
	bestMatch := ""
	minDist := 100
	for valid := range validFlags {
		dist := levenshtein(flagName, valid)
		if dist < minDist {
			minDist = dist
			bestMatch = valid
		}
	}
	if minDist <= 4 {
		return bestMatch
	}
	return ""
}

func isSpecialShare(shareName string) bool {
	specialShares := []string{"IPC$", "ADMIN$"}
	for _, special := range specialShares {
		if shareName == special {
			return true
		}
	}
	return false
}

// jitterSleep sleeps a random duration in [0, maxMs] ms. No-op when maxMs <= 0.
func jitterSleep(maxMs int) {
	if maxMs <= 0 {
		return
	}
	time.Sleep(time.Duration(rand.Intn(maxMs+1)) * time.Millisecond)
}

func getFileSize(filename string) int64 {
	info, err := os.Stat(filename)
	if err != nil {
		return 0
	}
	return info.Size()
}

// Helper to check if a string is empty or only whitespace
func isBlank(s string) bool {
	return len(strings.TrimSpace(s)) == 0
}

func parseSmbDialect(dialect string) (uint16, error) {
	switch strings.ToUpper(dialect) {
	case "SMB311":
		return 0x0311, nil
	case "SMB302":
		return 0x0302, nil
	case "SMB300":
		return 0x0300, nil
	case "SMB210":
		return 0x0210, nil
	case "SMB202":
		return 0x0202, nil
	case "":
		return 0, nil
	default:
		return 0, fmt.Errorf("Invalid SMB dialect: %s", dialect)
	}
}

func parseSmbSigning(signing string) (*bool, error) {
	if signing == "" {
		return nil, nil
	}
	s := strings.ToLower(signing)
	switch s {
	case "on", "true", "yes":
		b := true
		return &b, nil
	case "off", "false", "no":
		b := false
		return &b, nil
	default:
		return nil, fmt.Errorf("Invalid smb-signing value: %s", signing)
	}
}

const authFailStateFile = ".nullfang_authfail"

// readPersistentAuthFailCount returns the number of failed auth runs recorded on disk.
func readPersistentAuthFailCount() int {
	data, err := os.ReadFile(authFailStateFile)
	if err != nil {
		return 0
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 0
	}
	return n
}

// writePersistentAuthFailCount persists the failure count to disk.
func writePersistentAuthFailCount(n int) {
	_ = os.WriteFile(authFailStateFile, []byte(strconv.Itoa(n)), 0600)
}

// resetPersistentAuthFailCount clears the on-disk failure counter after a successful auth.
func resetPersistentAuthFailCount() {
	_ = os.Remove(authFailStateFile)
}

// Função auxiliar para converter string de tamanho (ex: "1m", "32k") para bytes
func parseSize(sizeStr string) int {
	var multiplier int = 1
	s := strings.ToLower(strings.TrimSpace(sizeStr))
	if strings.HasSuffix(s, "k") {
		multiplier = 1024
		s = strings.TrimSuffix(s, "k")
	} else if strings.HasSuffix(s, "m") {
		multiplier = 1024 * 1024
		s = strings.TrimSuffix(s, "m")
	}
	val, err := strconv.Atoi(s)
	if err != nil {
		return 1024 * 1024 // fallback 1MB
	}
	return val * multiplier
}
