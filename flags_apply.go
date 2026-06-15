package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/m0ng3sh3ll/NullFang/search"
)

func validateFlags() {
	validFlags := map[string]bool{
		// Target
		"-n": true, "-H": true, "-l": true, "-port": true,
		// Auth
		"-d": true, "-u": true, "-p": true, "-ntlm-hash": true,
		"-kerberos": true, "-ticket-file": true, "-local-auth": true,
		// Search
		"-m": true, "-r": true, "-e": true, "-share": true, "-exclude-share": true,
		"-leet": true, "--leet": true,
		// Mode & stealth
		"-mode": true, "--mode": true,
		"-stealth": true, "--stealth": true,
		"-socks5": true,
		// Output
		"-out": true, "-v": true, "-output": true, "--output": true,
		// Config & state
		"-config": true, "-resume": true, "-delta": true,
		// Admin & web
		"-check-admin": true, "-web": true, "-web-port": true, "-db": true,
		// Meta
		"-help": true, "-version": true, "-faq": true, "-summary": true,
	}

	for _, arg := range os.Args[1:] {
		if strings.HasPrefix(arg, "-") {
			flagName := arg
			if idx := strings.Index(arg, "="); idx != -1 {
				flagName = arg[:idx]
			}
			if !validFlags[flagName] {
				suggestion := suggestFlag(flagName, validFlags)
				fmt.Printf("[ERRO] Flag unknown: %s\n", flagName)
				if suggestion != "" {
					fmt.Printf("Did you mean: %s ?\n", suggestion)
				}
				fmt.Println("Use -help to see all available options.")
				os.Exit(1)
			}
		}
	}
}

// applyModeFlag translates --mode into the internal noCopy/noCopyDeep vars.
func applyModeFlag() {
	switch strings.ToLower(*modeFlag) {
	case "recon":
		*noCopyFlag = true
		*noCopyDeepFlag = false
	case "search":
		*noCopyFlag = false
		*noCopyDeepFlag = true
	case "exfil", "":
		*noCopyFlag = false
		*noCopyDeepFlag = false
	default:
		fmt.Printf("[ERRO] Unknown --mode %q. Valid: recon|search|exfil\n", *modeFlag)
		os.Exit(1)
	}
}

// applyOutputFlag translates --output into internal verbose/machine/quiet vars.
func applyOutputFlag() {
	switch strings.ToLower(*outputFlag) {
	case "verbose":
		*verboseFlag = true
	case "json":
		*machineFlag = true
	case "quiet":
		*quietFlag = true
	case "normal", "":
		// defaults already set
	default:
		fmt.Printf("[ERRO] Unknown --output %q. Valid: normal|verbose|json|quiet\n", *outputFlag)
		os.Exit(1)
	}
	// -v is an explicit alias for verbose; don't reset it if already set
}

// applyStealthMode sets all internal config vars for human-like SMB behavior.
// Stealth takes priority over everything except explicit CLI flags.
func applyStealthMode() {
	if !*stealthFlag {
		return
	}
	// Single thread, single connection per host — mimics a single user session.
	*threadsFlag = 1
	*maxConnsPerHostFlag = 1
	*maxConcurrentFlag = 1

	// humanBrowseDelay base: 500ms → distribution yields 250ms–5s per directory entry.
	// This closely matches Windows Explorer "Refresh" + "Open" latency on a LAN.
	*operationDelayMsFlag = 500

	// Restore atime so file system audits don't show mass-access timestamps.
	*preserveAtimeFlag = true

	// Keep randomized order (default true) — sequential alphabetical is a scanner fingerprint.
	*noRandomizeFlag = false

	// Keep canary skip (default true) — tripping a canary ends the engagement.
	*noSkipCanaryFlag = false

	// 500ms max jitter between share mounts (humanBrowseDelay handles per-entry timing).
	*jitterFlag = 500
}

// applyScanConfigFromYAML reads the `settings:` block from the -config YAML
// and overrides internal config vars. Called after flag.Parse and before stealth.
// --stealth always wins over YAML settings.
func applyScanConfigFromYAML(patterns *search.SearchPatterns) {
	if patterns == nil {
		return
	}
	s := patterns.Settings

	// Performance
	if s.Performance.Threads > 0 {
		*threadsFlag = s.Performance.Threads
	}
	if s.Performance.Timeout != "" {
		if d, err := time.ParseDuration(s.Performance.Timeout); err == nil {
			*timeoutFlag = d
		}
	}
	if s.Performance.CopyTimeout != "" {
		if d, err := time.ParseDuration(s.Performance.CopyTimeout); err == nil {
			*copyTimeoutFlag = d
		}
	}
	if s.Performance.AuthTimeout != "" {
		if d, err := time.ParseDuration(s.Performance.AuthTimeout); err == nil {
			*authTimeoutFlag = d
		}
	}
	if s.Performance.MaxConnsPerHost > 0 {
		*maxConnsPerHostFlag = s.Performance.MaxConnsPerHost
	}
	if s.Performance.MaxConcurrent > 0 {
		*maxConcurrentFlag = s.Performance.MaxConcurrent
	}
	if s.Performance.ChunkSize != "" {
		*chunkSizeFlag = s.Performance.ChunkSize
	}
	if s.Performance.BufferSize != "" {
		*bufferSizeFlag = s.Performance.BufferSize
	}
	if s.Performance.LRUCacheSize > 0 {
		*lruCacheSizeFlag = s.Performance.LRUCacheSize
	}
	if s.Performance.BatchSize > 0 {
		*batchSizeFlag = s.Performance.BatchSize
	}
	if s.Performance.MiniBatchSize > 0 {
		*miniBatchSizeFlag = s.Performance.MiniBatchSize
	}
	if s.Performance.BatchTimeout != "" {
		if d, err := time.ParseDuration(s.Performance.BatchTimeout); err == nil {
			*batchTimeoutFlag = d
		}
	}
	if s.Performance.BatchMode {
		*batchModeFlag = true
	}
	if s.Performance.PerHostLimit {
		*perHostLimitFlag = true
	}
	if s.Performance.MaxHostBandwidth != "" {
		*maxHostBandwidthFlag = s.Performance.MaxHostBandwidth
	}

	// Search
	if s.Search.MaxSize > 0 {
		*maxSizeFlag = s.Search.MaxSize
	}
	if s.Search.MaxDepth > 0 {
		*maxDepthFlag = s.Search.MaxDepth
	}
	if s.Search.CaseSensitive {
		*caseSensitive = true
	}
	if s.Search.LeetSpeak {
		*leetFlag = true
	}
	if s.Search.Binary {
		*binaryFlag = true
	}
	if s.Search.MinBinaryString > 0 {
		*minBinaryStringFlag = s.Search.MinBinaryString
	}
	if s.Search.MaxCacheFileSize > 0 {
		*maxCacheFileSizeFlag = s.Search.MaxCacheFileSize
	}
	if len(s.Search.ExcludePatterns) > 0 {
		*excludeFlag = strings.Join(s.Search.ExcludePatterns, ",")
	}
	if s.Search.MinDate != "" {
		*minDateFlag = s.Search.MinDate
	}
	if s.Search.MaxDate != "" {
		*maxDateFlag = s.Search.MaxDate
	}

	// Stealth (YAML)
	if s.Stealth.OperationDelayMs > 0 {
		*operationDelayMsFlag = s.Stealth.OperationDelayMs
	}
	if s.Stealth.ShareJitterMs > 0 {
		*jitterFlag = s.Stealth.ShareJitterMs
	}
	if s.Stealth.PreserveAtime {
		*preserveAtimeFlag = true
	}
	if s.Stealth.DisableRandomize {
		*noRandomizeFlag = true
	}
	if s.Stealth.DisableCanarySkip {
		*noSkipCanaryFlag = true
	}

	// Network
	if s.Network.SMBDialect != "" {
		*smbDialectFlag = s.Network.SMBDialect
	}
	if s.Network.SMBSigning != "" {
		*smbSigningFlag = s.Network.SMBSigning
	}
}
