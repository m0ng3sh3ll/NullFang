package main

import (
	"database/sql"
	"flag"
	"sync"
	"time"

	"github.com/m0ng3sh3ll/NullFang/checkpoint"
	"github.com/m0ng3sh3ll/NullFang/smb"
)

const (
	VERSION = "v1.5.5"
	AUTHOR  = "M0ng3Sh3ll"
)

var (
	// Variáveis globais para estatísticas
	totalFiles  int
	totalHosts  int
	noSMBHosts  int
	failedHosts int
	mu          sync.Mutex

	// ── CLI flags (user-facing) ──────────────────────────────────────────────

	// Target
	networkFlag  = flag.String("n", "", "Network CIDR (e.g., 192.168.0.0/24)")
	hostFlag     = flag.String("H", "", "Single host to connect to")
	listFlag     = flag.String("l", "", "File containing list of hosts")
	portFlag     = flag.Int("port", 445, "SMB port")

	// Authentication
	domainFlag     = flag.String("d", "", "Domain name")
	usernameFlag   = flag.String("u", "", "Username")
	passwordFlag   = flag.String("p", "", "Password")
	ntlmHashFlag   = flag.String("ntlm-hash", "", "NTLM hash (LM:NT or NT only)")
	kerberosFlag   = flag.Bool("kerberos", false, "Use Kerberos authentication")
	ticketFileFlag = flag.String("ticket-file", "", "Kerberos ticket cache file (ccache)")
	localAuthFlag    = flag.Bool("local-auth", false, "Local account auth (uses target hostname as domain)")
	nullSessionFlag  = flag.Bool("null-session", false, "Null/anonymous session (no credentials required; server must permit)")

	// Search
	matchFlag         = flag.String("m", "", "Strings to match (comma-separated)")
	regexFlag         = flag.String("r", "", "Regex patterns (comma-separated)")
	extensionsFlag    = flag.String("e", "", "File extensions (comma-separated, e.g. xlsx,docx,pdf)")
	specificShareFlag = flag.String("share", "", "Specific shares to scan (comma-separated)")
	excludeSharesFlag = flag.String("exclude-share", "", "Shares to skip (comma-separated, e.g. IPC$,ADMIN$)")

	// Scan mode — replaces -no-copy / -no-copy-deep
	//   recon  = enumerate files only, no content read, no copy
	//   search = content search, no copy (former -no-copy-deep)
	//   exfil  = content search + copy matching files (default)
	modeFlag = flag.String("mode", "exfil", "Scan mode: recon|search|exfil")

	// Stealth bundle — sets human-like timing, atime restore, single thread
	stealthFlag = flag.Bool("stealth", false, "Enable stealth mode (human pacing, atime restore, single thread)")

	// Relay
	socks5Flag = flag.String("socks5", "", "SOCKS5 proxy host:port for NTLM relay (ntlmrelayx --socks)")

	// Output
	outputDirFlag = flag.String("out", "NullFang_output", "Output directory for copied files")
	verboseFlag   = flag.Bool("v", false, "Verbose output (alias for --output verbose)")
	outputFlag    = flag.String("output", "normal", "Output style: normal|verbose|json|quiet")

	// Config & state
	configFileFlag     = flag.String("config", "", "YAML config file (patterns + advanced settings)")
	checkpointInstance *checkpoint.Checkpoint
	resumeFlag         = flag.String("resume", "", "Checkpoint file to resume a previous scan")
	deltaFlag          = flag.Bool("delta", false, "Delta scan: skip files unchanged since last run (requires existing DB)")

	// Admin & web
	checkAdminFlag = flag.Bool("check-admin", false, "Check admin privileges (may trigger EDR)")
	webFlag        = flag.Bool("web", false, "Start web interface server")
	webPortFlag    = flag.String("web-port", "9090", "Web interface port")
	dbFlag         = flag.String("db", "", "Custom database path for web interface")

	// Meta
	helpFlag    = flag.Bool("help", false, "Show help")
	versionFlag = flag.Bool("version", false, "Show version information")
	faqFlag     = flag.Bool("faq", false, "Show FAQ and troubleshooting tips")
	summaryFlag = flag.Bool("summary", false, "Show historical domain scan summary (requires -d)")

	// ── Internal configuration ───────────────────────────────────────────────
	// Not exposed as CLI flags. Set via the `settings:` block in -config YAML
	// or automatically by --stealth. See config/nullfang.yaml for full docs.

	threadsFlag          = func() *int           { v := 10; return &v }()
	timeoutFlag          = func() *time.Duration { v := 5 * time.Minute; return &v }()
	copyTimeoutFlag      = func() *time.Duration { v := 2 * time.Minute; return &v }()
	authTimeoutFlag      = func() *time.Duration { v := 30 * time.Second; return &v }()
	maxConnsPerHostFlag  = func() *int           { v := 5; return &v }()
	maxConcurrentFlag    = func() *int           { v := 10; return &v }()
	chunkSizeFlag        = func() *string        { v := "1m"; return &v }()
	bufferSizeFlag       = func() *string        { v := "32k"; return &v }()
	lruCacheSizeFlag     = func() *int           { v := 512; return &v }()
	batchSizeFlag        = func() *int           { v := 100; return &v }()
	miniBatchSizeFlag    = func() *int           { v := 10; return &v }()
	batchTimeoutFlag     = func() *time.Duration { v := 2 * time.Second; return &v }()
	batchModeFlag        = func() *bool          { v := false; return &v }()
	perHostLimitFlag     = func() *bool          { v := false; return &v }()
	maxHostBandwidthFlag = func() *string        { v := "10m"; return &v }()
	maxSizeFlag          = func() *int64         { v := int64(10 * 1024 * 1024); return &v }()
	caseSensitive        = func() *bool          { v := false; return &v }()
	leetFlag             = flag.Bool("leet", false, "Enable leet-speak pattern variations for keyword matching (e.g. 'password' also matches 'p4ssw0rd')")
	binaryFlag           = func() *bool          { v := false; return &v }()
	minBinaryStringFlag  = func() *int           { v := 4; return &v }()
	maxCacheFileSizeFlag = func() *int64         { v := int64(1024 * 1024); return &v }()
	maxDepthFlag         = func() *int           { v := 10; return &v }()
	excludeFlag          = func() *string        { v := ""; return &v }()
	minDateFlag          = func() *string        { v := ""; return &v }()
	maxDateFlag          = func() *string        { v := ""; return &v }()
	smbDialectFlag       = func() *string        { v := ""; return &v }()
	smbSigningFlag       = func() *string        { v := ""; return &v }()
	jitterFlag           = func() *int           { v := 0; return &v }()
	preserveAtimeFlag    = func() *bool          { v := false; return &v }()
	noRandomizeFlag      = func() *bool          { v := false; return &v }()
	noSkipCanaryFlag     = func() *bool          { v := false; return &v }()
	noCopyFlag           = func() *bool          { v := false; return &v }()
	noCopyDeepFlag       = func() *bool          { v := false; return &v }()
	machineFlag          = func() *bool          { v := false; return &v }()
	quietFlag            = func() *bool          { v := false; return &v }()
	operationDelayMsFlag    = func() *int  { v := 0; return &v }()    // per-entry delay; 0 = disabled
	lockoutThresholdFlag    = flag.Int("lockout-threshold", 1, "Halt scan after N auth failures to prevent account lockout (0 = disabled)")
	hashDedupFlag           = func() *bool { v := true; return &v }() // enabled by default
)

// authGuard tracks consecutive authentication failures to prevent AD lockout.
var authGuard = struct {
	mu     sync.Mutex
	count  int
	halted bool
}{}

// Criar struct para resultado
type hostResult struct {
	host     string
	err      error
	messages []string
}

var db *sql.DB
var throttlersByHost map[string]*smb.Throttler
var checkAdminOnly bool // true when -check-admin is the sole intent (no search flags)
