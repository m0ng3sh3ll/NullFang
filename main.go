package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/hirochachacha/go-smb2"
	"github.com/m0ng3sh3ll/NullFang/auth"
	"github.com/m0ng3sh3ll/NullFang/checkpoint"
	copyutil "github.com/m0ng3sh3ll/NullFang/copy"
	"github.com/m0ng3sh3ll/NullFang/database"
	"github.com/m0ng3sh3ll/NullFang/logger"
	"github.com/m0ng3sh3ll/NullFang/scanner"
	"github.com/m0ng3sh3ll/NullFang/search"
	"github.com/m0ng3sh3ll/NullFang/smb"
	"github.com/m0ng3sh3ll/NullFang/utils"
	"github.com/m0ng3sh3ll/NullFang/web"
)

const (
	VERSION = "1.1.0"
	AUTHOR  = "M0ng3Sh3ll"
)

var (
	// Variáveis globais para estatísticas
	totalFiles  int
	totalHosts  int
	noSMBHosts  int
	failedHosts int
	mu          sync.Mutex

	// Flags
	networkFlag          = flag.String("n", "", "Network CIDR (e.g., 192.168.0.0/24)")
	hostFlag             = flag.String("H", "", "Single host to connect to")
	listFlag             = flag.String("l", "", "File containing list of hosts")
	portFlag             = flag.Int("port", 445, "SMB port")
	domainFlag           = flag.String("d", "", "Domain name")
	usernameFlag         = flag.String("u", "", "Username")
	passwordFlag         = flag.String("p", "", "Password")
	ntlmHashFlag         = flag.String("ntlm-hash", "", "NTLM hash (format: LM:NT or just NT)")
	kerberosFlag         = flag.Bool("kerberos", false, "Use Kerberos authentication")
	ticketFileFlag       = flag.String("ticket-file", "", "Kerberos ticket file (ccache)")
	matchFlag            = flag.String("m", "", "Strings to match (comma-separated)")
	regexFlag            = flag.String("r", "", "Regex patterns to match (comma-separated)")
	extensionsFlag       = flag.String("e", "", "File extensions to search (comma-separated)")
	maxSizeFlag          = flag.Int64("max-size", 10*1024*1024, "Maximum file size in bytes")
	specificShareFlag    = flag.String("share", "", "Specific shares to search (comma-separated)")
	outputDirFlag        = flag.String("out", "NullFang_output", "Output directory")
	verboseFlag          = flag.Bool("v", false, "Verbose output")
	noCopyFlag           = flag.Bool("no-copy", false, "Only list files without copying them")
	noCopyDeepFlag       = flag.Bool("no-copy-deep", false, "No-copy mode, but allows content and regex search (less stealth)")
	threadsFlag          = flag.Int("threads", 10, "Number of concurrent threads")
	timeoutFlag          = flag.Duration("timeout", 5*time.Minute, "Search timeout duration")
	copyTimeoutFlag      = flag.Duration("copy-timeout", 2*time.Minute, "File copy timeout")
	helpFlag             = flag.Bool("help", false, "Show help")
	versionFlag          = flag.Bool("version", false, "Show version information")
	caseSensitive        = flag.Bool("cs", false, "Enables case sensitive search")
	leetFlag             = flag.Bool("leet", false, "Enables the use of leet speak in search")
	configFileFlag       = flag.String("config", "", "Custom YAML configuration file")
	checkpointInstance   *checkpoint.Checkpoint
	resumeFlag           = flag.String("resume", "", "Checkpoint file to resume previous execution")
	chunkSizeFlag        = flag.String("chunk-size", "1m", "Chunk size for file reading (e.g., 256k, 1m)")
	bufferSizeFlag       = flag.String("buffer-size", "32k", "Buffer size for read operations (e.g., 8k, 32k)")
	maxConnsPerHostFlag  = flag.Int("max-conns-per-host", 3, "Maximum number of concurrent connections per host")
	maxConcurrentFlag    = flag.Int("max-concurrent", 5, "Maximum number of global concurrent operations")
	batchSizeFlag        = flag.Int("batch-size", 100, "Batch size for operations")
	batchTimeoutFlag     = flag.Duration("batch-timeout", 2*time.Second, "Timeout for batch processing")
	perHostLimitFlag     = flag.Bool("per-host-limit", false, "Limit bandwidth per host")
	maxHostBandwidthFlag = flag.String("max-host-bandwidth", "10m", "Bandwidth limit per host (e.g., 512k, 5m, 10m)")
	authTimeoutFlag      = flag.Duration("auth-timeout", 30*time.Second, "Timeout for SMB authentication")
	binaryFlag           = flag.Bool("binary", false, "Enable search in binary files (default: false)")
	minBinaryStringFlag  = flag.Int("min-binary-string", 4, "Minimum string length for binary extraction (default: 4)")
	maxCacheFileSizeFlag = flag.Int64("max-cache-file-size", 1024*1024, "Maximum file size (in bytes) to cache content (default: 1MB)")
	lruCacheSizeFlag     = flag.Int("lru-cache-size", 512, "Number of entries for the LRU file cache (default: 512)")
	machineFlag          = flag.Bool("machine", false, "Machine-readable output (JSON, no emojis or banners)")
	quietFlag            = flag.Bool("quiet", false, "Minimal output, no banners or emojis")
	summaryFlag          = flag.Bool("summary", false, "Show summary of execution by domain (requires -d <domain>)")
	excludeSharesFlag    = flag.String("exclude-share", "", "Share to be excluded from the search separated by commas (ex: IPC$,ADMIN$,C$)")
	maxDepthFlag         = flag.Int("max-depth", 10, "Maximum directory recursion depth (default: 10)")
	excludeFlag          = flag.String("exclude", "", "Patterns or extensions to exclude from copy, separated by comma (ex: *.ini,.ini,secret)")
	minDateFlag          = flag.String("min-date", "", "Minimum file modification date (YYYY-MM-DD or YYYY-MM-DDTHH:MM:SS)")
	maxDateFlag          = flag.String("max-date", "", "Maximum file modification date (YYYY-MM-DD or YYYY-MM-DDTHH:MM:SS)")
	batchModeFlag        = flag.Bool("batch-mode", false, "Enable batch processing for file copying")
	miniBatchSizeFlag    = flag.Int("mini-batch-size", 10, "Size of the mini-batch for file copying in batch mode (default: 10)")
	faqFlag              = flag.Bool("faq", false, "Show frequently asked questions and troubleshooting tips")
	smbDialectFlag       = flag.String("smb-dialect", "", "Force SMB dialect (SMB311, SMB302, SMB300, SMB210, SMB202)")
	smbSigningFlag       = flag.String("smb-signing", "", "Force SMB signing (on/off)")
	localAuthFlag        = flag.Bool("local-auth", false, "Use local account authentication (uses the target's hostname as domain)")
	webFlag              = flag.Bool("web", false, "Start web interface server")
	webPortFlag          = flag.String("web-port", "9090", "Port for web interface server")
	dbFlag               = flag.String("db", "", "Custom database path for web interface")
)

// Criar struct para resultado
type hostResult struct {
	host     string
	err      error
	messages []string
}

var db *sql.DB
var throttlersByHost map[string]*smb.Throttler

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
func validateFlags() {
	validFlags := map[string]bool{
		"-n": true, "-H": true, "-l": true, "-port": true, "-d": true, "-u": true, "-p": true,
		"-ntlm-hash": true, "-kerberos": true, "-ticket-file": true, "-m": true, "-r": true,
		"-e": true, "-max-size": true, "-share": true, "-out": true, "-v": true, "--verbose": true,
		"-no-copy": true, "-no-copy-deep": true, "-threads": true, "-timeout": true, "-copy-timeout": true,
		"-help": true, "-version": true, "-cs": true, "-leet": true, "-config": true, "-resume": true,
		"-chunk-size": true, "-buffer-size": true, "-max-conns-per-host": true, "-max-concurrent": true,
		"-batch-size": true, "-batch-timeout": true, "-per-host-limit": true, "-max-host-bandwidth": true,
		"-auth-timeout": true, "-binary": true, "-min-binary-string": true, "-max-cache-file-size": true,
		"-lru-cache-size": true, "-machine": true, "-quiet": true, "-summary": true, "-exclude-share": true,
		"-max-depth": true, "-exclude": true, "-min-date": true, "-max-date": true, "-batch-mode": true,
		"-mini-batch-size": true, "-faq": true, "-smb-dialect": true, "-smb-signing": true,
		"-local-auth": true, "-web": true, "-web-port": true, "-db": true,
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

func main() {

	var err error
	dbPath := utils.GetDefaultDBPath()
	patternsPath, err := utils.EnsureDefaultPatternsFile()
	if err != nil {
		logger.Fatal("Failed to create patterns file: %v", err)
	}
	if _, err = os.Stat(dbPath); os.IsNotExist(err) {
		// Cria o banco e as tabelas
		_, err = database.InitDB(dbPath)
		if err != nil {
			logger.Fatal("Failed to create database: %v", err)
		}
		showBanner()
		fmt.Printf("\n═══════════════════════════════════════════════════════\n")
		fmt.Printf("   	NullFang - First execution\n")
		fmt.Printf("═══════════════════════════════════════════════════════\n\n")
		fmt.Println("	Database created at:", dbPath)
		fmt.Println("	Patterns created at:", patternsPath)
		fmt.Printf("\n	Happy Hacking!")
		fmt.Printf("\n═══════════════════════════════════════════════════════\n")
		fmt.Printf(" ✨ NullFang execution completed successfully! ✨\n")
		fmt.Printf("═══════════════════════════════════════════════════════\n")
		os.Exit(0)
	}
	db, err = database.InitDB(dbPath)
	if err != nil {
		logger.Fatal("Failed to initialize database: %v", err)
	}
	defer db.Close()

	flag.Parse()

	// Se nenhuma flag for passada, exibe mensagem amigável e exemplo
	if len(os.Args) == 1 {
		fmt.Println("[ERRO] No flag passed to NullFang.")
		fmt.Println("Example:")
		fmt.Println("  NullFang -H 192.168.1.10 -u admin -p password")
		fmt.Println("Use -help to see all options.")
		os.Exit(1)
	}

	// Flags de controle que não exigem alvo
	if *helpFlag {
		showHelp()
		return
	}
	if *versionFlag {
		showBanner()
		return
	}
	if *faqFlag {
		showFAQ()
		return
	}

	// Modo web - iniciar servidor web
	if *webFlag {
		startWebServer()
		return
	}

	// Mostra o banner para execuções normais (não é flag de controle)
	if !*helpFlag && !*versionFlag && !*faqFlag && !*webFlag {
		showBanner()
	}

	validateFlags()

	// Mark the start of execution for reference of new files
	execStartTime := time.Now()

	// Mutually exclusive flags: -no-copy and -no-copy-deep
	if *noCopyFlag && *noCopyDeepFlag {
		printUsageError(
			"Do not use --no-copy and --no-copy-deep together. Choose only one stealth mode:",
			"NullFang -n 192.168.1.0/24 -u admin -p password --no-copy",
		)
	}

	// If -no-copy-deep, force reduced stealth behavior (never copies, but searches content)
	if *noCopyDeepFlag {
		*noCopyFlag = false // Ensure only one mode is active
	}

	if *versionFlag {
		showBanner()
		return
	}

	if *helpFlag {
		showHelp()
		return
	}

	if *threadsFlag < 1 {
		printUsageError(
			"Invalid value for --threads. Must be at least 1.",
			"NullFang -n 192.168.1.0/24 -u admin -p password --threads 5",
		)
	}
	if *miniBatchSizeFlag < 1 {
		printUsageError(
			"Invalid value for --mini-batch-size. Must be at least 1.",
			"NullFang -n 192.168.1.0/24 -u admin -p password --batch-mode --mini-batch-size 10",
		)
	}
	if *maxDepthFlag < 1 {
		printUsageError(
			"Invalid value for --max-depth. Must be at least 1.",
			"NullFang -n 192.168.1.0/24 -u admin -p password --max-depth 10",
		)
	}
	if *minBinaryStringFlag < 1 {
		printUsageError(
			"-min-binary-string must be greater than 0.",
			"NullFang -n 192.168.1.0/24 -u admin -p password --binary --min-binary-string 4",
		)
	}
	if *maxCacheFileSizeFlag < 1 {
		printUsageError(
			"-max-cache-file-size must be greater than 0.",
			"NullFang -n 192.168.1.0/24 -u admin -p password --max-cache-file-size 1048576",
		)
	}
	if *lruCacheSizeFlag < 1 {
		printUsageError(
			"-lru-cache-size must be greater than 0.",
			"NullFang -n 192.168.1.0/24 -u admin -p password --lru-cache-size 512",
		)
	}
	if *batchModeFlag && *miniBatchSizeFlag < 1 {
		printUsageError(
			"When using --batch-mode, --mini-batch-size must be at least 1.",
			"NullFang -n 192.168.1.0/24 -u admin -p password --batch-mode --mini-batch-size 10",
		)
	}
	if *resumeFlag != "" && *ntlmHashFlag == "" {
		printUsageError(
			"To continue execution, you need to provide credentials:",
			"NullFang -resume checkpoints/nullfang_resume_*.json -p <password>",
		)
	}
	if *resumeFlag != "" && *usernameFlag == "" {
		printUsageError(
			"To resume, you must specify the username with -u <username>.",
			"NullFang -resume checkpoints/nullfang_resume_*.json -u admin -p <password>",
		)
	}
	if *resumeFlag != "" && *domainFlag == "WORKGROUP" {
		printUsageError(
			"To resume, you must specify the domain with -d <domain>.",
			"NullFang -resume checkpoints/nullfang_resume_*.json -d MYDOMAIN -u admin -p <password>",
		)
	}
	if *minDateFlag != "" {
		_, err := time.Parse("2006-01-02", *minDateFlag)
		if err != nil {
			_, err = time.Parse("2006-01-02T15:04:05", *minDateFlag)
		}
		if err != nil {
			printUsageError(
				"Invalid --min-date format. Use YYYY-MM-DD or YYYY-MM-DDTHH:MM:SS",
				"NullFang -n 192.168.1.0/24 -u admin -p password --min-date 2024-01-01",
			)
		}
	}
	if *maxDateFlag != "" {
		_, err := time.Parse("2006-01-02", *maxDateFlag)
		if err != nil {
			_, err = time.Parse("2006-01-02T15:04:05", *maxDateFlag)
		}
		if err != nil {
			printUsageError(
				"Invalid --max-date format. Use YYYY-MM-DD or YYYY-MM-DDTHH:MM:SS",
				"NullFang -n 192.168.1.0/24 -u admin -p password --max-date 2024-01-01",
			)
		}
	}
	if *configFileFlag != "" {
		if _, err := os.Stat(*configFileFlag); os.IsNotExist(err) {
			printUsageError(
				"Configuration file does not exist: "+*configFileFlag,
				"NullFang -config myconfig.yaml -n 192.168.1.0/24 -u admin -p password",
			)
		}
	}

	if !*quietFlag && !*machineFlag {
		if *verboseFlag {
			logger.Info("[DEBUG] main() started - beginning execution")
		}
	}

	// Configurar logger global
	logger.SetGlobalVerbose(*verboseFlag)
	if *verboseFlag {
		logger.SetGlobalLevel(logger.DEBUG)
	}
	// Timestamp sempre ativo, mas só será exibido em modo verbose
	logger.SetGlobalTimestamp(true)

	// Resetar contadores globais
	totalFiles = 0
	totalHosts = 0
	noSMBHosts = 0
	failedHosts = 0

	// Criar diretórios necessários
	for _, dir := range []string{"checkpoints", "history", "targets"} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			logger.Error("Error creating %s directory: %v", dir, err)
		}
	}

	if *summaryFlag {
		if *domainFlag == "" {
			fmt.Println("\n[ERROR] For use -summary, inform the domain with -d <domain>\n")
			os.Exit(1)
		}

		domain := strings.ToLower(*domainFlag)
		printSummaryBox("NullFang - Execution Summary", []string{fmt.Sprintf("Domain: %s", domain)}, 60)

		isIP := net.ParseIP(domain) != nil
		var rows *sql.Rows
		var err error

		// LOW HANGING FRUIT
		var lhfLines []string
		if isIP {
			rows, err = db.Query("SELECT host,user, COUNT(*) FROM low_hanging_fruit WHERE host = ? GROUP BY user, host", domain)
		} else {
			rows, err = db.Query("SELECT host,user, COUNT(*) FROM low_hanging_fruit WHERE LOWER(domain) = LOWER(?) GROUP BY user, host", domain)
		}
		if err == nil {
			var lastUser, lastHost string
			first := true
			totalLHF := 0
			for rows.Next() {
				var host, user string
				var count int
				rows.Scan(&host, &user, &count)
				if first || user != lastUser || host != lastHost {
					if !first {
						lhfLines = append(lhfLines, "")
					}
					lhfLines = append(lhfLines, fmt.Sprintf("Host: %s", host))
					lhfLines = append(lhfLines, fmt.Sprintf("User: %s", user))
					first = false
				}
				lhfLines = append(lhfLines, fmt.Sprintf("  Interesting files: %d", count))
				totalLHF += count
				lastUser = user
				lastHost = host
			}
			rows.Close()
			if totalLHF == 0 {
				lhfLines = append(lhfLines, "No interesting files were found for this domain.")
			}
		} else {
			lhfLines = append(lhfLines, "Error querying low_hanging_fruit in the database.")
		}
		printSummaryBox("Low Hanging Fruit", lhfLines, 60)

		// LARGE FILES
		var lfLines []string
		if isIP {
			rows, err = db.Query(`SELECT user, host, COUNT(*) FROM low_hanging_fruit WHERE host = ? AND large_file = 1 GROUP BY user, host`, domain)
		} else {
			rows, err = db.Query(`SELECT user, host, COUNT(*) FROM low_hanging_fruit WHERE LOWER(domain) = LOWER(?) AND large_file = 1 GROUP BY user, host`, domain)
		}
		if err == nil {
			var lastUser, lastHost string
			first := true
			totalLF := 0
			for rows.Next() {
				var user, host string
				var count int
				rows.Scan(&user, &host, &count)
				if first || user != lastUser || host != lastHost {
					if !first {
						lfLines = append(lfLines, "")
					}
					lfLines = append(lfLines, fmt.Sprintf("Host: %s", host))
					lfLines = append(lfLines, fmt.Sprintf("User: %s", user))
					first = false
				}
				lfLines = append(lfLines, fmt.Sprintf("  Large files: %d", count))
				totalLF += count
				lastUser = user
				lastHost = host
			}
			rows.Close()
			if totalLF == 0 {
				lfLines = append(lfLines, "No large files found for this domain.")
			}
		} else {
			lfLines = append(lfLines, "Error querying large files in the database.")
		}
		printSummaryBox("Large Files Detection", lfLines, 60)

		// FILES COPIED PER HOST/EXTENSION
		var filesLines []string
		if isIP {
			rows, err = db.Query(`SELECT user, host, COALESCE(file_type, '[no extension]') as file_type, COUNT(*) FROM files WHERE host = ? GROUP BY user, host, file_type ORDER BY user, host, file_type`, domain)
		} else {
			rows, err = db.Query(`SELECT user, host, COALESCE(file_type, '[no extension]') as file_type, COUNT(*) FROM files WHERE LOWER(domain) = LOWER(?) GROUP BY user, host, file_type ORDER BY user, host, file_type`, domain)
		}
		if err == nil {
			var lastUser, lastHost string
			first := true
			for rows.Next() {
				var user, host, fileType string
				var count int
				rows.Scan(&user, &host, &fileType, &count)
				if first || user != lastUser || host != lastHost {
					if !first {
						filesLines = append(filesLines, "") // linha em branco entre grupos
					}
					filesLines = append(filesLines, fmt.Sprintf("Host: %s", host))
					filesLines = append(filesLines, fmt.Sprintf("User: %s", user))
					first = false
				}
				filesLines = append(filesLines, fmt.Sprintf("  File Type: %s | Total: %d", fileType, count))
				lastUser = user
				lastHost = host
			}
			rows.Close()
			if len(filesLines) == 0 {
				filesLines = append(filesLines, "No files copied for this domain.")
			}
		} else {
			filesLines = append(filesLines, "Error querying copied files/extensions in the database.")
		}
		printSummaryBox("Files Copied Per Host/Extension", filesLines, 60)

		// Credentials
		var credentialsLines []string
		if isIP {
			rows, err = db.Query(`SELECT user, host, auth_method, password_clear, password_hash, password_ticket, found_time, isAdmin FROM domain_credentials WHERE host = ?`, domain)
		} else {
			rows, err = db.Query(`SELECT user, host, auth_method, password_clear, password_hash, password_ticket, found_time, isAdmin FROM domain_credentials WHERE LOWER(domain) = LOWER(?)`, domain)
		}
		if err == nil {
			var lastUser, lastHost string
			first := true
			for rows.Next() {
				var user, host, authMethod, passwordClear, passwordHash, passwordTicket, foundTime string
				var isAdmin bool
				rows.Scan(&user, &host, &authMethod, &passwordClear, &passwordHash, &passwordTicket, &foundTime, &isAdmin)
				if first || user != lastUser || host != lastHost {
					if !first {
						credentialsLines = append(credentialsLines, "") // linha em branco entre grupos
					}
					credentialsLines = append(credentialsLines, fmt.Sprintf("Host: %s", host))
					credentialsLines = append(credentialsLines, fmt.Sprintf("User: %s", user))
					first = false
				}
				if authMethod != "" {
					credentialsLines = append(credentialsLines, fmt.Sprintf("  Auth Method: %s", authMethod))
				}
				if passwordClear != "" {
					credentialsLines = append(credentialsLines, fmt.Sprintf("  Password Clear: %s", passwordClear))
				}
				if passwordHash != "" {
					credentialsLines = append(credentialsLines, fmt.Sprintf("  Password Hash: %s", passwordHash))
				}
				if passwordTicket != "" {
					credentialsLines = append(credentialsLines, fmt.Sprintf("  Password Ticket: %s", passwordTicket))
				}
				if foundTime != "" {
					credentialsLines = append(credentialsLines, fmt.Sprintf("  Found Time: %s", foundTime))
				}
				credentialsLines = append(credentialsLines, fmt.Sprintf("  Is Admin: %t", isAdmin))
				lastUser = user
				lastHost = host
			}
			rows.Close()
			if len(credentialsLines) == 0 {
				credentialsLines = append(credentialsLines, "No credentials found for this domain.")
			}
		} else {
			credentialsLines = append(credentialsLines, "Error querying credentials in the database.")
		}
		printSummaryBox("Credentials", credentialsLines, 60)

		os.Exit(0)
	}

	var hosts []string

	// Verificar se é uma retomada de execução
	if *resumeFlag != "" {
		var err error
		checkpointInstance, err = checkpoint.Load(*resumeFlag)
		if err != nil {
			logger.Fatal("Error loading checkpoint: %v", err)
		}

		// Check if credentials were provided
		if isBlank(*passwordFlag) && isBlank(*ntlmHashFlag) {
			printUsageError(
				"To continue execution, you need to provide credentials:",
				"NullFang -resume checkpoints/nullfang_resume_*.json -p <password>",
			)
		}

		// Update credentials with values from checkpoint if not provided or blank
		if isBlank(*usernameFlag) {
			*usernameFlag = checkpointInstance.GetUser()
			logger.Debug("Using username from checkpoint: %s", *usernameFlag)
		}

		if isBlank(*domainFlag) {
			*domainFlag = checkpointInstance.GetDomain()
			logger.Debug("Using domain from checkpoint: %s", *domainFlag)
		}

		if !*leetFlag {
			*leetFlag = checkpointInstance.GetLeetSpeak()
			logger.Debug("Using leet speak from checkpoint")
		}

		if !*noCopyFlag {
			*noCopyFlag = checkpointInstance.GetNoCopy()
			logger.Debug("Using no-copy mode from checkpoint")
		}

		hosts = checkpointInstance.GetPendingHosts()
		if len(hosts) == 0 {
			logger.Info("No pending hosts to process")
			return
		}

		logger.Debug("Creating initial checkpoint...")
		if err := checkpointInstance.Save(); err != nil {
			logger.Error("Error creating initial checkpoint: %v", err)
		} else {
			size := getFileSize(checkpointInstance.GetFilename())
			fmt.Println("[⏩] Resuming execution from previous checkpoint...")
			fmt.Printf("[i] Checkpoint loaded successfully (%d bytes)\n\n", size)
		}
	} else {
		// Normal execution
		if isBlank(*networkFlag) && isBlank(*hostFlag) && isBlank(*listFlag) {
			printUsageError(
				"No target specified. Use -H, -n, or -l to specify a target.",
				"NullFang -H 192.168.1.10 -u admin -p password",
			)
		}
		hosts = getHostsList()
		// --- FILTRO DE PORTA 445 PARA BUSCA POR CIDR ---
		if *networkFlag != "" {
			var filteredHosts []string
			var wg sync.WaitGroup
			var mu sync.Mutex
			timeout := 800 * time.Millisecond // timeout curto para não atrasar
			total := len(hosts)
			tested := 0
			openCount := 0
			progressBar := func(current, total, open int) {
				barLen := 30
				filled := int(float64(current) / float64(total) * float64(barLen))
				bar := strings.Repeat("█", filled) + strings.Repeat("░", barLen-filled)
				fmt.Printf("\r[🔍] SMB Scan Progress: [%s]  %d/%d  | %d open 🎯", bar, current, total, open)
				if current == total {
					fmt.Print("\n")
				}
			}
			// Captura de sinal para interromper visualmente o portscan
			sigChan := make(chan os.Signal, 1)
			signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
			go func() {
				<-sigChan
				mu.Lock()
				fmt.Printf("\n⏹️ Portscan interrupted by user!\n")
				mu.Unlock()
				os.Exit(130)
			}()
			sem := make(chan struct{}, 64) // limitar concorrência
			for _, host := range hosts {
				wg.Add(1)
				go func(h string) {
					defer wg.Done()
					sem <- struct{}{}
					defer func() { <-sem }()
					conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:445", h), timeout)
					mu.Lock()
					tested++
					if err == nil {
						conn.Close()
						filteredHosts = append(filteredHosts, h)
						openCount++
					}
					if !*verboseFlag {
						progressBar(tested, total, openCount)
					} else {
						if err == nil {
							logger.Info("[PortScan] %s: port 445 open", h)
						} else {
							logger.Info("[PortScan] %s: port 445 closed (%v)", h, err)
						}
					}
					mu.Unlock()
				}(host)
			}
			wg.Wait()
			signal.Stop(sigChan) // Desativa o handler de sinal do portscan após o término
			if *verboseFlag {
				logger.Info("[PortScan] Hosts with port 445 open: %d", len(filteredHosts))
			} else {
				fmt.Printf("[✔️] Portscan finished! %d hosts with port 445 open.\n\n", len(filteredHosts))
			}
			hosts = filteredHosts
		}
		if *verboseFlag {
			logger.Success("Starting with %d hosts to process", len(hosts))
			logger.Info("Creating initial checkpoint...")
			if checkpointInstance != nil {
				size := getFileSize(checkpointInstance.GetFilename())
				logger.Success("Checkpoint saved successfully (%d bytes)", size)
			}
			logger.Info("[Search] Using only patterns passed via command line (-m, -r, -e)")
		}

		// Criar novo checkpoint
		checkpointFile := filepath.Join("checkpoints", fmt.Sprintf("nullfang_resume_%s.json",
			time.Now().Format("20060102_150405")))

		searchConfig := configureSearch()

		checkpointInstance = checkpoint.New(
			getNetworkContext(), // Garante que o campo network será preenchido corretamente
			*usernameFlag,
			*domainFlag,
			fmt.Sprintf("m:%s,r:%s,e:%s", *matchFlag, *regexFlag, *extensionsFlag),
			hosts,
			*outputDirFlag,
			searchConfig.ExcludePatterns,
			searchConfig.ExcludedShares,
			func() string {
				if *minDateFlag != "" {
					return *minDateFlag
				} else {
					return ""
				}
			}(),
			func() string {
				if *maxDateFlag != "" {
					return *maxDateFlag
				} else {
					return ""
				}
			}(),
		)
		checkpointInstance.SetFilename(checkpointFile)
		checkpointInstance.SetLeetSpeak(*leetFlag)
		checkpointInstance.SetNoCopy(*noCopyFlag)

		// Após criar o checkpointInstance, setar a flag no_copy_deep
		if checkpointInstance != nil {
			checkpointInstance.SetNoCopyDeep(*noCopyDeepFlag)
		}

		// Salvar checkpoint inicial
		if err := checkpointInstance.Save(); err != nil {
			logger.Error("Error creating initial checkpoint: %v", err)
		}
	}

	totalHosts = len(hosts)

	// Configurar tratamento de sinais
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		sig := <-c
		fmt.Println("\nInterrupted by user!")
		if *verboseFlag {
			logger.Info("Signal %v received, saving checkpoint...", sig)
		}

		if checkpointInstance != nil {
			if err := checkpointInstance.Save(); err != nil {
				logger.Error("Error saving checkpoint: %v", err)
			} else {
				fmt.Printf("Checkpoint saved in: %s\n", checkpointInstance.GetFilename())
				fmt.Printf("To continue execution later, use:\n")
				fmt.Printf("    ./NullFang -resume %s -p or -ntlm-hash\n", checkpointInstance.GetFilename())
			}
		}

		if *verboseFlag {
			logger.Info("Shutting down...")
		}
		os.Exit(1)
	}()

	searchConfig := configureSearch()
	chunkSize := parseSize(*chunkSizeFlag)
	bufferSize := parseSize(*bufferSizeFlag)
	batchSize := *batchSizeFlag
	batchTimeout := *batchTimeoutFlag
	copyConfig := configureCopy(chunkSize, bufferSize, batchSize, batchTimeout)
	copyConfig.AuthObject = configureAuthentication(*hostFlag) // Preencher o campo com o objeto real

	dialect, err := parseSmbDialect(*smbDialectFlag)
	if err != nil {
		fmt.Println("[ERRO]", err)
		os.Exit(1)
	}
	signing, err := parseSmbSigning(*smbSigningFlag)
	if err != nil {
		fmt.Println("[ERRO]", err)
		os.Exit(1)
	}
	copyConfig.Dialect = dialect
	copyConfig.Signing = signing

	// Após configurar as flags e o SearchConfig
	fileContentCache, err := scanner.NewFileContentCache(*lruCacheSizeFlag)
	if err != nil {
		logger.Fatal("Error initializing file LRU cache: %v", err)
	}

	// Ajuste para o modo -no-copy: não adicionar arquivos large_file se não baterem com string ou extensão
	if *noCopyFlag {
		searchConfig.FilterLargeFiles = true // nova flag para filtrar large_files
	}

	resultsChan := make(chan hostResult, len(hosts))
	sem := make(chan struct{}, *threadsFlag)
	var wg sync.WaitGroup

	if *verboseFlag {
		logger.Info("[DEBUG] Starting host processing goroutines")
	}

	var throttlersByHost map[string]*smb.Throttler
	if *perHostLimitFlag {
		throttlersByHost = make(map[string]*smb.Throttler)
		maxHostBandwidth := parseSize(*maxHostBandwidthFlag)
		for _, host := range hosts {
			throttlersByHost[host] = smb.NewThrottler(&smb.ThrottleConfig{
				MaxBandwidth:  int64(maxHostBandwidth),
				MaxConcurrent: *maxConcurrentFlag,
				BatchSize:     *batchSizeFlag,
				BatchTimeout:  *batchTimeoutFlag,
			})
		}
	}

	for _, host := range hosts {
		wg.Add(1)
		go func(host string) {
			if *verboseFlag {
				logger.Info("[DEBUG] Host goroutine started: %s", host)
			}
			defer func() {
				if *verboseFlag {
					logger.Info("[DEBUG] Host goroutine finished: %s", host)
				}
				wg.Done()
			}()
			sem <- struct{}{}
			var messages []string
			var throttler *smb.Throttler
			if *perHostLimitFlag {
				throttler = throttlersByHost[host]
			}
			err := processHostWithMessages(host, searchConfig, copyConfig, fileContentCache, &messages, throttler)
			resultsChan <- hostResult{host: host, err: err, messages: messages}
			<-sem
		}(host)
	}

	go func() {
		wg.Wait()
		if *verboseFlag {
			logger.Info("[DEBUG] All host goroutines finished, closing resultsChan")
		}
		close(resultsChan)
	}()

	if *verboseFlag {
		logger.Info("[DEBUG] Entering results consumption loop")
	}
	for res := range resultsChan {
		if *verboseFlag {
			if res.err != nil {
				logger.Debug("Error: %v", res.err)
			}
		} else {
			fmt.Printf("🎯 %s:\n", res.host)
			for i, msg := range res.messages {
				if strings.HasPrefix(msg, "[Host: ") {
					// Progresso: sobrescreve a linha
					fmt.Printf("\r%s", msg)
					if i == len(res.messages)-1 {
						fmt.Printf("\n")
					}
				} else {
					fmt.Println(msg)
				}
			}
			if res.err == nil {
				fmt.Printf("✅ completed!\n\n")
			} else {
				fmt.Printf("🔴 error! %v\n\n", res.err)
			}
		}
	}
	if *verboseFlag {
		logger.Info("[DEBUG] Finished results consumption loop")
	}

	// --- VERIFICAÇÃO DE TODOS OS HOSTS FALHOS ---
	if checkpointInstance != nil {
		failed := checkpointInstance.GetFailedHosts()
		processed := checkpointInstance.GetProcessedHosts()
		foundFiles := checkpointInstance.GetFoundFilesCount()
		if len(processed) == 0 && len(failed) == totalHosts && foundFiles == 0 {
			fmt.Println("\nNo valid SMB service detected. All targets failed to connect or SMB service is unreachable\n")
			os.Exit(1)
		}
	}

	// Verificar se todos os hosts foram processados
	if checkpointInstance != nil {
		pendingHosts := checkpointInstance.GetPendingHosts()
		if len(pendingHosts) == 0 {
			// --- Coleta de dados para o resumo ---
			// Filtrar apenas hosts do alvo atual
			hostSet := make(map[string]struct{})
			for _, h := range hosts {
				hostSet[h] = struct{}{}
			}

			totalLargeFiles := 0
			largeFilesInfo := make(map[string]int)
			largeFilesPaths := make(map[string]string)
			files, err := os.ReadDir("targets")
			if err == nil {
				for _, file := range files {
					if strings.HasSuffix(file.Name(), "_large_files.json") {
						largeFilesPath := filepath.Join("targets", file.Name())
						var largeFiles copyutil.LargeFilesList
						if data, err := os.ReadFile(largeFilesPath); err == nil {
							if err := json.Unmarshal(data, &largeFiles); err == nil {
								host := strings.TrimSuffix(file.Name(), "_large_files.json")
								if _, ok := hostSet[host]; ok {
									largeFilesInfo[host] = len(largeFiles.Entries)
									largeFilesPaths[host] = largeFilesPath
									totalLargeFiles += len(largeFiles.Entries)
								}
							}
						}
					}
				}
			}
			totalFiles = 0
			for _, h := range hosts {
				totalFiles += len(checkpointInstance.GetFoundFiles(h))
			}
			var summaryIP string
			if *networkFlag != "" {
				summaryIP = *networkFlag
			} else if *listFlag != "" {
				summaryIP = *listFlag
			} else if *hostFlag != "" {
				summaryIP = *hostFlag
			}
			// --- Coleta de arquivos extraídos ---
			extractedFilesByHost := make(map[string]int)
			extractedFilesPaths := make(map[string]string)
			newFilesByHost := make(map[string]int)
			totalExtracted := 0
			totalNewFiles := 0
			newFilesPathsByHost := make(map[string][]string)
			files, err = os.ReadDir(filepath.Join("history", "copy"))
			if err == nil {
				for _, file := range files {
					if strings.HasSuffix(file.Name(), "_history.json") {
						filePath := filepath.Join("history", "copy", file.Name())
						var history copyutil.CopyHistory
						if data, err := os.ReadFile(filePath); err == nil {
							if err := json.Unmarshal(data, &history); err == nil {
								if _, ok := hostSet[history.Host]; ok {
									extractedFilesByHost[history.Host] = len(history.Entries)
									extractedFilesPaths[history.Host] = filePath
									newFilesByHost[history.Host] = history.NewFiles
									totalExtracted += len(history.Entries)
									totalNewFiles += history.NewFiles
									if history.NewFiles > 0 {
										for _, entry := range history.Entries {
											if entry.CopiedAt.After(history.ScanTime.Add(-2 * time.Minute)) {
												newFilesPathsByHost[history.Host] = append(newFilesPathsByHost[history.Host], entry.LocalPath)
											}
										}
									}
								}
							}
						}
					}
				}
			}
			// --- Coleta de erros ---
			errorsByHost := make(map[string][]string)
			files, err = os.ReadDir(filepath.Join("errors", "copy"))
			if err == nil {
				for _, file := range files {
					if strings.HasSuffix(file.Name(), ".json") {
						errorFilePath := filepath.Join("errors", "copy", file.Name())
						var errorLog copyutil.ErrorLog
						if data, err := os.ReadFile(errorFilePath); err == nil {
							if err := json.Unmarshal(data, &errorLog); err == nil {
								if _, ok := hostSet[errorLog.Host]; ok {
									for _, entry := range errorLog.Entries {
										errorsByHost[errorLog.Host] = append(errorsByHost[errorLog.Host], entry.ErrorMsg)
									}
								}
							}
						}
					}
				}
			}
			// --- Lógica para --no-copy: mostrar apenas arquivos listados/interessantes e large files ---
			if *noCopyFlag || *noCopyDeepFlag {
				interestingFilesByHost := make(map[string]int)
				interestingFilesPaths := make(map[string]string)
				largeFilesByHost := make(map[string]int)
				newFilesByHost := make(map[string]int)
				totalInteresting := 0
				totalNewFiles := 0
				domain := strings.ToUpper(*domainFlag)
				user := strings.ToLower(*usernameFlag)
				lhfRoot := filepath.Join("targets", "low-hanging_fruit", domain)
				// Percorre todos os diretórios de hosts dentro do domínio
				hostDirs, err := os.ReadDir(lhfRoot)
				if err == nil {
					for _, hostEntry := range hostDirs {
						if !hostEntry.IsDir() {
							continue
						}
						host := hostEntry.Name()
						hostPath := filepath.Join(lhfRoot, host)
						jsonFiles, err := os.ReadDir(hostPath)
						if err != nil {
							continue
						}
						for _, file := range jsonFiles {
							if strings.HasSuffix(file.Name(), ".json") {
								filePath := filepath.Join(hostPath, file.Name())
								var scanResult copyutil.NocopyScanResult
								if data, err := os.ReadFile(filePath); err == nil {
									if err := json.Unmarshal(data, &scanResult); err == nil {
										if _, ok := hostSet[scanResult.Host]; ok {
											interestingFilesByHost[scanResult.Host] += len(scanResult.Files)
											if interestingFilesPaths[scanResult.Host] == "" {
												interestingFilesPaths[scanResult.Host] = filePath
											}
											// Contar arquivos large_file
											countLarge := 0
											for _, f := range scanResult.Files {
												if f.LargeFile {
													countLarge++
												}
											}
											largeFilesByHost[scanResult.Host] += countLarge
											totalInteresting += len(scanResult.Files)
											newFilesByHost[scanResult.Host] += scanResult.NewFiles
											totalNewFiles += scanResult.NewFiles
										}
									}
								}
							}
						}
					}
				}
				// --- Output Machine (JSON) ---
				if *machineFlag {
					output := map[string]interface{}{
						"target":            summaryIP,
						"processed_hosts":   totalHosts,
						"files_found":       totalFiles,
						"hosts_failed":      failedHosts,
						"hosts_without_smb": noSMBHosts,
						"low_hanging_fruit": []map[string]interface{}{},
						"large_files":       []map[string]interface{}{},
						"new_files":         totalNewFiles,
						"new_files_paths":   newFilesPathsByHost,
					}
					for host, count := range interestingFilesByHost {
						output["low_hanging_fruit"] = append(output["low_hanging_fruit"].([]map[string]interface{}), map[string]interface{}{
							"host":         host,
							"files_listed": count,
							"large_files":  largeFilesByHost[host],
							"path":         interestingFilesPaths[host],
							"new_files":    newFilesByHost[host],
						})
					}
					enc := json.NewEncoder(os.Stdout)
					enc.SetIndent("", "  ")
					enc.Encode(output)
					return
				}
				// --- Output Quiet ---
				if *quietFlag {
					fmt.Printf("\nTarget: %s\n", summaryIP)
					fmt.Printf("Processed Hosts: %d\n", totalHosts)
					fmt.Printf("Files Found: %d\n", totalFiles)
					fmt.Printf("Low-hanging Fruit: %d\n", totalInteresting)
					fmt.Printf("New Files This Run: %d\n", totalNewFiles)
					fmt.Printf("Hosts Failed: %d\n", failedHosts)
					fmt.Printf("Hosts without SMB: %d\n", noSMBHosts)
					for host, count := range interestingFilesByHost {
						fmt.Printf(" - %s:\n", host)
						fmt.Printf("    ➔ %d file(s) listed (large files: %d, new this run: ", count, largeFilesByHost[host])
						var newLHFCount int
						db.QueryRow("SELECT COUNT(*) FROM low_hanging_fruit WHERE host = ? AND LOWER(domain) = LOWER(?) AND LOWER(user) = LOWER(?) AND found_time >= ?", host, domain, user, execStartTime).Scan(&newLHFCount)
						fmt.Printf("%d)\n", newLHFCount)
						fmt.Printf("    ➔ Details at: %s\n", interestingFilesPaths[host])
						if newLHFCount > 0 {
							fmt.Printf("%d new interesting files found for host %s!\n", newLHFCount, host)
						} else {
							fmt.Printf("No new interesting files were found for host %s.\n", host)
						}
						fmt.Printf("\n")
					}
					if totalNewFiles > 0 {
						fmt.Printf("\n New files found this run:\n")
						for host, paths := range newFilesPathsByHost {
							for _, path := range paths {
								fmt.Printf("   [%s] %s\n", host, path)
							}
						}
					}
					return
				}
				// --- Output Visual mode no-copy ---
				fmt.Printf("\n═══════════════════════════════════════════════════════\n")
				fmt.Printf("      NullFang - Execution Summary\n")
				fmt.Printf("═══════════════════════════════════════════════════════\n\n")
				fmt.Printf(" 🎯 Target(s): %s\n", summaryIP)
				fmt.Printf(" 🖥️  Processed Hosts: %d\n", totalHosts)
				fmt.Printf(" 🔑 User: %s - %s\n", *usernameFlag, getUserStatus(db, *hostFlag, *usernameFlag))
				fmt.Printf(" 🛠️  Domain: %s\n", getDisplayDomain(db, *hostFlag))
				fmt.Printf(" 🚫 Hosts Failed: %d\n", failedHosts)
				// Consultar o banco para contar arquivos extraídos e novos
				filesExtractedByHost := make(map[string]int)
				newFilesByHost = make(map[string]int)
				totalExtracted = 0
				totalNewFiles = 0
				for _, host := range hosts {
					var count, newCount int
					// Total de arquivos extraídos para o host
					db.QueryRow("SELECT COUNT(*) FROM files WHERE host = ?", host).Scan(&count)
					filesExtractedByHost[host] = count
					totalExtracted += count
					// Novos arquivos nesta execução: found_time >= início da execução
					db.QueryRow("SELECT COUNT(*) FROM files WHERE host = ? AND found_time >= ?", host, execStartTime).Scan(&newCount)
					newFilesByHost[host] = newCount
					totalNewFiles += newCount
				}
				fmt.Printf("\n═══════════════════════════════════════════════════════\n")
				if *noCopyFlag || *noCopyDeepFlag {
					fmt.Printf("   🍏 LOW-HANGING FRUIT (Interesting Files)\n")
					fmt.Printf("═══════════════════════════════════════════════════════\n")
					for _, host := range hosts {
						// buscar count no banco:
						var count int
						db.QueryRow("SELECT COUNT(*) FROM low_hanging_fruit WHERE host = ? AND (LOWER(domain) = LOWER(?) OR LOWER(domain) = LOWER(?)) AND LOWER(user) = LOWER(?)", host, domain, host, user).Scan(&count)
						fmt.Printf(" - %s:\n", host)
						fmt.Printf("    ➔ %d file(s) listed (large files: %d, new this run: ", count, largeFilesByHost[host])
						var newLHFCount int
						db.QueryRow(
							"SELECT COUNT(*) FROM low_hanging_fruit WHERE host = ? AND (LOWER(domain) = LOWER(?) OR LOWER(domain) = LOWER(?)) AND LOWER(user) = LOWER(?) AND found_time >= ?",
							host, domain, host, user, execStartTime,
						).Scan(&newLHFCount)
						fmt.Printf("%d)\n", newLHFCount)
						if newLHFCount > 0 {
							fmt.Printf("    🍏 %d new interesting files found for host!\n", newLHFCount)
						} else {
							fmt.Printf("    ℹ️ No new interesting files were found for host.\n")
						}
						fmt.Printf("\n")
					}
				}

				if totalNewFiles == 0 {
					// --- NOVO: Consulta o banco de dados para arquivos no modo no-copy ---
					var lhfCount int
					err := db.QueryRow(
						"SELECT COUNT(*) FROM low_hanging_fruit WHERE LOWER(domain) = LOWER(?) AND LOWER(user) = LOWER(?)",
						strings.ToUpper(*domainFlag), strings.ToLower(*usernameFlag),
					).Scan(&lhfCount)
					if err == nil && lhfCount > 0 {
						// Mensagem de sucesso
						fmt.Printf("\n 🍏 To view the %d interesting files, use the command below:\n", lhfCount)
						fmt.Printf(" Use the command below to view:\n")
						fmt.Printf("    nfdb\n")
						fmt.Printf("    > list low-hanging-fruits\n\n")
						// Move o checkpoint para a pasta history
						if checkpointInstance != nil {
							checkpointPath := checkpointInstance.GetFilename()
							checkpointName := filepath.Base(checkpointPath)
							historyDir := filepath.Join("history")
							os.MkdirAll(historyDir, 0755)
							historyName := strings.Replace(checkpointName, "nullfang_resume_", "nullfang_history_", 1)
							historyPath := filepath.Join(historyDir, historyName)
							err := os.Rename(checkpointPath, historyPath)
							if err == nil {
								fmt.Printf("The history was saved to: %s\n", historyPath)
								fmt.Printf("\n═══════════════════════════════════════════════════════\n")
								fmt.Printf(" ✨ NullFang execution completed successfully! ✨\n")
								fmt.Printf("═══════════════════════════════════════════════════════\n")
							} else {
								fmt.Printf("[WARN] Could not move checkpoint to history: %v\n", err)
								fmt.Printf("\n═══════════════════════════════════════════════════════\n")
								fmt.Printf(" ✨ NullFang execution completed successfully! ✨\n")
								fmt.Printf("═══════════════════════════════════════════════════════\n")
							}
						}
						return
					}
					// Move o checkpoint para a pasta history
					if checkpointInstance != nil {
						checkpointPath := checkpointInstance.GetFilename()
						checkpointName := filepath.Base(checkpointPath)
						historyDir := filepath.Join("history")
						os.MkdirAll(historyDir, 0755)
						historyName := strings.Replace(checkpointName, "nullfang_resume_", "nullfang_history_", 1)
						historyPath := filepath.Join(historyDir, historyName)
						err := os.Rename(checkpointPath, historyPath)
						if err == nil {
							fmt.Printf("The history was saved to: %s\n", historyPath)
							fmt.Printf("\n═══════════════════════════════════════════════════════\n")
							fmt.Printf(" ✨ NullFang execution completed successfully! ✨\n")
							fmt.Printf("═══════════════════════════════════════════════════════\n")
						} else {
							fmt.Printf("[WARN] Could not move checkpoint to history: %v\n", err)
							fmt.Printf("\n═══════════════════════════════════════════════════════\n")
							fmt.Printf(" ✨ NullFang execution completed successfully! ✨\n")
							fmt.Printf("═══════════════════════════════════════════════════════\n")
						}
					}

					return
				}

				// --- Mover checkpoint para history ao final do no-copy ---
				if checkpointInstance != nil {
					checkpointPath := checkpointInstance.GetFilename()
					checkpointName := filepath.Base(checkpointPath)
					historyDir := filepath.Join("history")
					os.MkdirAll(historyDir, 0755)
					historyName := strings.Replace(checkpointName, "nullfang_resume_", "nullfang_history_", 1)
					historyPath := filepath.Join(historyDir, historyName)
					err := os.Rename(checkpointPath, historyPath)
					if err == nil {
						fmt.Printf("The history was saved to: %s\n", historyPath)
						fmt.Printf("\n═══════════════════════════════════════════════════════\n")
						fmt.Printf(" ✨ NullFang execution completed successfully! ✨\n")
						fmt.Printf("═══════════════════════════════════════════════════════\n")
					} else {
						fmt.Printf("[WARN] Could not move checkpoint to history: %v\n", err)
						fmt.Printf("\n═══════════════════════════════════════════════════════\n")
						fmt.Printf(" ✨ NullFang execution completed successfully! ✨\n")
						fmt.Printf("═══════════════════════════════════════════════════════\n")
					}
				}
				return
			}

			// --- Output Machine (JSON) ---
			if *machineFlag {
				output := map[string]interface{}{
					"target":            summaryIP,
					"processed_hosts":   totalHosts,
					"files_found":       totalFiles,
					"files_extracted":   totalExtracted,
					"hosts_failed":      failedHosts,
					"hosts_without_smb": noSMBHosts,
					"extractions":       []map[string]interface{}{},
					"large_files":       []map[string]interface{}{},
					"errors":            []map[string]interface{}{},
					"new_files_paths":   newFilesPathsByHost,
				}
				for host, count := range extractedFilesByHost {
					output["extractions"] = append(output["extractions"].([]map[string]interface{}), map[string]interface{}{
						"host":            host,
						"files_extracted": count,
						"path":            extractedFilesPaths[host],
					})
				}
				for host, count := range largeFilesInfo {
					output["large_files"] = append(output["large_files"].([]map[string]interface{}), map[string]interface{}{
						"host":  host,
						"count": count,
						"path":  largeFilesPaths[host],
					})
				}
				if len(errorsByHost) > 0 {
					output["errors"] = []map[string]interface{}{}
					for host, errs := range errorsByHost {
						for _, errMsg := range errs {
							output["errors"] = append(output["errors"].([]map[string]interface{}), map[string]interface{}{
								"host":  host,
								"error": errMsg,
							})
						}
					}
				}
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				enc.Encode(output)
				return
			}
			// --- Output Quiet ---
			if *quietFlag {
				fmt.Printf("Target: %s\n", summaryIP)
				fmt.Printf("Processed Hosts: %d\n", totalHosts)
				fmt.Printf("Files Found: %d\n", totalFiles)
				fmt.Printf("Files Extracted: %d\n", totalExtracted)
				fmt.Printf("New Files This Run: %d\n", totalNewFiles)
				fmt.Printf("Hosts Failed: %d\n", failedHosts)
				fmt.Printf("Hosts without SMB: %d\n", noSMBHosts)
				for host, count := range extractedFilesByHost {
					fmt.Printf("Host %s: %d file(s) extracted, path: %s, new this run: %d\n\n", host, count, extractedFilesPaths[host], newFilesByHost[host])
				}
				for host, count := range largeFilesInfo {
					fmt.Printf("Host %s: %d large file(s) detected, details: %s\n\n", host, count, largeFilesPaths[host])
				}
				if len(errorsByHost) > 0 {
					for host, errs := range errorsByHost {
						for _, errMsg := range errs {
							fmt.Printf("Host %s: ERROR: %s\n\n", host, errMsg)
						}
					}
				}
				if totalNewFiles > 0 {
					fmt.Printf("New files found this run:\n")
					for host, paths := range newFilesPathsByHost {
						for _, path := range paths {
							fmt.Printf("   [%s] %s\n", host, path)
						}
					}
				}
				return
			}
			// --- Output Profissional Visual modo normal  ---
			fmt.Printf("\n═══════════════════════════════════════════════════════\n")
			fmt.Printf("      NullFang - Execution Summary\n")
			fmt.Printf("═══════════════════════════════════════════════════════\n\n")
			fmt.Printf(" 🎯 Target(s): %s\n", summaryIP)
			fmt.Printf(" 🖥️  Processed Hosts: %d\n", totalHosts)
			fmt.Printf(" 🔑 User: %s - %s\n", *usernameFlag, getUserStatus(db, *hostFlag, *usernameFlag))
			fmt.Printf(" 🛠️  Domain: %s\n", getDisplayDomain(db, *hostFlag))
			fmt.Printf(" 🚫 Hosts Failed: %d\n", failedHosts)
			fmt.Printf("\n═══════════════════════════════════════════════════════\n")
			fmt.Printf("   	 SUCCESSFUL FILE EXTRACTIONS\n")
			fmt.Printf("═══════════════════════════════════════════════════════\n")
			for _, host := range hosts {
				var count, newCount int
				// Total de arquivos copiados para o host
				db.QueryRow("SELECT COUNT(*) FROM files WHERE host = ?", host).Scan(&count)
				// Novos arquivos nesta execução
				db.QueryRow("SELECT COUNT(*) FROM files WHERE host = ? AND found_time >= ?", host, execStartTime).Scan(&newCount)

				fmt.Printf(" - %s:\n", host)
				fmt.Printf("🗂️  %d file(s) extracted (new this run: %d)\n", count, newCount)
				fmt.Printf("To see details, use:\n")
				fmt.Printf(" nfdb\n")
				fmt.Printf("  > list files\n\n")
				// NOVO: Consulta SQL para arquivos grandes
				var largeFilesCount int
				err := db.QueryRow("SELECT COUNT(*) FROM low_hanging_fruit WHERE host = ? AND (LOWER(domain) = LOWER(?) OR LOWER(domain) = LOWER(?)) AND LOWER(user) = LOWER(?) AND large_file = 1",
					host, strings.ToLower(*domainFlag), host, strings.ToLower(*usernameFlag)).Scan(&largeFilesCount)
				if err == nil && largeFilesCount > 0 {
					fmt.Printf(" ➔ %d large file(s) detected for details, use:\n", largeFilesCount)
					fmt.Printf(" nfdb\n")
					fmt.Printf("  > list large-files\n\n")
				}

				fmt.Printf("\n")
			}

			if checkpointInstance != nil {
				checkpointPath := checkpointInstance.GetFilename()
				historyDir := filepath.Join("history")
				os.MkdirAll(historyDir, 0755)
				historyPath := filepath.Join(historyDir, "nullfang_history_"+time.Now().Format("20060102_150405")+".json")
				err := os.Rename(checkpointPath, historyPath)
				if err == nil {
					fmt.Printf("The history was saved to: %s\n", historyPath)
					fmt.Printf("\n═══════════════════════════════════════════════════════\n")
					fmt.Printf(" ✨ NullFang execution completed successfully! ✨\n")
					fmt.Printf("═══════════════════════════════════════════════════════\n")
				} else {
					fmt.Printf("[WARN] Could not move checkpoint to history: %v\n", err)
					fmt.Printf("\n═══════════════════════════════════════════════════════\n")
					fmt.Printf(" ✨ NullFang execution completed successfully! ✨\n")
					fmt.Printf("═══════════════════════════════════════════════════════\n")
				}

			}
			return
		}
		// --- Mover checkpoint para history ao final do no-copy ---
		if checkpointInstance != nil {
			checkpointPath := checkpointInstance.GetFilename()
			historyDir := filepath.Join("history")
			os.MkdirAll(historyDir, 0755)
			historyPath := filepath.Join(historyDir, "nullfang_history_"+time.Now().Format("20060102_150405")+".json")
			err := os.Rename(checkpointPath, historyPath)
			if err == nil {
				fmt.Printf("The history was saved to: %s\n", historyPath)
				fmt.Printf("\n═══════════════════════════════════════════════════════\n")
				fmt.Printf(" ✨ NullFang execution completed successfully! ✨\n")
				fmt.Printf("═══════════════════════════════════════════════════════\n")
			} else {
				fmt.Printf("[WARN] Could not move checkpoint to history: %v\n", err)
				fmt.Printf("\n═══════════════════════════════════════════════════════\n")
				fmt.Printf(" ✨ NullFang execution completed successfully! ✨\n")
				fmt.Printf("═══════════════════════════════════════════════════════\n")
			}
		}
		return
	}

	fmt.Printf("\033[1;31m\nNullFang executed successfully\n\033[0m")
	if *verboseFlag {
		logger.Info("[DEBUG] End of main() function - program should exit now.")
	}

	// --- Antes do return do resumo visual ---
	if totalFiles == 0 {
		fmt.Printf("\n⚠️ No files were copied during the scan.\n\n")
		// Move o checkpoint para a pasta history
		if checkpointInstance != nil {
			checkpointPath := checkpointInstance.GetFilename()
			// checkpointName := filepath.Base(checkpointPath)
			historyDir := filepath.Join("history")
			os.MkdirAll(historyDir, 0755)
			historyPath := filepath.Join(historyDir, "nullfang_history_"+time.Now().Format("20060102_150405")+".json")
			err := os.Rename(checkpointPath, historyPath)
			if err == nil {
				fmt.Printf("The history was saved to: %s\n", historyPath)
				fmt.Printf("\n═══════════════════════════════════════════════════════\n")
				fmt.Printf(" ✨ NullFang execution completed successfully! ✨\n")
				fmt.Printf("═══════════════════════════════════════════════════════\n")
			} else {
				fmt.Printf("[WARN] Could not move checkpoint to history: %v\n", err)
				fmt.Printf("\n═══════════════════════════════════════════════════════\n")
				fmt.Printf(" ✨ NullFang execution completed successfully! ✨\n")
				fmt.Printf("═══════════════════════════════════════════════════════\n")
			}
		}
		return
	}

	// Após configurar as flags e o SearchConfig
	if *excludeSharesFlag != "" {
		shares := strings.Split(*excludeSharesFlag, ",")
		for i := range shares {
			shares[i] = strings.TrimSpace(shares[i])
		}
		searchConfig.ExcludedShares = shares
		fmt.Println("[INFO] Using shares excluded defined via command line:", shares)
	}

	// --- MIN/MAX DATE ---
	if *minDateFlag != "" {
		t, err := time.Parse("2006-01-02", *minDateFlag)
		if err != nil {
			t, err = time.Parse("2006-01-02T15:04:05", *minDateFlag)
		}
		if err != nil {
			logger.Fatal("Error: Invalid --min-date format. Use YYYY-MM-DD or YYYY-MM-DDTHH:MM:SS")
		}
		searchConfig.MinDate = t
	}
	if *maxDateFlag != "" {
		t, err := time.Parse("2006-01-02", *maxDateFlag)
		if err != nil {
			t, err = time.Parse("2006-01-02T15:04:05", *maxDateFlag)
		}
		if err != nil {
			logger.Fatal("Error: Invalid --max-date format. Use YYYY-MM-DD or YYYY-MM-DDTHH:MM:SS")
		}
		searchConfig.MaxDate = t
	}

	// Ao retomar com -resume, preencher as flags min-date e max-date se não forem passadas
	if *minDateFlag == "" && checkpointInstance != nil && checkpointInstance.GetMinDate() != "" {
		*minDateFlag = checkpointInstance.GetMinDate()
	}
	if *maxDateFlag == "" && checkpointInstance != nil && checkpointInstance.GetMaxDate() != "" {
		*maxDateFlag = checkpointInstance.GetMaxDate()
	}

}

func getHostsList() []string {
	var hosts []string

	// Validate input parameters
	if *hostFlag != "" && *networkFlag != "" {
		printUsageError(
			"Cannot use both -h and -n flags at the same time.",
			"NullFang -h 192.168.1.10 -u admin -p password",
		)
	}

	if *hostFlag != "" {
		// Validate if it's a valid IP
		if net.ParseIP(*hostFlag) == nil {
			printUsageError(
				"Invalid IP address format for -h flag. Expected format: x.x.x.x",
				"NullFang -h 192.168.1.10 -u admin -p password",
			)
		}
		hosts = append(hosts, *hostFlag)
	}

	if *networkFlag != "" {
		_, ipnet, err := net.ParseCIDR(*networkFlag)
		if err != nil {
			printUsageError(
				"Invalid CIDR format for -n flag. Expected format: x.x.x.x/y",
				"NullFang -n 192.168.1.0/24 -u admin -p password",
			)
		}
		hosts = append(hosts, expandCIDR(ipnet)...)
	}

	if *listFlag != "" {
		// Check if file exists
		if _, err := os.Stat(*listFlag); os.IsNotExist(err) {
			printUsageError(
				"File specified with -l flag does not exist: "+*listFlag,
				"NullFang -l hosts.txt -u admin -p password",
			)
		}

		// Check if it's a file (not a directory)
		fileInfo, err := os.Stat(*listFlag)
		if err == nil && fileInfo.IsDir() {
			printUsageError(
				"Path specified with -l flag is a directory, expected a file: "+*listFlag,
				"NullFang -l hosts.txt -u admin -p password",
			)
		}

		fileHosts, err := readHostsFile(*listFlag)
		if err != nil {
			printUsageError(
				"Error reading hosts file: "+err.Error(),
				"NullFang -l hosts.txt -u admin -p password",
			)
		}

		// Validate each IP in the file
		for i, host := range fileHosts {
			if net.ParseIP(host) == nil {
				printUsageError(
					fmt.Sprintf("Invalid IP address at line %d in file %s: %s", i+1, *listFlag, host),
					"NullFang -l hosts.txt -u admin -p password",
				)
			}
		}
		hosts = append(hosts, fileHosts...)
	}

	if len(hosts) == 0 {
		printUsageError(
			"No target specified. Use -h, -n, or -l to specify a target.",
			"NullFang -h 192.168.1.10 -u admin -p password",
		)
	}

	return hosts
}

func expandCIDR(ipnet *net.IPNet) []string {
	var ips []string
	// Primeiro, coleta todos os IPs
	for ip := ipnet.IP.Mask(ipnet.Mask); ipnet.Contains(ip); incIP(ip) {
		ips = append(ips, ip.String())
	}

	// Randomiza a ordem dos IPs usando o algoritmo Fisher-Yates
	rand.Seed(time.Now().UnixNano())
	for i := len(ips) - 1; i > 0; i-- {
		j := rand.Intn(i + 1)
		ips[i], ips[j] = ips[j], ips[i]
	}

	return ips
}

func readHostsFile(filename string) ([]string, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var hosts []string
	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			hosts = append(hosts, line)
		}
	}
	return hosts, nil
}

func UpsertDomainCredential(db *sql.DB, domain, user, host, authMethod, passwordClear, passwordHash, passwordTicket string) error {
	_, err := db.Exec(`
		INSERT INTO DomainCredentials (domain, user, host, auth_method, password_clear, password_hash, password_ticket)
		VALUES (?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(domain, user, host, auth_method) DO UPDATE SET
			password_clear=excluded.password_clear,
			password_hash=excluded.password_hash,
			password_ticket=excluded.password_ticket
	`, domain, user, host, authMethod, passwordClear, passwordHash, passwordTicket)
	return err
}

func processShares(conn *smb.SMBConnection, host string) map[string]*smb2.Share {
	shares, err := conn.ListShares()
	if err != nil {
		logger.Error("[-] Failed to list shares on %s: %v", host, err)
		return nil
	}

	if *verboseFlag {
		logger.Info("Found %d shares on %s", len(shares), host)
	}

	// Filter shares if specified
	if *specificShareFlag != "" {
		shares = filterShares(shares, strings.Split(*specificShareFlag, ","))
	}

	// Mount shares
	mountedShares := make(map[string]*smb2.Share)
	for _, shareName := range shares {
		if isSpecialShare(shareName) {
			continue
		}

		if fs, err := conn.MountShare(shareName); err == nil {
			shareNameWithIP := fmt.Sprintf("\\\\%s\\%s", host, shareName)
			mountedShares[shareNameWithIP] = fs
		}
	}

	return mountedShares
}

func filterShares(shares, specificShares []string) []string {
	var filtered []string
	for _, share := range shares {
		for _, specific := range specificShares {
			if strings.TrimSpace(specific) == share {
				filtered = append(filtered, share)
				break
			}
		}
	}
	return filtered
}

func searchAndCopyFiles(host string, conn *smb.SMBConnection, shares map[string]*smb2.Share, searchConfig *search.SearchConfig, copyConfig *copyutil.CopyConfig, fileContentCache *scanner.FileContentCache) {
	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), *copyTimeoutFlag)
	defer cancel()

	results, err := search.SearchMultipleShares(shares, searchConfig, fileContentCache)
	if err != nil {
		logger.Error("[-] Search error: %v", err)
		return
	}

	if *verboseFlag {
		logger.Info("Found %d matches", len(results))
	}

	if len(results) > 0 {
		if copyConfig.BatchMode {
			miniBatch := make([]*search.SearchResult, 0, copyConfig.MiniBatchSize)
			total := 0
			for _, result := range results {
				miniBatch = append(miniBatch, result)
				if len(miniBatch) >= copyConfig.MiniBatchSize {
					copyResults, _, err := copyutil.CopyMatchedFiles(ctx, db, shares, miniBatch, copyConfig, host, &smb.Throttler{})
					if err != nil {
						logger.Error("[ERROR] Failed to copy files: %v", err)
						return
					}
					sucesso := 0
					for _, r := range copyResults {
						if r.Success {
							sucesso++
						}
					}
					total += sucesso
					logger.Info("[+] %d of %d files copied successfully (mini-batch)", sucesso, len(miniBatch))
					miniBatch = miniBatch[:0]
				}
			}
			// Processa o que sobrou
			if len(miniBatch) > 0 {
				copyResults, _, err := copyutil.CopyMatchedFiles(ctx, db, shares, miniBatch, copyConfig, host, &smb.Throttler{})
				if err != nil {
					logger.Error("[ERROR] Failed to copy files: %v", err)
					return
				}
				sucesso := 0
				for _, r := range copyResults {
					if r.Success {
						sucesso++
					}
				}
				total += sucesso
				logger.Info("[+] %d of %d files copied successfully (final mini-batch)", sucesso, len(miniBatch))
			}
			logger.Info("[+] %d of %d files copied successfully (total)", total, len(results))
		} else {
			sucesso := 0
			erros := 0
			var throttler *smb.Throttler
			if *perHostLimitFlag {
				throttler = throttlersByHost[host]
			}
			for _, result := range results {
				res, err := copyutil.CopySingleMatch(ctx, db, shares, result, copyConfig, host, throttler)
				if res != nil && res.Success {
					sucesso++
				} else if err != nil {
					erros++
					logger.Error("[ERROR] Failed to copy %s: %v", result.FilePath, err)
				}
			}
			logger.Info("[+] %d of %d files copied successfully", sucesso, len(results))
			if erros > 0 {
				logger.Warning("[!] %d files presented an error in the copy", erros)
			}
		}
	}
}

func showBanner() {
	banner := `
%s███╗   ██╗██╗   ██╗██╗     ██╗     ███████╗ █████╗ ███╗   ██╗ ██████╗ %s
%s████╗  ██║██║   ██║██║     ██║     ██╔════╝██╔══██╗████╗  ██║██╔════╝ %s
%s██╔██╗ ██║██║   ██║██║     ██║     █████╗  ███████║██╔██╗ ██║██║  ███╗%s
%s██║╚██╗██║██║   ██║██║     ██║     ██╔══╝  ██╔══██║██║╚██╗██║██║   ██║%s
%s██║ ╚████║╚██████╔╝███████╗███████╗██║     ██║  ██║██║ ╚████║╚██████╔╝%s
%s╚═╝  ╚═══╝ ╚═════╝ ╚══════╝╚══════╝╚═╝     ╚═╝  ╚═╝╚═╝  ╚═══╝ ╚═════╝ %s
%s		[SMB Breach Intelligence Crawler]            
%s     
%s[Author: %s - github.com/m0ng3sh3ll/NullFang]%s
%s[Version: %s]%s
`
	// Cores ANSI
	blue := "\033[34m"
	cyan := "\033[36m"
	bold := "\033[1m"
	reset := "\033[0m"

	fmt.Printf(
		banner,
		blue, reset, // linha 1
		cyan, reset, // linha 2
		blue, reset, // linha 3
		cyan, reset, // linha 4
		blue, reset, // linha 5
		cyan, reset, // linha 6
		bold, reset, // linha do slogan
		bold, AUTHOR, reset, // linha do autor
		bold, VERSION, reset, // linha da versão
	)
	fmt.Printf("\n")
}

func showHelp() {
	fmt.Println("─────────────────────────────")
	fmt.Println(" Quick Usage Examples")
	fmt.Println("─────────────────────────────")
	fmt.Println("  1. Search for interesting files in a network:")
	fmt.Println("     NullFang -n 192.168.1.0/24 -u admin -p password -m \"password,config\" -e \".txt,.conf\"")
	fmt.Println("  2. Resume previous execution:")
	fmt.Println("     NullFang -resume checkpoints/nullfang_resume_*.json -p password")
	fmt.Println("  3. Exclude administrative shares:")
	fmt.Println("     NullFang --exclude-share=IPC$,ADMIN$ ...")
	fmt.Println("  4. Start web interface:")
	fmt.Println("     NullFang -web")
	fmt.Println("  5. Start web interface on custom port:")
	fmt.Println("     NullFang -web -web-port 9090")
	fmt.Println("  6. Start web interface with custom database:")
	fmt.Println("     NullFang -web -db /path/to/custom/database.db")
	fmt.Println("\nFor more examples and tips, visit:")
	fmt.Println("  https://nullfang.gitbook.io/nullfang/")
	fmt.Println("\n─────────────────────────────")
	fmt.Println(" Target Selection")
	fmt.Println("─────────────────────────────")
	fmt.Println("  -n string                  Network CIDR (e.g., 192.168.0.0/24)")
	fmt.Println("  -H string                  Single host to connect")
	fmt.Println("  -l string                  File containing list of hosts")
	fmt.Println("  -port int                  SMB port (default: 445)")
	fmt.Println("─────────────────────────────")
	fmt.Println(" Authentication")
	fmt.Println("─────────────────────────────")
	fmt.Println("  -d string                   Domain name")
	fmt.Println("  -u string                   Username")
	fmt.Println("  -p string                   Password")
	fmt.Println("  -ntlm-hash string           NTLM hash (format: LM:NT or just NT)")
	fmt.Println("  -kerberos                   Use Kerberos authentication")
	fmt.Println("  -ticket-file string         Kerberos ticket file (ccache)")
	fmt.Println("─────────────────────────────")
	fmt.Println(" Search & Filtering")
	fmt.Println("─────────────────────────────")
	fmt.Println("  -m string                   Strings to match (comma-separated)")
	fmt.Println("  -r string                   Regex patterns to match (comma-separated)")
	fmt.Println("  -e string                   File extensions to search (comma-separated)")
	fmt.Println("  -max-size int               Maximum file size in bytes (default: 10MB)")
	fmt.Println("  -share string               Specific shares to search (comma-separated)")
	fmt.Println("  -exclude-share string       Shares to exclude from search, separated by comma (ex: IPC$,ADMIN$,C$)")
	fmt.Println("  -cs                         Enable case sensitive search")
	fmt.Println("  -leet                       Enable leet speak variations in search")
	fmt.Println("  -no-copy                    Only list files without copying them")
	fmt.Println("  -binary                     Enable search in binary files (default: false)")
	fmt.Println("  -min-binary-string int      Minimum string length for binary extraction (default: 4)")
	fmt.Println("  -max-cache-file-size int    Maximum file size (in bytes) to cache content (default: 1MB)")
	fmt.Println("  -max-depth int              Maximum directory recursion depth (default: 10)")
	fmt.Println("  -exclude string             Patterns or extensions to exclude from copy, separated by comma (ex: *.ini,.ini,secret)")
	fmt.Println("  -min-date string            Minimum file modification date (YYYY-MM-DD or YYYY-MM-DDTHH:MM:SS)")
	fmt.Println("  -max-date string            Maximum file modification date (YYYY-MM-DD or YYYY-MM-DDTHH:MM:SS)")
	fmt.Println("─────────────────────────────")
	fmt.Println(" Output & Logging")
	fmt.Println("─────────────────────────────")
	fmt.Println("  -out string                 Output directory (default: NullFang_output)")
	fmt.Println("  -v, --verbose               Verbose output")
	fmt.Println("  -machine                    Machine-readable output (JSON, no emojis or banners)")
	fmt.Println("  -quiet                      Minimal output, no banners or emojis")
	fmt.Println("─────────────────────────────")
	fmt.Println(" Performance & Control")
	fmt.Println("─────────────────────────────")
	fmt.Println("  -threads int                Number of concurrent threads (default: 10)")
	fmt.Println("  -timeout duration           Search timeout duration (default: 5m)")
	fmt.Println("  -copy-timeout duration      File copy timeout (default: 2m)")
	fmt.Println("  -batch-mode                 Enable batch processing for file copying")
	fmt.Println("  -mini-batch-size int        Size of the mini-batch for file copying in batch mode (default: 10)")
	fmt.Println("  -chunk-size string          Chunk size for file reading (e.g., 256k, 1m)")
	fmt.Println("  -buffer-size string         Buffer size for file operations (e.g., 8k, 32k)")
	fmt.Println("  -max-conns-per-host int     Maximum SMB connections per host (default: 3)")
	fmt.Println("  -max-concurrent int         Maximum global concurrent operations (default: 5)")
	fmt.Println("  -batch-size int             Number of operations per batch (default: 100)")
	fmt.Println("  -batch-timeout duration     Timeout for batch processing (default: 2s)")
	fmt.Println("  -auth-timeout duration      Timeout for SMB authentication (default: 30s)")
	fmt.Println("  -lru-cache-size int         Number of entries for the LRU file cache (default: 512)")
	fmt.Println("─────────────────────────────")
	fmt.Println(" Configuration & Checkpoint")
	fmt.Println("─────────────────────────────")
	fmt.Println("  -resume string              Checkpoint file to resume previous execution")
	fmt.Println("  -config string              Custom YAML configuration file")
	fmt.Println("─────────────────────────────")
	fmt.Println(" Web Interface")
	fmt.Println("─────────────────────────────")
	fmt.Println("  -web                        Start web interface server")
	fmt.Println("  -web-port string            Port for web interface server (default: 9090)")
	fmt.Println("  -db string                  Custom database path for web interface")
	fmt.Println("─────────────────────────────")
	fmt.Println(" General")
	fmt.Println("─────────────────────────────")
	fmt.Println("  -help                       Show this help")
	fmt.Println("  -version                    Show version information")
	fmt.Println("─────────────────────────────")
	fmt.Println("\n─────────────────────────────")
	fmt.Println(" Quick Tips and FAQ")
	fmt.Println("─────────────────────────────")
	fmt.Println("  Use NullFang -faq to see frequently asked questions and troubleshooting tips.")
	fmt.Println("  To analyze results after execution, use:")
	fmt.Println("    nfdb > list files")
}

func showFAQ() {
	fmt.Println("NullFang - Frequently Asked Questions (FAQ)")
	fmt.Println("─────────────────────────────")
	fmt.Println("1. I did not find any files, what should I do?")
	fmt.Println("   - Try adjusting the search patterns (-m, -e, -r).")
	fmt.Println("   - Make sure the user has read permissions on the shares.")
	fmt.Println("2. How do I resume an interrupted execution?")
	fmt.Println("   - Use the -resume flag with the saved checkpoint file.")
	fmt.Println("3. How do I filter files by date?")
	fmt.Println("   - Use --min-date and --max-date in the format YYYY-MM-DD.")
	fmt.Println("4. For more tips, visit the Wiki: https://nullfang.gitbook.io/nullfang/")
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
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

func configureSearch() *search.SearchConfig {
	var patterns *search.SearchPatterns
	var err error

	// Se estiver usando -resume, extrair os padrões do checkpoint
	if *resumeFlag != "" {
		searchPattern := checkpointInstance.GetSearchPattern()
		parts := strings.Split(searchPattern, ",")
		for _, part := range parts {
			kv := strings.Split(part, ":")
			if len(kv) != 2 {
				continue
			}
			switch kv[0] {
			case "m":
				*matchFlag = kv[1]
			case "r":
				*regexFlag = kv[1]
			case "e":
				*extensionsFlag = kv[1]
			}
		}
	}

	// Validar parâmetros de busca
	usouFlag := false
	if *matchFlag != "" || *regexFlag != "" || *extensionsFlag != "" {
		usouFlag = true
	}

	if !usouFlag {
		// Carrega padrões do arquivo
		patternsPath, err := utils.EnsureDefaultPatternsFile()
		if err != nil {
			logger.Fatal("Error: Could not create or find default patterns file: %v", err)
		}
		patterns, err = search.LoadPatterns(patternsPath)
		if err != nil {
			logger.Fatal("Error: No search criteria specified and could not load default patterns: %v", err)
		}
		// Verifica se há padrões no arquivo
		if len(patterns.Patterns.Credentials) == 0 &&
			len(patterns.Patterns.Sensitive) == 0 &&
			len(patterns.Patterns.Extensions) == 0 &&
			len(patterns.Patterns.Regex) == 0 {
			logger.Fatal("Error: No search criteria specified. Use at least one of:\n" +
				"  -m <patterns>     for string patterns\n" +
				"  -r <regex>        for regex patterns\n" +
				"  -e <extensions>   for file extensions")
		}

		// Usa os padrões do arquivo como critérios de busca
		*matchFlag = strings.Join(append(patterns.Patterns.Credentials, patterns.Patterns.Sensitive...), ",")
		*regexFlag = strings.Join(patterns.Patterns.Regex, ",")
		*extensionsFlag = strings.Join(patterns.Patterns.Extensions, ",")
		if *verboseFlag {
			logger.Info("[Search] Using defaults from the YAML file (default.yaml)")
		}
	} else {
		if *verboseFlag {
			logger.Info("[Search] Using only defaults passed via command line (-m, -r, -e)")
		}
	}

	// Carrega o arquivo de padrões para obter o leet_speak_map
	if *configFileFlag != "" {
		if _, err := os.Stat(*configFileFlag); os.IsNotExist(err) {
			logger.Fatalf("Error: Configuration file does not exist: %s", *configFileFlag)
		}
		patterns, err = search.LoadPatterns(*configFileFlag)
		if err != nil {
			logger.Fatalf("Error loading configuration file: %v", err)
		}
	} else {
		patternsPath, err := utils.EnsureDefaultPatternsFile()
		if err != nil {
			logger.Fatalf("Error loading default patterns: %v", err)
		}
		patterns, err = search.LoadPatterns(patternsPath)
		if err != nil {
			logger.Fatalf("Error loading default patterns: %v", err)
		}
	}

	// Cria padrões da linha de comando
	cmdPatterns := &search.SearchPatterns{}
	if *matchFlag != "" {
		if *noCopyFlag {
			cmdPatterns.Patterns.Sensitive = strings.Split(*matchFlag, ",")
		} else {
			cmdPatterns.Patterns.Credentials = strings.Split(*matchFlag, ",")
			cmdPatterns.Patterns.Sensitive = cmdPatterns.Patterns.Credentials
		}
		if *leetFlag {
			var leetVariations []string
			var patternsToProcess []string
			if *noCopyFlag {
				patternsToProcess = cmdPatterns.Patterns.Sensitive
			} else {
				patternsToProcess = cmdPatterns.Patterns.Credentials
			}
			for _, pattern := range patternsToProcess {
				variations := patterns.ProcessLeetSpeak(pattern)
				leetVariations = append(leetVariations, variations...)
			}
			if *noCopyFlag {
				cmdPatterns.Patterns.Sensitive = leetVariations
			} else {
				cmdPatterns.Patterns.Credentials = leetVariations
				cmdPatterns.Patterns.Sensitive = leetVariations
			}
		}
	}
	if *regexFlag != "" {
		cmdPatterns.Patterns.Regex = strings.Split(*regexFlag, ",")
	}
	if *extensionsFlag != "" {
		extensions := strings.Split(*extensionsFlag, ",")
		for i, ext := range extensions {
			ext = strings.TrimSpace(ext)
			if !strings.HasPrefix(ext, ".") {
				ext = "." + ext
			}
			extensions[i] = strings.ToLower(ext)
		}
		cmdPatterns.Patterns.Extensions = extensions
	}

	// Se o usuário passou flags, ignora padrões do arquivo (exceto leet_speak_map)
	var mergedPatterns *search.SearchPatterns
	if usouFlag {
		cmdPatterns.Patterns.LeetSpeakMap = patterns.Patterns.LeetSpeakMap
		mergedPatterns = cmdPatterns
	} else {
		mergedPatterns = search.MergePatterns(cmdPatterns, patterns)
	}

	// Cria e configura SearchConfig
	config := search.NewSearchConfig()
	config.MaxFileSize = *maxSizeFlag
	config.CaseSensitive = *caseSensitive
	config.SearchBinary = *binaryFlag
	config.MinBinaryStringLen = *minBinaryStringFlag
	config.MaxCacheFileSize = *maxCacheFileSizeFlag
	config.MaxDepth = *maxDepthFlag

	// Em modo no-copy, só habilita busca por conteúdo/regex se --no-copy-deep estiver ativo
	if *noCopyFlag {
		config.SearchContents = false
		config.SearchRegex = false
	}
	if *noCopyDeepFlag {
		config.SearchContents = true
		config.SearchRegex = true
	}

	// Adiciona padrões mesclados ao config
	if !*noCopyFlag {
		for _, pattern := range mergedPatterns.Patterns.Credentials {
			config.AddContentPattern(pattern)
		}
	}
	// Se houver padrões de nome de arquivo, adiciona
	for _, fname := range mergedPatterns.Patterns.Sensitive {
		config.AddFilenamePattern(fname)
	}
	for _, ext := range mergedPatterns.Patterns.Extensions {
		config.AddFileExtension(ext)
	}
	if !*noCopyFlag {
		for _, regex := range mergedPatterns.Patterns.Regex {
			if err := config.AddRegexPattern(regex); err != nil {
				logger.Printf("Warning: Invalid regex ignored: %v", err)
			}
		}
	}

	if *minBinaryStringFlag < 1 {
		logger.Fatal("Error: -min-binary-string must be greater than 0.")
	}
	if *maxCacheFileSizeFlag < 1 {
		logger.Fatal("Error: -max-cache-file-size must be greater than 0.")
	}
	if *lruCacheSizeFlag < 1 {
		logger.Fatal("Error: -lru-cache-size must be greater than 0.")
	}

	// --- EXCLUDE PATTERNS ---
	if *excludeFlag != "" {
		config.ExcludePatterns = strings.Split(*excludeFlag, ",")
		for i := range config.ExcludePatterns {
			config.ExcludePatterns[i] = strings.TrimSpace(config.ExcludePatterns[i])
		}
	} else if patterns.Patterns.SearchConfig.Exclude != nil && len(patterns.Patterns.SearchConfig.Exclude) > 0 {
		config.ExcludePatterns = patterns.Patterns.SearchConfig.Exclude
	} else {
		config.ExcludePatterns = []string{}
	}

	// --- EXCLUDED SHARES ---
	if *excludeSharesFlag != "" {
		shares := strings.Split(*excludeSharesFlag, ",")
		for i := range shares {
			shares[i] = strings.TrimSpace(shares[i])
		}
		config.ExcludedShares = shares
	} else if patterns.Patterns.SearchConfig.ExcludedShares != nil && len(patterns.Patterns.SearchConfig.ExcludedShares) > 0 {
		config.ExcludedShares = patterns.Patterns.SearchConfig.ExcludedShares
	} else {
		config.ExcludedShares = []string{"IPC$", "ADMIN$"}
	}

	// --- MAX DEPTH ---
	if maxDepthFlag != nil && *maxDepthFlag != 10 {
		config.MaxDepth = *maxDepthFlag
	} else if patterns.Patterns.SearchConfig.MaxDepth > 0 {
		config.MaxDepth = patterns.Patterns.SearchConfig.MaxDepth
	} else {
		config.MaxDepth = 10
	}

	// --- MIN/MAX DATE ---
	if *minDateFlag != "" {
		t, err := time.Parse("2006-01-02", *minDateFlag)
		if err != nil {
			t, err = time.Parse("2006-01-02T15:04:05", *minDateFlag)
		}
		if err != nil {
			logger.Fatal("Error: Invalid --min-date format. Use YYYY-MM-DD or YYYY-MM-DDTHH:MM:SS")
		}
		config.MinDate = t
	}
	if *maxDateFlag != "" {
		t, err := time.Parse("2006-01-02", *maxDateFlag)
		if err != nil {
			t, err = time.Parse("2006-01-02T15:04:05", *maxDateFlag)
		}
		if err != nil {
			logger.Fatal("Error: Invalid --max-date format. Use YYYY-MM-DD or YYYY-MM-DDTHH:MM:SS")
		}
		config.MaxDate = t
	}

	return config
}

func configureCopy(chunkSize, bufferSize, batchSize int, batchTimeout time.Duration) *copyutil.CopyConfig {
	config := copyutil.NewCopyConfig()

	config.OutputDir = *outputDirFlag
	config.Verbose = *verboseFlag
	config.Username = *usernameFlag
	config.Domain = *domainFlag
	config.NoCopy = *noCopyFlag
	config.NoCopyDeep = *noCopyDeepFlag
	config.MaxFileSize = *maxSizeFlag
	config.LeetSpeak = *leetFlag
	config.AuthMethod = determineAuthMethod()

	// Adicionar padrões de busca do SearchConfig
	if *matchFlag != "" {
		config.FilenamePatterns = append(config.FilenamePatterns, strings.Split(*matchFlag, ",")...)
	}
	if *extensionsFlag != "" {
		// Processa e limpa as extensões
		extensions := strings.Split(*extensionsFlag, ",")
		for i, ext := range extensions {
			ext = strings.TrimSpace(ext)
			if !strings.HasPrefix(ext, ".") {
				ext = "." + ext
			}
			extensions[i] = strings.ToLower(ext)
		}
		config.FileExtensions = extensions
	}

	config.BatchMode = *batchModeFlag
	config.MiniBatchSize = *miniBatchSizeFlag

	// Novos campos
	config.ChunkSize = chunkSize
	config.BufferSize = bufferSize
	config.BatchSize = batchSize
	config.BatchTimeout = batchTimeout

	return config
}

func configureAuthentication(host string) auth.AuthMethod {
	var authMethod auth.AuthMethod
	var err error

	params := map[string]string{
		"username": *usernameFlag,
		"domain":   *domainFlag,
		"password": *passwordFlag,
	}

	// NTLM Hash Authentication
	if *ntlmHashFlag != "" {
		params["hash"] = *ntlmHashFlag
		authMethod, err = auth.NewAuthMethod(auth.AuthTypeNTLM, params)
		if err != nil {
			logger.Fatalf("Failed to configure NTLM authentication: %v", err)
		}
		return authMethod
	}

	// Kerberos Authentication
	if *kerberosFlag || *ticketFileFlag != "" {
		if *ticketFileFlag != "" {
			params["ticket_path"] = *ticketFileFlag
		}
		authMethod, err = auth.NewAuthMethod(auth.AuthTypeKerberos, params)
		if err != nil {
			logger.Fatalf("Failed to configure Kerberos authentication: %v", err)
		}
		return authMethod
	}

	return nil // Default: password authentication
}

func getFileSize(filename string) int64 {
	info, err := os.Stat(filename)
	if err != nil {
		return 0
	}
	return info.Size()
}

// Helper function to determine the authentication method being used
func determineAuthMethod() string {
	if *ntlmHashFlag != "" {
		return "ntlm"
	}
	if *kerberosFlag {
		return "kerberos"
	}
	if *ticketFileFlag != "" {
		return "kerberos_ticket"
	}
	return "plaintext"
}

// Helper function to format file sizes
func formatSize(size int64) string {
	const (
		B  = 1
		KB = 1024 * B
		MB = 1024 * KB
		GB = 1024 * MB
	)

	switch {
	case size >= GB:
		return fmt.Sprintf("%.2f GB", float64(size)/float64(GB))
	case size >= MB:
		return fmt.Sprintf("%.2f MB", float64(size)/float64(MB))
	case size >= KB:
		return fmt.Sprintf("%.2f KB", float64(size)/float64(KB))
	default:
		return fmt.Sprintf("%d B", size)
	}
}

// NOVA FUNÇÃO: processHostWithMessages
// Versão de processHost que acumula mensagens para exibir ao final
func processHostWithMessages(host string, searchConfig *search.SearchConfig, copyConfig *copyutil.CopyConfig, fileContentCache *scanner.FileContentCache, messages *[]string, throttler *smb.Throttler) error {
	if *verboseFlag {
		logger.Info("[DEBUG] processHost started: %s", host)
	}
	defer func() {
		if *verboseFlag {
			logger.Info("[DEBUG] processHost finished: %s", host)
		}
	}()

	ctx, cancel := context.WithTimeout(context.Background(), *copyTimeoutFlag)
	defer cancel()

	if *verboseFlag {
		logger.Debug("Processing host: %s", host)
		authMethod := determineAuthMethod()
		logger.Debug("Authentication method: %s", authMethod)
		logger.Debug("Search configuration:")
		logger.Debug("    - Max file size: %s", formatSize(*maxSizeFlag))
		logger.Debug("    - Case sensitive: %v", *caseSensitive)
		if *matchFlag != "" {
			logger.Debug("    - String patterns: %s", *matchFlag)
		}
		if *regexFlag != "" {
			logger.Debug("    - Regex patterns: %s", *regexFlag)
		}
		if *extensionsFlag != "" {
			logger.Debug("    - File extensions: %s", *extensionsFlag)
		}
		if *specificShareFlag != "" {
			logger.Debug("    - Target shares: %s", *specificShareFlag)
		}
	}

	// Criar um canal para timeout
	authTimeout := make(chan bool, 1)
	authDone := make(chan bool, 1)

	var domain string
	if *localAuthFlag {
		domain = "" // será preenchido após conectar
	} else {
		domain = *domainFlag
	}

	smbConfig := &smb.SMBConfig{
		Host:     host,
		Port:     *portFlag,
		Domain:   domain,
		Username: *usernameFlag,
		Password: *passwordFlag,
		Timeout:  10 * time.Second,
	}

	// Configure authentication
	if authMethod := configureAuthentication(host); authMethod != nil {
		smbConfig.AuthMethod = authMethod
	}

	copyConfig.AuthMethod = determineAuthMethod()

	conn := smb.NewSMBConnection(smbConfig)
	var connectionError error
	go func() {
		if err := conn.Connect(); err != nil {
			connectionError = err
			if *verboseFlag {
				logger.Debug("[-] %s: %v", host, err)
			}
			return
		}
		authDone <- true
	}()

	// Timeout de 30 segundos para autenticação
	go func() {
		time.Sleep(30 * time.Second)
		authTimeout <- true
	}()

	// Esperar pela autenticação ou timeout
	select {
	case <-authDone:
		if connectionError != nil {
			mu.Lock()
			failedHosts++
			mu.Unlock()
			// Marcar host como processado mesmo com erro de conexão
			if checkpointInstance != nil {
				checkpointInstance.MarkHostProcessed(host)
				checkpointInstance.AddFailedHost(host, connectionError.Error())
				if err := checkpointInstance.Save(); err != nil && *verboseFlag {
					logger.Debug("[-] Error saving checkpoint after failure on %s: %v", host, err)
				}
				checkpointInstance.Save()
			}
			return connectionError
		}
		defer conn.Disconnect()

		// Após autenticar e antes de processar arquivos, se local-auth, tentar obter o hostname via SRVSVC ou NBNS
		if *localAuthFlag && connectionError == nil {
			var hostname string
			if conn.Connection != nil {
				name, err := smb.GetRemoteHostnameSRVSVC(conn.Connection, host)
				if err == nil && name != "" {
					hostname = name
					if *verboseFlag {
						logger.Info("[local-auth] Hostname via SRVSVC: %s", hostname)
					}
				} else {
					// Fallback: tenta via NBNS/NetBIOS
					if *verboseFlag {
						logger.Warning("[local-auth] Could not get hostname via SRVSVC: %v", err)
						logger.Info("[local-auth] Trying NBNS/NetBIOS fallback...")
					}
					nameNBNS, errNBNS := smb.NetbiosNameFromNBNS(host)
					if errNBNS == nil && nameNBNS != "" {
						hostname = nameNBNS
						if *verboseFlag {
							logger.Info("[local-auth] Hostname via NBNS: %s", hostname)
						}
					} else {
						hostname = host
						if *verboseFlag {
							logger.Warning("[local-auth] Could not get hostname via NBNS: %v", errNBNS)
						}
					}
				}
				smbConfig.Domain = hostname
				copyConfig.Domain = hostname
			}
		}

	case <-authTimeout:
		mu.Lock()
		failedHosts++
		mu.Unlock()
		// Marcar host como processado em caso de timeout
		if checkpointInstance != nil {
			checkpointInstance.MarkHostProcessed(host)
			checkpointInstance.AddFailedHost(host, "authentication timeout")
			if err := checkpointInstance.Save(); err != nil && *verboseFlag {
				logger.Debug("[-] Error saving checkpoint after timeout on %s: %v", host, err)
			}
			checkpointInstance.Save()
		}
		if *verboseFlag {
			logger.Debug("[-] %s: Authentication timeout after 30 seconds", host)
		}
		return fmt.Errorf("authentication timeout")
	}

	// Process shares
	shares := processShares(conn, host)
	if len(shares) == 0 {
		mu.Lock()
		noSMBHosts++
		mu.Unlock()
		if checkpointInstance != nil {
			checkpointInstance.MarkHostProcessed(host)
			checkpointInstance.Save()
		}
		return nil
	}

	// Search files
	resultsChan := make(chan *search.SearchResult, 1000)
	fileContentCache, _ = scanner.NewFileContentCache(1000)
	go func() {
		err := search.SearchMultipleSharesStream(shares, searchConfig, fileContentCache, resultsChan)
		if err != nil && *verboseFlag {
			logger.Debug("Search error on %s: %v", host, err)
		}
		close(resultsChan)
	}()

	// Processa cada resultado assim que chega
	for result := range resultsChan {
		_, err := copyutil.CopySingleMatch(ctx, db, shares, result, copyConfig, host, throttler)
		if err != nil && *verboseFlag {
			logger.Debug("[-] Copy error on %s: %v", host, err)
		}
	}

	if checkpointInstance != nil {
		checkpointInstance.MarkHostProcessed(host)
		if err := checkpointInstance.Save(); err != nil && *verboseFlag {
			logger.Debug("[-] Error saving checkpoint after processing %s: %v", host, err)
		}
		checkpointInstance.Save()
	}

	// Teste de privilégio admin (stealth): abrir pipe svcctl
	isAdmin := false
	if conn.Connection != nil {
		fs, err := conn.Connection.Mount("IPC$")
		if err == nil {
			defer fs.Umount()
			pipes := []string{"svcctl", "samr", "lsarpc", "winreg", "eventlog", "netlogon"}
			for _, pipe := range pipes {
				f, err := fs.OpenFile(pipe, 2, 0666)
				if err == nil {
					isAdmin = true
					f.Close()
					if *verboseFlag {
						logger.Success("[Pwn3d] User has admin privileges! (pipe: %s)", pipe)
					}
					break
				}
			}
			if !isAdmin && *verboseFlag {
				logger.Info("[USER] Unable to determine admin privileges (all pipes blocked or access denied)")
			}
		} else if *verboseFlag {
			logger.Warning("[USER] Unable to mount IPC$ for admin privilege test: %v", err)
		}
	}

	saveCredential(db, smbConfig.Domain, *usernameFlag, determineAuthMethod(), host, *passwordFlag, *ntlmHashFlag, *ticketFileFlag, time.Now().Format("2006-01-02 15:04:05"), isAdmin)
	return nil
}

// Função utilitária para garantir que o campo network seja sempre preenchido corretamente
func getNetworkContext() string {
	if *networkFlag != "" {
		return *networkFlag
	}
	if *hostFlag != "" {
		return *hostFlag
	}
	if *listFlag != "" {
		return *listFlag
	}
	return ""
}
func printSummaryBox(title string, lines []string, width int) {
	border := "═"
	fmt.Printf("╔%s╗\n", strings.Repeat(border, width-2))
	if title != "" {
		fmt.Printf("║%s║\n", padCenter(title, width-2))
		fmt.Printf("╠%s╣\n", strings.Repeat(border, width-2))
	}
	for _, line := range lines {
		for len(line) > 0 {
			var part string
			if utf8.RuneCountInString(line) > width-4 {
				part = string([]rune(line)[:width-4])
				line = string([]rune(line)[width-4:])
			} else {
				part = line
				line = ""
			}
			fmt.Printf("║ %-*s ║\n", width-4, part)
		}
	}
	fmt.Printf("╚%s╝\n", strings.Repeat(border, width-2))
}

func padCenter(str string, width int) string {
	pad := width - len(str)
	left := pad / 2
	right := pad - left
	return strings.Repeat(" ", left) + str + strings.Repeat(" ", right)
}

func saveCredential(db *sql.DB, domain, user, authMethod, host, passwordClear, passwordHash, passwordTicket, foundTime string, isAdmin bool) {
	if err := database.InsertDomainCredentials(
		db,
		domain,
		user,
		host,
		authMethod,
		passwordClear,
		passwordHash,
		passwordTicket,
		foundTime,
		isAdmin,
	); err != nil {
		fmt.Printf("[-] Error saving credential: %v\n", err)
	}
	if *verboseFlag {
		fmt.Printf("[-] Credential saved: %s:%s@%s\n", domain, user, host)
	}
}

func printUsageError(msg, example string) {
	fmt.Printf("[ERROR] %s\n", msg)
	if example != "" {
		fmt.Printf("Example:\n  %s\n", example)
	}
	fmt.Println("For more options, use: NullFang -help")
	os.Exit(1)
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

// getUserStatus retorna o status do usuário baseado nos privilégios de admin
func getUserStatus(db *sql.DB, host, user string) string {
	var isAdmin bool
	err := db.QueryRow("SELECT isAdmin FROM domain_credentials WHERE host = ? AND LOWER(user) = LOWER(?)", host, strings.ToLower(user)).Scan(&isAdmin)
	if err != nil {
		return ""
	}
	if isAdmin {
		return "Pwn3d"
	}
	return "not admin"
}

// getDisplayDomain retorna o domínio correto para exibir nas mensagens do Telegram
func getDisplayDomain(db *sql.DB, host string) string {
	if *localAuthFlag {
		// Tenta obter o hostname salvo no banco de dados para o host
		var domain string
		err := db.QueryRow("SELECT domain FROM domain_credentials WHERE host = ? ORDER BY ROWID DESC LIMIT 1", host).Scan(&domain)
		if err == nil && domain != "" {
			return domain
		}
		// Fallback: retorna o próprio host (IP)
		return host
	}
	// Caso padrão: retorna o valor da flag -d
	return *domainFlag
}

// Função para iniciar o servidor web
func startWebServer() {
	showBanner()
	fmt.Printf("\n═══════════════════════════════════════════════════════\n")
	fmt.Printf("   	NullFang - Web Interface\n")
	fmt.Printf("═══════════════════════════════════════════════════════\n\n")

	// Determinar caminho do banco de dados
	var dbPath string
	if *dbFlag != "" {
		// Usar caminho customizado fornecido via flag -db
		dbPath = *dbFlag
	} else {
		// Usar caminho padrão
		dbPath = utils.GetDefaultDBPath()
	}

	// Validar se o banco de dados existe
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		fmt.Printf("❌ Database not found: %s\n", dbPath)
		fmt.Printf("💡 Execute NullFang first to create the database:\n")
		fmt.Printf("   NullFang -H 192.168.1.10 -u admin -p password\n")
		if *dbFlag != "" {
			fmt.Printf("   Or specify a different database with: -db /path/to/database\n\n")
		} else {
			fmt.Printf("\n")
		}
		os.Exit(1)
	}

	// Validar porta
	port := *webPortFlag
	if port == "" {
		port = "9090"
	}

	// Tentar converter porta para número para validação
	if _, err := strconv.Atoi(port); err != nil {
		fmt.Printf("❌ Invalid port: %s\n", port)
		os.Exit(1)
	}

	fmt.Printf("🗄️  Database: %s\n", dbPath)
	fmt.Printf("🌐 Web server: http://localhost:%s\n", port)
	fmt.Printf("📊 Interface available for data analysis\n\n")

	// Iniciar servidor web
	server, err := web.NewServer(dbPath)
	if err != nil {
		fmt.Printf("❌ Error starting web server: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("🚀 Web server started successfully!\n")
	fmt.Printf("📱 Access: http://localhost:%s\n", port)
	fmt.Printf("⏹️  Press Ctrl+C to stop the server\n\n")

	// Configurar tratamento de sinais para graceful shutdown
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		sig := <-c
		fmt.Printf("\n🛑 Web server stopped by %v\n", sig)
		os.Exit(0)
	}()

	// Iniciar servidor
	if err := server.Start(port); err != nil {
		fmt.Printf("❌ Error starting web server: %v\n", err)
		os.Exit(1)
	}
}
