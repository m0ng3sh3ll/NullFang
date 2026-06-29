package main

import (
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/m0ng3sh3ll/NullFang/checkpoint"
	copyutil "github.com/m0ng3sh3ll/NullFang/copy"
	"github.com/m0ng3sh3ll/NullFang/database"
	"github.com/m0ng3sh3ll/NullFang/logger"
	"github.com/m0ng3sh3ll/NullFang/scanner"
	"github.com/m0ng3sh3ll/NullFang/search"
	"github.com/m0ng3sh3ll/NullFang/smb"
	"github.com/m0ng3sh3ll/NullFang/utils"
)

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

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "NullFang "+VERSION+" — SMB share intelligence & file exfiltration\n")
		fmt.Fprintf(os.Stderr, "Usage: nullfang [flags] -H <host> -u <user> -p <pass>\n")
		fmt.Fprintf(os.Stderr, "Run 'nullfang -help' for complete options.\n")
	}
	flag.Parse()

	// Apply derived modes before any other logic reads the internal vars.
	applyOutputFlag() // --output → verboseFlag / machineFlag / quietFlag
	applyModeFlag()   // --mode   → noCopyFlag / noCopyDeepFlag

	// Pre-load config YAML settings so internal vars are correct before configureSearch().
	// Pattern data is loaded again inside configureSearch() — small cost, clean architecture.
	if *configFileFlag != "" {
		if pats, err := search.LoadPatterns(*configFileFlag); err == nil {
			applyScanConfigFromYAML(pats)
		}
	}
	// Stealth overrides YAML settings (always wins).
	applyStealthMode()

	// Capture user intent NOW — before configureSearch() (called twice: checkpoint + main)
	// overwrites *matchFlag/*regexFlag/*extensionsFlag with defaults from the YAML file.
	checkAdminOnly = *checkAdminFlag && isBlank(*matchFlag) && isBlank(*regexFlag) && isBlank(*extensionsFlag)

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

	// noCopyFlag / noCopyDeepFlag are set by applyModeFlag() — always consistent.

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
	// Validação do username será feita após carregar o checkpoint
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
		if !*nullSessionFlag && isBlank(*passwordFlag) && isBlank(*ntlmHashFlag) {
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

		// Validar se username foi obtido do checkpoint ou fornecido
		if !*nullSessionFlag && isBlank(*usernameFlag) {
			printUsageError(
				"Username not found in checkpoint and not provided. Please specify username with -u <username>.",
				"NullFang -resume checkpoints/nullfang_resume_*.json -u admin -p <password>",
			)
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
	copyConfig.Socks5Proxy = *socks5Flag

	// Após configurar as flags e o SearchConfig
	fileContentCache, err := scanner.NewFileContentCache(*lruCacheSizeFlag)
	if err != nil {
		logger.Fatal("Error initializing file LRU cache: %v", err)
	}

	// Ajuste para não reportar arquivos grandes se estiver buscando algo específico (extensão, nome, conteúdo)
	hasSearchCriteria := len(searchConfig.FileExtensions) > 0 ||
		len(searchConfig.FilenamePatterns) > 0 ||
		len(searchConfig.ContentPatterns) > 0 ||
		len(searchConfig.RegexPatterns) > 0

	if *noCopyFlag || hasSearchCriteria {
		searchConfig.FilterLargeFiles = true // filtrar large_files se houver critérios de busca
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
		} else if !checkAdminOnly {
			fmt.Printf("🎯 %s:\n", res.host)
			for i, msg := range res.messages {
				if strings.HasPrefix(msg, "[Host: ") {
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

	if checkAdminOnly {
		return
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
			// --- No-copy mode: all data from SQLite, organized by host ---
			if *noCopyFlag || *noCopyDeepFlag {
				qUser := strings.ToLower(*usernameFlag)
				qDomain := strings.ToUpper(*domainFlag)

				type lhfHostStats struct {
					total    int
					large    int
					newCount int
				}
				statsByHost := make(map[string]lhfHostStats)
				totalInteresting := 0
				totalNewLHF := 0

				for _, host := range hosts {
					var s lhfHostStats
					db.QueryRow(
						`SELECT COUNT(*) FROM low_hanging_fruit WHERE host = ? AND LOWER(domain) = LOWER(?) AND LOWER(user) = LOWER(?)`,
						host, qDomain, qUser,
					).Scan(&s.total)
					db.QueryRow(
						`SELECT COUNT(*) FROM low_hanging_fruit WHERE host = ? AND LOWER(domain) = LOWER(?) AND LOWER(user) = LOWER(?) AND large_file = 1`,
						host, qDomain, qUser,
					).Scan(&s.large)
					db.QueryRow(
						`SELECT COUNT(*) FROM low_hanging_fruit WHERE host = ? AND LOWER(domain) = LOWER(?) AND LOWER(user) = LOWER(?) AND found_time >= ?`,
						host, qDomain, qUser, execStartTime,
					).Scan(&s.newCount)
					statsByHost[host] = s
					totalInteresting += s.total
					totalNewLHF += s.newCount
				}

				// Machine output
				if *machineFlag {
					type lhfEntry struct {
						Host       string `json:"host"`
						FilesFound int    `json:"files_found"`
						LargeFiles int    `json:"large_files"`
						NewFiles   int    `json:"new_files_this_run"`
					}
					lhfList := make([]lhfEntry, 0, len(hosts))
					for _, host := range hosts {
						s := statsByHost[host]
						lhfList = append(lhfList, lhfEntry{
							Host:       host,
							FilesFound: s.total,
							LargeFiles: s.large,
							NewFiles:   s.newCount,
						})
					}
					output := map[string]any{
						"target":            summaryIP,
						"processed_hosts":   totalHosts,
						"files_found":       totalInteresting,
						"hosts_failed":      failedHosts,
						"hosts_without_smb": noSMBHosts,
						"low_hanging_fruit": lhfList,
						"new_files_this_run": totalNewLHF,
					}
					enc := json.NewEncoder(os.Stdout)
					enc.SetIndent("", "  ")
					enc.Encode(output)
					return
				}

				// Quiet output
				if *quietFlag {
					fmt.Printf("\nTarget: %s\n", summaryIP)
					fmt.Printf("Processed Hosts: %d\n", totalHosts)
					fmt.Printf("Interesting Files Found: %d\n", totalInteresting)
					fmt.Printf("New This Run: %d\n", totalNewLHF)
					fmt.Printf("Hosts Failed: %d\n", failedHosts)
					fmt.Printf("Hosts without SMB: %d\n", noSMBHosts)
					for _, host := range hosts {
						s := statsByHost[host]
						fmt.Printf(" - %s: %d file(s) (large: %d, new: %d)\n",
							host, s.total, s.large, s.newCount)
					}
					return
				}

				// Visual output
				fmt.Printf("\n═══════════════════════════════════════════════════════\n")
				fmt.Printf("      NullFang - Execution Summary\n")
				fmt.Printf("═══════════════════════════════════════════════════════\n\n")
				fmt.Printf(" 🎯 Target(s): %s\n", summaryIP)
				fmt.Printf(" 🖥️  Processed Hosts: %d\n", totalHosts)
				if *nullSessionFlag || *usernameFlag == "" {
					fmt.Printf(" 🔑 User: ANONYMOUS (null session)\n")
				} else {
					fmt.Printf(" 🔑 User: %s - %s\n", *usernameFlag, getUserStatus(db, *hostFlag, *usernameFlag))
				}
				fmt.Printf(" 🛠️  Domain: %s\n", getDisplayDomain(db, *hostFlag))
				fmt.Printf(" 🚫 Hosts Failed: %d\n", failedHosts)
				fmt.Printf("\n═══════════════════════════════════════════════════════\n")
				fmt.Printf("   🍏 LOW-HANGING FRUIT (Interesting Files)\n")
				fmt.Printf("═══════════════════════════════════════════════════════\n")
				for _, host := range hosts {
					s := statsByHost[host]
					fmt.Printf(" - %s:\n", host)
					fmt.Printf("    ➔ %d file(s) listed (large: %d, new this run: %d)\n",
						s.total, s.large, s.newCount)
					if s.newCount > 0 {
						fmt.Printf("    🍏 %d new interesting file(s) found!\n", s.newCount)
					} else {
						fmt.Printf("    ℹ️  No new interesting files found.\n")
					}
					fmt.Println()
				}
				if totalInteresting > 0 {
					fmt.Printf(" 🍏 %d total interesting file(s). Use nfdb to explore:\n", totalInteresting)
					fmt.Printf("    nfdb\n\n")
				}
				finalizeRun(checkpointInstance)
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

			finalizeRun(checkpointInstance)
			return
		}
		finalizeRun(checkpointInstance)
		return
	}

	fmt.Printf("\033[1;31m\nNullFang executed successfully\n\033[0m")
	if *verboseFlag {
		logger.Info("[DEBUG] End of main() function - program should exit now.")
	}

	// --- Antes do return do resumo visual ---
	if totalFiles == 0 {
		fmt.Printf("\n⚠️ No files were copied during the scan.\n\n")
		finalizeRun(checkpointInstance)
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
