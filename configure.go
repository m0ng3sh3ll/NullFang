package main

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/m0ng3sh3ll/NullFang/auth"
	copyutil "github.com/m0ng3sh3ll/NullFang/copy"
	"github.com/m0ng3sh3ll/NullFang/logger"
	"github.com/m0ng3sh3ll/NullFang/search"
	"github.com/m0ng3sh3ll/NullFang/utils"
)

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
		if !*quietFlag && !*machineFlag && !checkAdminOnly {
			nKw := len(patterns.Patterns.Credentials) + len(patterns.Patterns.Sensitive)
			nExt := len(patterns.Patterns.Extensions)
			nRe := len(patterns.Patterns.Regex)
			fmt.Printf("[!] No search criteria — using default.yaml (%d keywords, %d extensions, %d regex)\n", nKw, nExt, nRe)
			fmt.Printf("[!] Use -m / -r / -e to target specific patterns, or -mode recon to enumerate only.\n")
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
		}
		cmdPatterns.Patterns.Sensitive = cmdPatterns.Patterns.Credentials
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
	config.Verbose = *verboseFlag
	config.MaxFileSize = *maxSizeFlag
	config.CaseSensitive = *caseSensitive
	config.SearchBinary = *binaryFlag
	config.MinBinaryStringLen = *minBinaryStringFlag
	config.MaxCacheFileSize = *maxCacheFileSizeFlag
	config.MaxDepth = *maxDepthFlag
	config.Timeout = *timeoutFlag
	config.MaxWorkers = *threadsFlag // Aplicar flag -threads ao MaxWorkers

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

	// --- STEALTH / BEHAVIORAL FLAGS ---
	config.PreserveAtime = *preserveAtimeFlag
	config.RandomizeOrder = !*noRandomizeFlag
	config.SkipCanaryFiles = !*noSkipCanaryFlag
	if *operationDelayMsFlag > 0 {
		config.OperationDelay = time.Duration(*operationDelayMsFlag) * time.Millisecond
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
		"username":    *usernameFlag,
		"domain":      *domainFlag,
		"password":    *passwordFlag,
		"target_host": host,
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

// Helper function to determine the authentication method being used
func determineAuthMethod() string {
	if *nullSessionFlag {
		return "null_session"
	}
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
