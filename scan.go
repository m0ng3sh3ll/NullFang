package main

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	copyutil "github.com/m0ng3sh3ll/NullFang/copy"
	"github.com/m0ng3sh3ll/NullFang/database"
	smb2 "github.com/m0ng3sh3ll/NullFang/go-smb2-patch"
	"github.com/m0ng3sh3ll/NullFang/logger"
	"github.com/m0ng3sh3ll/NullFang/scanner"
	"github.com/m0ng3sh3ll/NullFang/search"
	"github.com/m0ng3sh3ll/NullFang/smb"
)

// checkAdminPrivileges uses stealth TreeConnect to C$ / ADMIN$ (one SMB2 packet each).
// No named-pipe opens, no RPC calls — avoids the well-known CME/NetExec signature.
// Works cross-platform: Mount() is go-smb2 TreeConnect, not an OS-level mount.
// Returns true if the session has admin access.
func checkAdminPrivileges(conn *smb.SMBConnection) bool {
	if conn == nil || conn.Connection == nil {
		logger.Debug("[check-admin] conn or conn.Connection is nil")
		return false
	}
	for _, share := range []string{"C$", "ADMIN$"} {
		fs, err := conn.Connection.Mount(share)
		if err == nil {
			fs.Umount()
			logger.Debug("[check-admin] Mount(%s) succeeded → admin confirmed", share)
			return true
		}
		errLower := strings.ToLower(err.Error())
		logger.Debug("[check-admin] Mount(%s) error: %v", share, err)
		// Definitive non-admin responses (Windows STATUS_ACCESS_DENIED, Samba "permission denied")
		if strings.Contains(errLower, "access_denied") ||
			strings.Contains(errLower, "access denied") ||
			strings.Contains(errLower, "status_access_denied") ||
			strings.Contains(errLower, "0xc0000022") ||
			strings.Contains(errLower, "permission denied") {
			logger.Debug("[check-admin] Access denied on %s — not admin", share)
			return false
		}
		// Other error (share missing, network hiccup) → try next share
	}
	return false
}

func processShares(conn *smb.SMBConnection, host string) map[string]*search.MountedShare {
	// Se especificou shares, vamos processar o que o usuário pediu diretamente
	if *specificShareFlag != "" {
		mountedShares := make(map[string]*search.MountedShare)
		requestedShares := strings.Split(*specificShareFlag, ",")

		availableShares, err := conn.ListShares()
		if err != nil {
			logger.Warning("[-] Failed to list shares on %s (but continuing with requested shares): %v", host, err)
			// Continuamos mesmo se falhar em listar, pois o usuário especificou o que quer
		}

		for _, req := range requestedShares {
			req = strings.TrimSpace(req)
			if req == "" {
				continue
			}

			// Parse share name and path
			// Formats: "Share", "Share\Path", "Share/Path"
			req = strings.ReplaceAll(req, "/", "\\")
			parts := strings.SplitN(req, "\\", 2)

			shareName := parts[0]
			startPath := "."
			if len(parts) > 1 && parts[1] != "" {
				startPath = parts[1]
			}

			// Validate if share exists (optional check against availableShares)
			found := false
			if availableShares != nil {
				for _, s := range availableShares {
					if strings.EqualFold(s, shareName) {
						shareName = s // Use correct case from server
						found = true
						break
					}
				}
				if !found && availableShares != nil {
					// Se pudemos listar e não achamos, avisamos mas tentamos montar igual (pode ser hidden)
					logger.Debug("Requested share %s not found in enumeration list", shareName)
				}
			}

			fs, err := conn.MountShare(shareName)
			if err != nil {
				logger.Error("[-] Failed to mount share %s on %s: %v", shareName, host, err)
				continue
			}

			shareNameWithIP := fmt.Sprintf("\\\\%s\\%s", host, shareName)
			mountedShares[shareNameWithIP] = &search.MountedShare{
				Share:     fs,
				StartPath: startPath,
				ShareName: shareName,
			}
			logger.Debug("Mounted share %s with start path: %s", shareName, startPath)
		}
		return mountedShares
	}

	// Se não especificou share, lista todos e monta na raiz
	shares, err := conn.ListShares()
	if err != nil {
		logger.Error("[-] Failed to list shares on %s: %v", host, err)
		return nil
	}

	if *verboseFlag {
		logger.Info("Found %d shares on %s", len(shares), host)
	}

	// ACL pre-check via MSRPC: get share types to skip printer/device/IPC mounts
	// before attempting to mount them (reduces Windows event 5140/5145 noise).
	shareTypes := smb.GetShareTypes(conn.Connection, host)

	mountedShares := make(map[string]*search.MountedShare)
	for i, shareName := range shares {
		if isSpecialShare(shareName) {
			continue
		}

		// Skip non-disk shares (printers, comm devices, IPC) by MSRPC type
		if shareTypes != nil {
			if t, ok := shareTypes[shareName]; ok && !smb.IsSearchableShare(t) {
				logger.Debug("[ACL-PRE] Skipping non-disk share %s (type=%d)", shareName, t)
				continue
			}
		}

		if i > 0 {
			jitterSleep(*jitterFlag)
		}

		if fs, err := conn.MountShare(shareName); err == nil {
			shareNameWithIP := fmt.Sprintf("\\\\%s\\%s", host, shareName)
			mountedShares[shareNameWithIP] = &search.MountedShare{
				Share:     fs,
				StartPath: ".",
				ShareName: shareName,
			}
		}
	}

	return mountedShares
}

// processHostWithMessages
// Versão de processHost que acumula mensagens para exibir ao final
func processHostWithMessages(host string, searchConfig *search.SearchConfig, copyConfig *copyutil.CopyConfig, fileContentCache *scanner.FileContentCache, messages *[]string, throttler *smb.Throttler) error {
	// Check lockout guard before attempting connection.
	authGuard.mu.Lock()
	halted := authGuard.halted
	authGuard.mu.Unlock()
	if halted {
		return fmt.Errorf("scan halted by lockout guard — check credentials")
	}

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
		Host:        host,
		Port:        *portFlag,
		Domain:      domain,
		Username:    *usernameFlag,
		Password:    *passwordFlag,
		Timeout:     30 * time.Second, // TCP dial timeout; sessão é gerenciada pelo host context (5min)
		Socks5Proxy: *socks5Flag,
		Dialect:     copyConfig.Dialect,
		Signing:     copyConfig.Signing,
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
			// Lockout guard: track auth failures within this run AND across runs.
			// Only count SMB auth failures — not TCP/network errors.
			if *lockoutThresholdFlag > 0 && strings.Contains(connectionError.Error(), "SMB authentication failed") {
				authGuard.mu.Lock()
				authGuard.count++
				count := authGuard.count
				if count >= *lockoutThresholdFlag {
					authGuard.halted = true
					smb.HaltAuth()
				}
				authGuard.mu.Unlock()
				if authGuard.halted {
					// Read persistent failure counter to calibrate the warning message.
					prevFails := readPersistentAuthFailCount()
					writePersistentAuthFailCount(prevFails + 1)
					fmt.Printf("\n")
					logger.Warning("\033[1;31m╔══════════════════════════════════════════════════════╗\033[0m")
					logger.Warning("\033[1;31m║          ⚠  LOCKOUT GUARD — SCAN STOPPED  ⚠          ║\033[0m")
					logger.Warning("\033[1;31m╚══════════════════════════════════════════════════════╝\033[0m")
					if prevFails == 0 {
						logger.Warning("[LOCKOUT GUARD] Authentication failed on %s.", host)
						logger.Warning("[LOCKOUT GUARD] Verify your credentials before retrying.")
						logger.Warning("[LOCKOUT GUARD] Every wrong attempt increments the AD lockout counter.")
					} else {
						logger.Warning("[LOCKOUT GUARD] Authentication failed again on %s (run #%d with this error).", host, prevFails+1)
						logger.Warning("\033[1;33m[LOCKOUT GUARD] ⚠  HIGH RISK: the next failed attempt will likely lock the account!\033[0m")
						logger.Warning("[LOCKOUT GUARD] Check credentials carefully. If correct, the account may already be locked.")
					}
					logger.Warning("[LOCKOUT GUARD] Use -lockout-threshold 0 to disable this guard (NOT recommended on AD).")
					fmt.Printf("\n")
				}
			}
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
		// Successful auth: reset in-memory and on-disk failure counters.
		authGuard.mu.Lock()
		authGuard.count = 0
		authGuard.mu.Unlock()
		resetPersistentAuthFailCount()
		defer func() {
			logger.Debug("[DEBUG] About to disconnect from %s", host)
			// Sleep para garantir que workers e keep-alive terminem
			time.Sleep(500 * time.Millisecond)
			conn.Disconnect()
		}()

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
				// smbConfig.Domain drives the NTLM local-auth domain field (machine name).
				// copyConfig.Domain stays as *domainFlag so DB records are consistent
				// with what the user passed via -d (or empty for no -d).
				if hostname != "" {
					smbConfig.Domain = hostname
				}
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

	// check-admin-only: connect, check privilege via stealth TreeConnect, exit — no share scan
	if checkAdminOnly {
		isAdmin := checkAdminPrivileges(conn)
		if isAdmin {
			fmt.Printf("[+] %s — Pwn3d! (C$ / ADMIN$ reachable)\n", host)
		} else {
			fmt.Printf("[-] %s — Not admin (C$ and ADMIN$ denied)\n", host)
		}
		saveCredential(db, smbConfig.Domain, *usernameFlag, determineAuthMethod(), host, *passwordFlag, *ntlmHashFlag, *ticketFileFlag, time.Now().Format("2006-01-02 15:04:05"), isAdmin)
		return nil
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

	// Search files with host timeout
	resultsChan := make(chan *search.SearchResult, 1000)
	var searchErr error

	// Context com timeout para o host inteiro
	hostCtx, hostCancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer hostCancel()

	// Canal para sinalizar quando a busca terminar
	searchDone := make(chan error, 1)

	// Garantir que resultsChan seja fechado apenas uma vez
	var closeOnce sync.Once
	closeResultsChan := func() {
		closeOnce.Do(func() {
			close(resultsChan)
		})
	}

	// Delta mode: preload previously seen files for this host from DB
	if *deltaFlag && db != nil {
		knownFiles, err := database.LoadKnownFiles(db, host)
		if err != nil {
			logger.Warning("[DELTA] Failed to load known files for %s: %v", host, err)
		} else {
			searchConfig.DeltaMode = true
			searchConfig.KnownFiles = knownFiles
			logger.Info("[DELTA] Mode active for %s — %d files tracked", host, len(knownFiles))
		}
	}

	go func() {
		defer closeResultsChan()
		searchErr = search.SearchMultipleSharesStream(shares, searchConfig, fileContentCache, resultsChan)
		select {
		case searchDone <- searchErr:
		case <-hostCtx.Done():
			// Host foi cancelado, não enviar erro
		}
	}()

	// Processar resultados em goroutine separada para não perder arquivos em caso de timeout
	var copyWg sync.WaitGroup
	copyWg.Add(1)
	go func() {
		defer copyWg.Done()
		// Convert shares to map[string]*smb2.Share for copyutil
		simpleShares := make(map[string]*smb2.Share)
		for k, v := range shares {
			simpleShares[k] = v.Share
		}

		// Keepalive runs during search + copy: Echo on each share every 10s.
		// Prevents SMB session timeout during long operations.
		keepaliveCtx, keepaliveStop := context.WithCancel(context.Background())
		defer keepaliveStop()
		for _, s := range simpleShares {
			s := s
			go func() {
				ticker := time.NewTicker(10 * time.Second)
				defer ticker.Stop()
				for {
					select {
					case <-keepaliveCtx.Done():
						return
					case <-ticker.C:
						if err := s.Echo(); err != nil && *verboseFlag {
							logger.Debug("[KEEP-ALIVE] Echo error: %v", err)
						}
					}
				}
			}()
		}

		// Process each result immediately as it arrives (streaming copy).
		// Dedup by share+path to avoid copying the same file multiple times.
		seen := make(map[string]struct{})
		for result := range resultsChan {
			key := result.ShareName + "|" + result.FilePath
			if _, dup := seen[key]; dup {
				if *verboseFlag {
					logger.Debug("[DEDUP] Skipping duplicate: %s", result.FilePath)
				}
				continue
			}
			seen[key] = struct{}{}

			_, err := copyutil.CopySingleMatch(ctx, db, simpleShares, result, copyConfig, host, throttler)
			if err != nil {
				logger.Error("[-] Failed to copy %s: %v", result.FilePath, err)
			}
		}
	}()

	// Aguardar busca ou timeout do host
	select {
	case err := <-searchDone:
		if err != nil && *verboseFlag {
			logger.Debug("Search error on %s: %v", host, err)
		}
		// Se há muitos erros de timeout, considerar como host problemático
		if err != nil && strings.Contains(err.Error(), "directory . consistently timing out") {
			fmt.Printf("⚠️ Host %s has multiple timeout issues. Skipping to next host.\n", host)
			searchErr = fmt.Errorf("host %s has multiple timeout issues", host)
		} else {
			searchErr = err
		}
	case <-hostCtx.Done():
		// Host timeout - encerrar busca
		fmt.Printf("⏰ Host %s timeout after 5 minutes. Skipping to next host.\n", host)
		searchErr = fmt.Errorf("host %s timeout after 5 minutes", host)
		// Fechar canal usando sync.Once
		closeResultsChan()
	}

	// Aguardar que todos os arquivos encontrados sejam copiados
	copyWg.Wait()

	// IMPORTANTE: Aguardar um pouco para garantir que goroutines de keep-alive dos shares terminem
	time.Sleep(100 * time.Millisecond)

	if checkpointInstance != nil {
		checkpointInstance.MarkHostProcessed(host)
		if err := checkpointInstance.Save(); err != nil && *verboseFlag {
			logger.Debug("[-] Error saving checkpoint after processing %s: %v", host, err)
		}
		checkpointInstance.Save()
	}

	// Admin check via stealth TreeConnect (C$ / ADMIN$) — only when -check-admin is set
	isAdmin := false
	if *checkAdminFlag {
		isAdmin = checkAdminPrivileges(conn)
		if *verboseFlag {
			if isAdmin {
				logger.Success("[Pwn3d] %s — admin access confirmed (C$ / ADMIN$ reachable)", host)
			} else {
				logger.Info("[USER] %s — not admin (C$ and ADMIN$ access denied)", host)
			}
		}
	}

	saveCredential(db, smbConfig.Domain, *usernameFlag, determineAuthMethod(), host, *passwordFlag, *ntlmHashFlag, *ticketFileFlag, time.Now().Format("2006-01-02 15:04:05"), isAdmin)
	return nil
}
