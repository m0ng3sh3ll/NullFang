package main

import (
	"bufio"
	"database/sql"
	"fmt"
	"os"
	"strings"
)

var startupMsgs []string

func queueStartupMsg(format string, args ...any) {
	startupMsgs = append(startupMsgs, fmt.Sprintf(format, args...))
}

func flushStartupMsgs() {
	for _, m := range startupMsgs {
		fmt.Println(m)
	}
	startupMsgs = nil
}

const chatSystemTpl = `You are an offensive security intelligence analyst assistant embedded in nfpath.
You have analyzed files from an SMB scan engagement and built an intelligence graph.

ENGAGEMENT INTELLIGENCE:
%s

Answer operator questions concisely and tactically.
Cite specific findings (credentials, hosts, files) when relevant.
For attack paths be concrete: "credential X → system Y → can pivot to Z via ...".
Do not hallucinate. Only reference intel shown above.
If intel is insufficient to answer, say so plainly.`

func runChat(nfpathDB *sql.DB, llm LLMClient, maxItems int) {
	summary := buildChatContext(nfpathDB, maxItems)
	system := fmt.Sprintf(chatSystemTpl, summary)

	scanner := bufio.NewScanner(os.Stdin)
	printBanner()
	flushStartupMsgs()
	fmt.Printf("\n[nfpath chat] model=\033[33m%s\033[0m  context=%d chars\n", llm.ModelName(), len(summary))

	// Warn about context limits for small models
	contextChars := len(summary)
	switch {
	case contextChars > 6000:
		fmt.Printf("\033[31m[WARN] context is %d chars — may exceed 3B/7B model limits\033[0m\n", contextChars)
		fmt.Printf("       Use: nfpath -llm-model mistral:7b -max-context-items 15 chat\n")
	case contextChars > 3500:
		fmt.Printf("\033[33m[WARN] large context (%d chars) — 3B models may truncate\033[0m\n", contextChars)
		fmt.Printf("       Use: nfpath -max-context-items 15 chat  (or switch to 7B+ model)\n")
	}

	fmt.Println("\n  /help for commands   /quit to exit\n")

	for {
		fmt.Print("nfpath> ")
		if !scanner.Scan() {
			break
		}
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		switch line {
		case "/quit", "/exit", "quit", "exit":
			return
		case "/decisions":
			printDecisions(nfpathDB)
		case "/creds":
			printCredentials(nfpathDB)
		case "/hosts":
			printHosts(nfpathDB)
		case "/status":
			printStatus(nfpathDB)
		case "/refresh":
			summary = buildChatContext(nfpathDB, maxItems)
			system = fmt.Sprintf(chatSystemTpl, summary)
			fmt.Println("[context refreshed from DB]")
		case "/help":
			printChatHelp()
		default:
			fmt.Print("\n\033[36m")
			if err := llm.Stream(system, line, os.Stdout); err != nil {
				fmt.Printf("\033[0m[error] %v\n", err)
			} else {
				fmt.Print("\033[0m")
			}
			fmt.Println()
		}
	}
}

func buildChatContext(db *sql.DB, maxItems int) string {
	var sb strings.Builder

	rows, _ := db.Query(`
		SELECT username, password_clear, hash, token, service_type, confidence, host_hint, context_note
		FROM intel_credentials
		ORDER BY CASE confidence WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END
		LIMIT ?`, maxItems)
	if rows != nil {
		defer rows.Close()
		sb.WriteString("CREDENTIALS:\n")
		for rows.Next() {
			var user, pass, hash, token, svc, conf, host, ctx sql.NullString
			rows.Scan(&user, &pass, &hash, &token, &svc, &conf, &host, &ctx)
			sb.WriteString(fmt.Sprintf("  [%s] %s", conf.String, user.String))
			if pass.Valid && pass.String != "" {
				sb.WriteString(fmt.Sprintf(":%s", pass.String))
			}
			if hash.Valid && hash.String != "" {
				sb.WriteString(fmt.Sprintf(" (hash:%s)", truncate(hash.String, 32)))
			}
			if token.Valid && token.String != "" {
				sb.WriteString(fmt.Sprintf(" (token:%s)", truncate(token.String, 40)))
			}
			sb.WriteString(fmt.Sprintf(" → %s", svc.String))
			if host.Valid && host.String != "" {
				sb.WriteString(fmt.Sprintf(" @ %s", host.String))
			}
			if ctx.Valid && ctx.String != "" {
				sb.WriteString(fmt.Sprintf(" [%s]", ctx.String))
			}
			sb.WriteString("\n")
		}
		rows.Close()
	}

	rows2, _ := db.Query(`
		SELECT identifier, identifier_type, inferred_type, confidence, discovery_note
		FROM intel_hosts
		ORDER BY CASE confidence WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END
		LIMIT ?`, maxItems)
	if rows2 != nil {
		defer rows2.Close()
		sb.WriteString("\nHOSTS/SERVICES:\n")
		for rows2.Next() {
			var ident, itype, inferred, conf, note sql.NullString
			rows2.Scan(&ident, &itype, &inferred, &conf, &note)
			sb.WriteString(fmt.Sprintf("  [%s] %s (%s) → %s\n",
				conf.String, ident.String, itype.String, inferred.String))
		}
		rows2.Close()
	}

	rows3, _ := db.Query(`
		SELECT file_path, host, match_reason, inferred_value, priority
		FROM intel_decisions
		WHERE status='pending'
		ORDER BY CASE priority WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 ELSE 4 END
		LIMIT ?`, maxItems)
	if rows3 != nil {
		defer rows3.Close()
		sb.WriteString("\nPENDING DECISIONS (files not copied):\n")
		for rows3.Next() {
			var path, host, reason, inferred, pri sql.NullString
			rows3.Scan(&path, &host, &reason, &inferred, &pri)
			sb.WriteString(fmt.Sprintf("  [%s] %s on %s — matched: %s — inferred: %s\n",
				pri.String, path.String, host.String, reason.String, inferred.String))
		}
		rows3.Close()
	}

	return sb.String()
}

func printDecisions(db *sql.DB) {
	rows, err := db.Query(`
		SELECT id, priority, host, file_path, match_reason, inferred_value, recommended_action, status
		FROM intel_decisions
		ORDER BY CASE priority WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 ELSE 4 END, id`)
	if err != nil {
		fmt.Printf("[error] %v\n", err)
		return
	}
	defer rows.Close()

	fmt.Println("\n[DECISION TABLE]")
	any := false
	for rows.Next() {
		any = true
		var id int
		var pri, host, path, reason, inferred, action, status sql.NullString
		rows.Scan(&id, &pri, &host, &path, &reason, &inferred, &action, &status)
		color := priorityColor(pri.String)
		fmt.Printf("%s[%s] #%d %s\n", color, strings.ToUpper(pri.String), id, path.String)
		fmt.Printf("     Host    : %s\n", host.String)
		fmt.Printf("     Matched : %s\n", reason.String)
		fmt.Printf("     Intel   : %s\n", inferred.String)
		fmt.Printf("     Action  : %s\n", action.String)
		fmt.Printf("     Status  : %s\033[0m\n\n", status.String)
	}
	if !any {
		fmt.Println("  (no decisions)")
	}
}

func printCredentials(db *sql.DB) {
	rows, err := db.Query(`
		SELECT username, password_clear, hash, token, service_type, confidence, host_hint, context_note
		FROM intel_credentials
		ORDER BY CASE confidence WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END`)
	if err != nil {
		fmt.Printf("[error] %v\n", err)
		return
	}
	defer rows.Close()

	fmt.Println("\n[CREDENTIALS]")
	count := 0
	for rows.Next() {
		var user, pass, hash, token, svc, conf, host, ctx sql.NullString
		rows.Scan(&user, &pass, &hash, &token, &svc, &conf, &host, &ctx)
		color := confidenceColor(conf.String)
		fmt.Printf("%s  [%s]", color, conf.String)
		if user.Valid && user.String != "" {
			fmt.Printf(" %s", user.String)
			if pass.Valid && pass.String != "" {
				fmt.Printf(":%s", pass.String)
			}
		} else if pass.Valid && pass.String != "" {
			fmt.Printf(" [pass] %s", pass.String)
		}
		if hash.Valid && hash.String != "" {
			fmt.Printf(" (hash:%s)", truncate(hash.String, 32))
		}
		if token.Valid && token.String != "" {
			fmt.Printf(" [token:%s]", truncate(token.String, 40))
		}
		fmt.Printf(" → %s", svc.String)
		if host.Valid && host.String != "" {
			fmt.Printf(" @ %s", host.String)
		}
		if ctx.Valid && ctx.String != "" && user.String == "" && pass.String == "" && hash.String == "" && token.String == "" {
			fmt.Printf("\n         context: %s", truncate(ctx.String, 120))
		}
		fmt.Printf("\033[0m\n")
		count++
	}
	if count == 0 {
		fmt.Println("  (none found — run 'nfpath -v analyze' to diagnose)")
	}
	fmt.Println()
}

func printHosts(db *sql.DB) {
	// Deduplicate by (identifier, identifier_type): best confidence + aggregated services.
	rows, err := db.Query(`
		SELECT
			identifier,
			identifier_type,
			GROUP_CONCAT(DISTINCT CASE WHEN inferred_type != '' AND inferred_type IS NOT NULL THEN inferred_type END) AS services,
			CASE MAX(CASE confidence WHEN 'high' THEN 3 WHEN 'medium' THEN 2 ELSE 1 END)
				WHEN 3 THEN 'high' WHEN 2 THEN 'medium' ELSE 'low' END AS best_conf,
			COUNT(*) AS seen
		FROM intel_hosts
		GROUP BY identifier, identifier_type
		ORDER BY MAX(CASE confidence WHEN 'high' THEN 3 WHEN 'medium' THEN 2 ELSE 1 END) DESC, identifier`)
	if err != nil {
		fmt.Printf("[error] %v\n", err)
		return
	}
	defer rows.Close()

	fmt.Println("\n[HOSTS & SERVICES]")
	count := 0
	for rows.Next() {
		var ident, itype, services, conf sql.NullString
		var seen int
		rows.Scan(&ident, &itype, &services, &conf, &seen)
		color := confidenceColor(conf.String)
		svcStr := services.String
		if svcStr == "" {
			svcStr = "unknown"
		}
		seenNote := ""
		if seen > 1 {
			seenNote = fmt.Sprintf(" (×%d files)", seen)
		}
		fmt.Printf("%s  [%s] %s (%s) → %s%s\033[0m\n",
			color, conf.String, ident.String, itype.String, svcStr, seenNote)
		count++
	}
	if count == 0 {
		fmt.Println("  (none)")
	}
	fmt.Println()
}

func printStatus(db *sql.DB) {
	var creds, hosts, services, decisions, pending, processed int
	db.QueryRow("SELECT COUNT(*) FROM intel_credentials").Scan(&creds)
	db.QueryRow("SELECT COUNT(*) FROM intel_hosts").Scan(&hosts)
	db.QueryRow("SELECT COUNT(*) FROM intel_services").Scan(&services)
	db.QueryRow("SELECT COUNT(*) FROM intel_decisions").Scan(&decisions)
	db.QueryRow("SELECT COUNT(*) FROM intel_decisions WHERE status='pending'").Scan(&pending)
	db.QueryRow("SELECT COUNT(*) FROM intel_sources").Scan(&processed)

	var highCreds int
	db.QueryRow("SELECT COUNT(*) FROM intel_credentials WHERE confidence='high'").Scan(&highCreds)

	fmt.Printf("\n[STATUS]\n")
	fmt.Printf("  Files processed    : %d\n", processed)
	fmt.Printf("  Credentials        : %d (%d high confidence)\n", creds, highCreds)
	fmt.Printf("  Hosts/services     : %d hosts, %d services\n", hosts, services)
	fmt.Printf("  Decision table     : %d total, %d pending\n", decisions, pending)
	fmt.Println()
}

func printChatHelp() {
	fmt.Print(`
[COMMANDS]
  /decisions  show decision table (files not copied, need action)
  /creds      list all extracted credentials
  /hosts      list discovered hosts and services
  /status     processing statistics
  /refresh    reload intelligence context from DB (pipeline mode)
  /quit       exit

[EXAMPLE QUERIES]
  nfpath> what credentials give the most access?
  nfpath> is there a path to domain admin from what we found?
  nfpath> explain what was in the SAP configs
  nfpath> which system should I target first?
  nfpath> are there any reused passwords?

`)
}

func printBanner() {
	fmt.Print("\033[35m")
	fmt.Print(`
 ███╗   ██╗███████╗██████╗  █████╗ ████████╗██╗  ██╗
 ████╗  ██║██╔════╝██╔══██╗██╔══██╗╚══██╔══╝██║  ██║
 ██╔██╗ ██║█████╗  ██████╔╝███████║   ██║   ███████║
 ██║╚██╗██║██╔══╝  ██╔═══╝ ██╔══██║   ██║   ██╔══██║
 ██║ ╚████║██║     ██║     ██║  ██║   ██║   ██║  ██║
 ╚═╝  ╚═══╝╚═╝     ╚═╝     ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝
`)
	fmt.Print("\033[0m")
	fmt.Println(" SMB Intelligence Correlation Engine")
}

func priorityColor(p string) string {
	switch p {
	case "critical":
		return "\033[31;1m"
	case "high":
		return "\033[33m"
	case "medium":
		return "\033[36m"
	default:
		return "\033[37m"
	}
}

func confidenceColor(c string) string {
	switch c {
	case "high":
		return "\033[32m"
	case "medium":
		return "\033[33m"
	default:
		return "\033[37m"
	}
}
