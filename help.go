package main

import "fmt"

func showBanner() {
	banner := `
%s███╗   ██╗██╗   ██╗██╗     ██╗     ███████╗ █████╗ ███╗   ██╗ ██████╗ %s
%s████╗  ██║██║   ██║██║     ██║     ██╔════╝██╔══██╗████╗  ██║██╔════╝ %s
%s██╔██╗ ██║██║   ██║██║     ██║     █████╗  ███████║██╔██╗ ██║██║  ███╗%s
%s██║╚██╗██║██║   ██║██║     ██║     ██╔══╝  ██╔══██║██║╚██╗██║██║   ██║%s
%s██║ ╚████║╚██████╔╝███████╗███████╗██║     ██║  ██║██║ ╚████║╚██████╔╝%s
%s╚═╝  ╚═══╝ ╚═════╝ ╚══════╝╚══════╝╚═╝     ╚═╝  ╚═╝╚═╝  ╚═══╝ ╚══════╝ %s
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
	fmt.Println("NullFang " + VERSION + " — SMB share intelligence & file exfiltration")
	fmt.Println("")
	fmt.Println("─────────────────────────────")
	fmt.Println(" Common Usage")
	fmt.Println("─────────────────────────────")
	fmt.Println("  # Scan a network, search for credentials:")
	fmt.Println("  nullfang -n 192.168.1.0/24 -u admin -p password -m password,secret -e xlsx,docx")
	fmt.Println("")
	fmt.Println("  # Single host, pass-the-hash:")
	fmt.Println("  nullfang -H 192.168.1.10 -u admin -d CORP -ntlm-hash aad3b435b51404eeaad3b435b51404ee:... -m password")
	fmt.Println("")
	fmt.Println("  # Stealth recon (no copy, human pacing, atime restore):")
	fmt.Println("  nullfang -n 192.168.1.0/24 -u admin -p password --stealth --mode recon")
	fmt.Println("")
	fmt.Println("  # NTLM relay via ntlmrelayx --socks:")
	fmt.Println("  nullfang -H 192.168.1.10 -u admin -d CORP -socks5 127.0.0.1:1080 --mode recon")
	fmt.Println("")
	fmt.Println("  # Kerberos (auto-detect KRB5CCNAME):")
	fmt.Println("  nullfang -H dc01.corp.local -kerberos -m password")
	fmt.Println("")
	fmt.Println("  # Resume interrupted scan:")
	fmt.Println("  nullfang -resume checkpoints/nullfang_resume_*.json -p password")
	fmt.Println("")
	fmt.Println("  # Advanced settings via YAML (see config/nullfang.yaml):")
	fmt.Println("  nullfang -n 192.168.1.0/24 -u admin -p pass -config nullfang.yaml")
	fmt.Println("")
	fmt.Println("─────────────────────────────")
	fmt.Println(" Target")
	fmt.Println("─────────────────────────────")
	fmt.Println("  -H string        Single host (IP or hostname)")
	fmt.Println("  -n string        Network CIDR  (e.g. 192.168.1.0/24)")
	fmt.Println("  -l string        File with one host per line")
	fmt.Println("  -port int        SMB port  (default: 445)")
	fmt.Println("")
	fmt.Println("─────────────────────────────")
	fmt.Println(" Authentication")
	fmt.Println("─────────────────────────────")
	fmt.Println("  -u string        Username")
	fmt.Println("  -p string        Password")
	fmt.Println("  -d string        Domain  (omit for workgroup)")
	fmt.Println("  -ntlm-hash str   NT hash or LM:NT hash for pass-the-hash")
	fmt.Println("  -kerberos        Use Kerberos  (auto-reads KRB5CCNAME env var)")
	fmt.Println("  -ticket-file str ccache file path  (overrides KRB5CCNAME)")
	fmt.Println("  -local-auth      Authenticate as local account  (uses target hostname as domain)")
	fmt.Println("")
	fmt.Println("─────────────────────────────")
	fmt.Println(" Search")
	fmt.Println("─────────────────────────────")
	fmt.Println("  -m string        Match patterns  (comma-separated, e.g. password,secret,key)")
	fmt.Println("  -r string        Regex patterns  (comma-separated)")
	fmt.Println("  -e string        File extensions  (comma-separated, e.g. xlsx,docx,pdf,kdbx)")
	fmt.Println("  -share string    Specific shares to scan  (comma-separated)")
	fmt.Println("  -exclude-share   Shares to skip  (e.g. IPC$,ADMIN$,print$)")
	fmt.Println("")
	fmt.Println("─────────────────────────────")
	fmt.Println(" Scan Mode  (default: exfil)")
	fmt.Println("─────────────────────────────")
	fmt.Println("  -mode recon      Enumerate files and metadata only — no content read, no copy")
	fmt.Println("  -mode search     Search file contents — no copy  (low-noise default for engagements)")
	fmt.Println("  -mode exfil      Search + copy matching files  (default)")
	fmt.Println("")
	fmt.Println("─────────────────────────────")
	fmt.Println(" Stealth & Evasion")
	fmt.Println("─────────────────────────────")
	fmt.Println("  --stealth        Human-like pacing: jitter 500ms, single thread/conn,")
	fmt.Println("                   atime restore, randomized order, canary skip")
	fmt.Println("  -socks5 str      SOCKS5 proxy host:port for NTLM relay")
	fmt.Println("  -delta           Delta scan: skip files unchanged since last run")
	fmt.Println("  -check-admin     Check admin privileges  (may trigger EDR)")
	fmt.Println("")
	fmt.Println("  Advanced stealth tuning → config/nullfang.yaml  (settings.stealth section)")
	fmt.Println("")
	fmt.Println("─────────────────────────────")
	fmt.Println(" Output")
	fmt.Println("─────────────────────────────")
	fmt.Println("  -out string      Output directory  (default: NullFang_output)")
	fmt.Println("  -v               Verbose output")
	fmt.Println("  -output string   Output style: normal|verbose|json|quiet  (default: normal)")
	fmt.Println("")
	fmt.Println("─────────────────────────────")
	fmt.Println(" Config, Checkpoint & Web")
	fmt.Println("─────────────────────────────")
	fmt.Println("  -config string   YAML file with patterns + advanced settings")
	fmt.Println("                   Template: config/nullfang.yaml")
	fmt.Println("  -resume string   Resume from checkpoint file")
	fmt.Println("  -web             Start web UI  (analysis dashboard)")
	fmt.Println("  -web-port str    Web UI port  (default: 9090)")
	fmt.Println("  -db string       Custom database path for web UI")
	fmt.Println("")
	fmt.Println("─────────────────────────────")
	fmt.Println(" General")
	fmt.Println("─────────────────────────────")
	fmt.Println("  -help            Show this help")
	fmt.Println("  -version         Show version")
	fmt.Println("  -faq             FAQ and troubleshooting")
	fmt.Println("  -summary         Show historical scan summary for -d <domain> (standalone)")

	fmt.Println("")
	fmt.Println("─────────────────────────────")
	fmt.Println(" Performance & Tuning")
	fmt.Println("─────────────────────────────")
	fmt.Println("  -threads int             Host concurrency & workers  (default: 5)")
	fmt.Println("  -operation-delay int     Per-entry delay in ms between SMB ops  (default: 300)")
	fmt.Println("  -dir-concurrency int     Max concurrent directory opens  (default: 4)")
	fmt.Println("  -lockout-threshold       Halt scan after N auth failures to prevent AD lockout  (default: 1)")
	fmt.Println("")
	fmt.Println("  More advanced tuning → config/nullfang.yaml  (settings.performance section)")
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
