package main

import (
	"database/sql"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/m0ng3sh3ll/NullFang/utils"
)

var (
	nullfangDBFlag = flag.String("nullfang-db", "", "NullFang database path (default: OS standard location)")
	nfpathDBFlag   = flag.String("db", "", "nfpath intelligence database (default: derived from --nullfang-db name)")
	llmURLFlag      = flag.String("llm-url", "http://localhost:11434", "LLM base URL (Ollama default; change for external APIs)")
	llmModelFlag    = flag.String("llm-model", "qwen2.5:3b", "Model name (e.g. qwen2.5:3b, gpt-4o-mini, claude-haiku-4-5-20251001)")
	llmKeyFlag      = flag.String("llm-key", "", "API key (prefer NFPATH_LLM_KEY env var — CLI flag is visible in shell history)")
	llmProviderFlag = flag.String("llm-provider", "auto", "LLM provider: auto|ollama|openai|anthropic")
	pollFlag       = flag.Duration("poll", 30*time.Second, "Pipeline mode poll interval")
	reportOutFlag      = flag.String("report-out", "nfpath_report.html", "HTML report output path")
	maxContextItemsFlag = flag.Int("max-context-items", 30, "Max items per category injected into chat context (lower = fewer tokens)")
	verboseFlag         = flag.Bool("v", false, "Verbose output")
)

func main() {
	flag.Usage = usage
	flag.Parse()

	// Resolve nullfang DB path: explicit flag > OS standard location.
	if *nullfangDBFlag == "" {
		*nullfangDBFlag = utils.GetDefaultDBPath()
		queueStartupMsg("[nfpath] nullfang DB not specified — using default: %s", *nullfangDBFlag)
	}

	args := flag.Args()
	if len(args) == 0 {
		usage()
		os.Exit(1)
	}

	cmd := args[0]

	switch cmd {
	case "analyze":
		cmdAnalyze()
	case "pipeline":
		cmdPipeline()
	case "chat":
		cmdChat()
	case "report":
		cmdReport()
	case "decisions":
		cmdDecisions()
	case "status":
		cmdStatus()
	case "models":
		cmdModels()
	case "config":
		printConfigSources()
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", cmd)
		usage()
		os.Exit(1)
	}
}

func cmdAnalyze() {
	flushStartupMsgs()
	nfDB, err := openNullFangDB(*nullfangDBFlag)
	if err != nil {
		fatalf("open nullfang DB: %v", err)
	}
	defer nfDB.Close()

	nfpathDB := mustNfpathDB()
	defer nfpathDB.Close()

	llm := mustLLM()

	if err := runAnalyze(nfDB, nfpathDB, llm, *verboseFlag); err != nil {
		fatalf("analyze: %v", err)
	}
}

func cmdPipeline() {
	flushStartupMsgs()
	nfDB, err := openNullFangDB(*nullfangDBFlag)
	if err != nil {
		fatalf("open nullfang DB: %v", err)
	}
	defer nfDB.Close()

	nfpathDB := mustNfpathDB()
	defer nfpathDB.Close()

	llm := mustLLM()

	if err := runPipeline(nfDB, nfpathDB, llm, *pollFlag, *verboseFlag); err != nil {
		fatalf("pipeline: %v", err)
	}
}

func cmdChat() {
	nfpathDB := mustNfpathDBExplicit()
	defer nfpathDB.Close()

	llm := mustLLM()
	runChat(nfpathDB, llm, *maxContextItemsFlag)
}

func cmdReport() {
	flushStartupMsgs()
	nfpathDB := mustNfpathDBExplicit()
	defer nfpathDB.Close()

	if err := runReport(nfpathDB, *reportOutFlag); err != nil {
		fatalf("report: %v", err)
	}
}

func cmdDecisions() {
	flushStartupMsgs()
	nfpathDB := mustNfpathDBExplicit()
	defer nfpathDB.Close()
	printDecisions(nfpathDB)
}

func cmdStatus() {
	flushStartupMsgs()
	nfpathDB := mustNfpathDBExplicit()
	defer nfpathDB.Close()
	printStatus(nfpathDB)
}

func cmdModels() {
	llm := NewOllamaClient(*llmURLFlag, *llmModelFlag)
	models, err := llm.ListModels()
	if err != nil {
		fatalf("list models: %v", err)
	}
	if len(models) == 0 {
		fmt.Println("[nfpath] No models found. Pull one with: ollama pull qwen2.5:3b")
		return
	}
	fmt.Printf("[nfpath] Ollama models available at %s:\n\n", *llmURLFlag)
	recommended := map[string]string{
		"qwen2.5:3b":  "fast, 8K ctx — good default for most engagements",
		"qwen2.5:7b":  "better extraction quality, needs 8GB RAM",
		"phi3:mini":   "very fast, lower accuracy on complex files",
		"llama3.2:3b": "good balance, slightly slower than qwen",
		"mistral:7b":  "strong extraction, best for large files",
	}
	current := *llmModelFlag
	for _, m := range models {
		marker := "  "
		if m == current || strings.HasPrefix(m, current) {
			marker = "▶ "
		}
		note := recommended[m]
		if note == "" {
			// Check prefix match for versioned names
			for k, v := range recommended {
				if strings.HasPrefix(m, strings.Split(k, ":")[0]) {
					note = v
					break
				}
			}
		}
		if note != "" {
			fmt.Printf("%s%-30s  %s\n", marker, m, note)
		} else {
			fmt.Printf("%s%s\n", marker, m)
		}
	}
	fmt.Printf("\nCurrent: %s\nChange with: nfpath -llm-model <name> <command>\n", current)
	fmt.Println("\nContext limits by model size:")
	fmt.Println("  3B models  — ~8K tokens  (~5K chars context) — use --max-context-items 15")
	fmt.Println("  7B models  — ~8-32K tokens — use --max-context-items 30")
	fmt.Println("  13B+       — 32K+ tokens  — default --max-context-items 50 is fine")
}

// nfpathDBPath returns the effective path for the nfpath DB.
// If --db is set explicitly, use it.
// Otherwise derive from the nullfang DB stem: "bwgi_nfdb.db" → "bwgi_nfdb_nfpath.db".
// For commands that don't use a nullfang DB (chat, report, decisions, status),
// --db must be set explicitly when the user wants a specific engagement.
func nfpathDBPath(requireExplicit bool) string {
	if *nfpathDBFlag != "" {
		return *nfpathDBFlag
	}
	if requireExplicit {
		fatalf("specify --db <path> to select the nfpath intelligence database\n" +
			"       (or run 'analyze' first with --nullfang-db to create one)")
	}
	return deriveNfpathDBPath(*nullfangDBFlag)
}

func deriveNfpathDBPath(nullfangPath string) string {
	// strip directory, strip extension, append _nfpath.db
	base := nullfangPath
	if idx := strings.LastIndexAny(base, `/\`); idx >= 0 {
		base = base[idx+1:]
	}
	stem := strings.TrimSuffix(base, ".db")
	stem = strings.TrimSuffix(stem, ".sqlite")
	stem = strings.TrimSuffix(stem, ".sqlite3")
	return stem + "_nfpath.db"
}

func mustNfpathDB() *sql.DB {
	path := nfpathDBPath(false)
	db, err := initDB(path)
	if err != nil {
		fatalf("init nfpath DB %s: %v", path, err)
	}
	return db
}

// mustNfpathDBExplicit is used for commands that only read nfpath.db and don't
// have a nullfang-db context to derive from (chat, report, decisions, status).
// Requires --db or derives from --nullfang-db if it was explicitly set.
func mustNfpathDBExplicit() *sql.DB {
	path := nfpathDBPath(false)
	db, err := initDB(path)
	if err != nil {
		fatalf("init nfpath DB %s: %v", path, err)
	}
	queueStartupMsg("[nfpath] using DB: %s", path)
	return db
}

func mustLLM() LLMClient {
	url, model, key, provider := resolveLLMConfig()
	llm := NewLLMClient(url, model, key, provider)
	if err := llm.Ping(); err != nil {
		fatalf("LLM backend not reachable: %v", err)
	}
	return llm
}

func fatalf(format string, args ...any) {
	fmt.Fprintf(os.Stderr, "[nfpath] ERROR: "+format+"\n", args...)
	os.Exit(1)
}

func usage() {
	fmt.Fprintf(os.Stderr, `nfpath — SMB intelligence correlation engine

Usage:
  nfpath [flags] <command>

Commands:
  analyze    Process nullfang.db files via LLM (post-scan, one-shot)
  pipeline   Watch nullfang.db and process new files as they arrive
  chat       Interactive intelligence chat REPL
  report     Generate HTML report (with interactive graph)
  decisions  Show decision table for recon-only findings
  status     Show processing statistics
  models     List Ollama models available locally
  config     Show effective config and where each setting came from

Flags:
`)
	flag.PrintDefaults()
}
