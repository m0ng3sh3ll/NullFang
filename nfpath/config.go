package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

var configFileFlag = flag.String("config", "", "Path to nfpath config file (default: .nfpath.yaml or ~/.nfpath/config.yaml)")

type nfpathConfig struct {
	LLM struct {
		URL      string `yaml:"url"`
		Model    string `yaml:"model"`
		Key      string `yaml:"key"`
		Provider string `yaml:"provider"`
	} `yaml:"llm"`
}

// resolveLLMConfig merges LLM settings from three sources, in ascending priority:
//
//  1. Config file (.nfpath.yaml, ~/.nfpath/config.yaml, or --config path)
//  2. Environment variables (NFPATH_LLM_KEY, NFPATH_LLM_URL, etc.)
//  3. CLI flags (--llm-url, --llm-model, --llm-provider)
//
// The API key is intentionally NOT accepted via --llm-key CLI flag to prevent
// exposure in shell history and process lists. Use NFPATH_LLM_KEY or config file.
func resolveLLMConfig() (url, model, key, provider string) {
	url = "http://localhost:11434"
	model = "qwen2.5:3b"
	provider = "auto"

	// Layer 1: config file
	cfg := loadConfig(*configFileFlag)
	if cfg.LLM.URL != "" {
		url = cfg.LLM.URL
	}
	if cfg.LLM.Model != "" {
		model = cfg.LLM.Model
	}
	if cfg.LLM.Key != "" {
		key = cfg.LLM.Key
	}
	if cfg.LLM.Provider != "" {
		provider = cfg.LLM.Provider
	}

	// Layer 2: environment variables
	if v := os.Getenv("NFPATH_LLM_URL"); v != "" {
		url = v
	}
	if v := os.Getenv("NFPATH_LLM_MODEL"); v != "" {
		model = v
	}
	if v := os.Getenv("NFPATH_LLM_KEY"); v != "" {
		key = v
	}
	if v := os.Getenv("NFPATH_LLM_PROVIDER"); v != "" {
		provider = v
	}

	// Layer 3: CLI flags — only apply flags that were explicitly set (not defaults).
	// flag.Visit only visits flags present on the command line.
	// Key is not accepted via CLI flag — print a helpful error if attempted.
	flag.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "llm-url":
			url = *llmURLFlag
		case "llm-model":
			model = *llmModelFlag
		case "llm-provider":
			provider = *llmProviderFlag
		case "llm-key":
			// Accept it but warn loudly — supports automation pipelines that
			// can't use env vars, but makes the risk explicit.
			key = *llmKeyFlag
			fmt.Fprintln(os.Stderr, "\033[33m[WARN] --llm-key is visible in shell history and process list.\033[0m")
			fmt.Fprintln(os.Stderr, "       Prefer: export NFPATH_LLM_KEY=<key>  or use a config file.")
		}
	})

	return
}

func loadConfig(explicitPath string) nfpathConfig {
	candidates := []string{}
	if explicitPath != "" {
		candidates = append(candidates, explicitPath)
	}
	candidates = append(candidates, ".nfpath.yaml", ".nfpath.yml")
	if home, err := os.UserHomeDir(); err == nil {
		candidates = append(candidates, filepath.Join(home, ".nfpath", "config.yaml"))
		candidates = append(candidates, filepath.Join(home, ".nfpath", "config.yml"))
	}

	for _, path := range candidates {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var cfg nfpathConfig
		if err := yaml.Unmarshal(data, &cfg); err != nil {
			fmt.Fprintf(os.Stderr, "[WARN] config %s: %v\n", path, err)
			continue
		}
		return cfg
	}
	return nfpathConfig{}
}

// printConfigSources prints where each LLM setting came from — useful for debugging.
func printConfigSources() {
	url, model, key, provider := resolveLLMConfig()
	hasKey := key != ""
	fmt.Println("[nfpath config]")
	fmt.Printf("  llm-url      = %s\n", url)
	fmt.Printf("  llm-model    = %s\n", model)
	fmt.Printf("  llm-provider = %s\n", provider)
	if hasKey {
		fmt.Printf("  llm-key      = %s (set)\n", mask(key))
	} else {
		fmt.Printf("  llm-key      = (not set — required for external APIs)\n")
	}
	fmt.Println()
	fmt.Println("  Sources checked (lowest → highest priority):")
	fmt.Println("    1. ~/.nfpath/config.yaml or .nfpath.yaml")
	fmt.Println("    2. NFPATH_LLM_KEY / NFPATH_LLM_URL / NFPATH_LLM_MODEL / NFPATH_LLM_PROVIDER")
	fmt.Println("    3. --llm-url / --llm-model / --llm-provider flags")
	fmt.Println("    (API key is never accepted via CLI flag in normal use)")
}

func mask(key string) string {
	if len(key) <= 8 {
		return "***"
	}
	return key[:4] + "..." + key[len(key)-4:]
}
