package main

import (
	"io"
	"strings"
)

// LLMClient is the common interface for all LLM backends.
type LLMClient interface {
	// Complete sends a non-streaming request, returns the full response text.
	// For extraction tasks the response should be valid JSON.
	Complete(system, user string) (string, error)
	// Stream sends a request and writes tokens to w as they arrive.
	// Used for the interactive chat REPL.
	Stream(system, user string, w io.Writer) error
	// Ping verifies the backend is reachable and the model exists.
	Ping() error
	// ModelName returns the configured model identifier.
	ModelName() string
}

// NewLLMClient creates the right backend based on URL, key, and optional provider hint.
//
// Auto-detection logic (applied when provider == "" or "auto"):
//   - URL contains "anthropic.com"              → Anthropic Messages API
//   - key is set (and URL is not Ollama default) → OpenAI-compatible
//   - key is set and URL is still default        → OpenAI (url reset to api.openai.com)
//   - no key                                     → Ollama (local)
//
// Explicit provider values: ollama | openai | anthropic
func NewLLMClient(url, model, key, provider string) LLMClient {
	p := resolveProvider(url, key, provider)
	switch p {
	case "anthropic":
		if isOllamaDefault(url) {
			url = "https://api.anthropic.com"
		}
		return &AnthropicClient{BaseURL: strings.TrimRight(url, "/"), Model: model, APIKey: key}
	case "openai":
		if isOllamaDefault(url) {
			url = "https://api.openai.com"
		}
		return &OpenAIClient{BaseURL: strings.TrimRight(url, "/"), Model: model, APIKey: key}
	default:
		return NewOllamaClient(url, model)
	}
}

func resolveProvider(url, key, hint string) string {
	if hint != "" && hint != "auto" {
		return hint
	}
	if strings.Contains(url, "anthropic.com") {
		return "anthropic"
	}
	if key != "" {
		return "openai"
	}
	return "ollama"
}

func isOllamaDefault(url string) bool {
	return strings.HasPrefix(url, "http://localhost:11434") ||
		strings.HasPrefix(url, "http://127.0.0.1:11434")
}
