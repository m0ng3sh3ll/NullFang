package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

type OllamaClient struct {
	BaseURL string
	Model   string
	Timeout time.Duration
}

type ollamaRequest struct {
	Model    string         `json:"model"`
	Messages []ollamaMsg    `json:"messages"`
	Stream   bool           `json:"stream"`
	Format   string         `json:"format,omitempty"`
	Options  map[string]any `json:"options,omitempty"`
}

type ollamaMsg struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type ollamaChunk struct {
	Message ollamaMsg `json:"message"`
	Done    bool      `json:"done"`
}

func NewOllamaClient(url, model string) *OllamaClient {
	return &OllamaClient{
		BaseURL: strings.TrimRight(url, "/"),
		Model:   model,
		Timeout: 180 * time.Second,
	}
}

func (c *OllamaClient) ModelName() string { return c.Model }

// Complete sends a non-streaming request and returns the full response text.
// Used for structured JSON extraction (file analysis, decision inference).
func (c *OllamaClient) Complete(system, user string) (string, error) {
	payload := ollamaRequest{
		Model:  c.Model,
		Stream: false,
		Format: "json",
		Messages: []ollamaMsg{
			{Role: "system", Content: system},
			{Role: "user", Content: user},
		},
		Options: map[string]any{
			"temperature": 0.05,
			"num_predict": 2048,
		},
	}
	data, _ := json.Marshal(payload)

	client := &http.Client{Timeout: c.Timeout}
	resp, err := client.Post(c.BaseURL+"/api/chat", "application/json", bytes.NewReader(data))
	if err != nil {
		return "", fmt.Errorf("ollama request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("ollama HTTP %d: %s", resp.StatusCode, body)
	}

	var result ollamaChunk
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("ollama decode: %w", err)
	}
	return result.Message.Content, nil
}

// Stream sends a chat request and streams token-by-token to w. Used for the chat REPL.
func (c *OllamaClient) Stream(system, user string, w io.Writer) error {
	payload := ollamaRequest{
		Model:  c.Model,
		Stream: true,
		Messages: []ollamaMsg{
			{Role: "system", Content: system},
			{Role: "user", Content: user},
		},
		Options: map[string]any{
			"temperature": 0.3,
		},
	}
	data, _ := json.Marshal(payload)

	client := &http.Client{Timeout: c.Timeout}
	resp, err := client.Post(c.BaseURL+"/api/chat", "application/json", bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("ollama stream: %w", err)
	}
	defer resp.Body.Close()

	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		var chunk ollamaChunk
		if err := json.Unmarshal(scanner.Bytes(), &chunk); err != nil {
			continue
		}
		fmt.Fprint(w, chunk.Message.Content)
		if chunk.Done {
			break
		}
	}
	fmt.Fprintln(w)
	return scanner.Err()
}

// ListModels returns all models available in the local Ollama instance.
func (c *OllamaClient) ListModels() ([]string, error) {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(c.BaseURL + "/api/tags")
	if err != nil {
		return nil, fmt.Errorf("cannot reach Ollama at %s: %w", c.BaseURL, err)
	}
	defer resp.Body.Close()

	var tags struct {
		Models []struct {
			Name    string `json:"name"`
			Size    int64  `json:"size"`
			Details struct {
				ParameterSize string `json:"parameter_size"`
			} `json:"details"`
		} `json:"models"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tags); err != nil {
		return nil, fmt.Errorf("decode: %w", err)
	}
	names := make([]string, 0, len(tags.Models))
	for _, m := range tags.Models {
		names = append(names, m.Name)
	}
	return names, nil
}

// Ping checks that Ollama is reachable and the requested model is available.
func (c *OllamaClient) Ping() error {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(c.BaseURL + "/api/tags")
	if err != nil {
		return fmt.Errorf("cannot reach Ollama at %s: %w", c.BaseURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return fmt.Errorf("ollama returned HTTP %d", resp.StatusCode)
	}

	// Check model is available
	var tags struct {
		Models []struct {
			Name string `json:"name"`
		} `json:"models"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tags); err != nil {
		return nil // can't parse, still reachable
	}
	for _, m := range tags.Models {
		if strings.HasPrefix(m.Name, c.Model) {
			return nil
		}
	}
	return fmt.Errorf("model %q not found in Ollama — run: ollama pull %s", c.Model, c.Model)
}
