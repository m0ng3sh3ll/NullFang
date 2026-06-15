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

// OpenAIClient handles any OpenAI-compatible API:
// OpenAI, Groq, Together AI, Mistral API, DeepSeek, Perplexity,
// Azure OpenAI, LiteLLM proxy, Cursor proxy, Anyscale, etc.
// Endpoint: POST /v1/chat/completions
// Auth: Authorization: Bearer <key>
type OpenAIClient struct {
	BaseURL string
	Model   string
	APIKey  string
	Timeout time.Duration
}

func (c *OpenAIClient) ModelName() string { return c.Model }

func (c *OpenAIClient) timeout() time.Duration {
	if c.Timeout == 0 {
		return 180 * time.Second
	}
	return c.Timeout
}

type openAIRequest struct {
	Model          string         `json:"model"`
	Messages       []openAIMsg    `json:"messages"`
	Stream         bool           `json:"stream"`
	ResponseFormat *openAIFormat  `json:"response_format,omitempty"`
	Temperature    float64        `json:"temperature"`
	MaxTokens      int            `json:"max_tokens"`
}

type openAIMsg struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type openAIFormat struct {
	Type string `json:"type"` // "json_object" for structured extraction
}

type openAIResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
		Delta struct {
			Content string `json:"content"`
		} `json:"delta"`
		FinishReason string `json:"finish_reason"`
	} `json:"choices"`
	Error *struct {
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

func (c *OpenAIClient) post(path string, body any) (*http.Response, error) {
	data, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest("POST", c.BaseURL+path, bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.APIKey)

	client := &http.Client{Timeout: c.timeout()}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("openai request: %w", err)
	}
	if resp.StatusCode != 200 {
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		// Try to extract error message
		var errResp openAIResponse
		if json.Unmarshal(b, &errResp) == nil && errResp.Error != nil {
			return nil, fmt.Errorf("openai HTTP %d: %s", resp.StatusCode, errResp.Error.Message)
		}
		return nil, fmt.Errorf("openai HTTP %d: %s", resp.StatusCode, b)
	}
	return resp, nil
}

func (c *OpenAIClient) Complete(system, user string) (string, error) {
	payload := openAIRequest{
		Model:       c.Model,
		Stream:      false,
		Temperature: 0.05,
		MaxTokens:   2048,
		ResponseFormat: &openAIFormat{Type: "json_object"},
		Messages: []openAIMsg{
			{Role: "system", Content: system},
			{Role: "user", Content: user},
		},
	}

	resp, err := c.post("/v1/chat/completions", payload)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var result openAIResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("openai decode: %w", err)
	}
	if len(result.Choices) == 0 {
		return "", fmt.Errorf("openai: no choices in response")
	}
	return result.Choices[0].Message.Content, nil
}

func (c *OpenAIClient) Stream(system, user string, w io.Writer) error {
	payload := openAIRequest{
		Model:       c.Model,
		Stream:      true,
		Temperature: 0.3,
		MaxTokens:   2048,
		Messages: []openAIMsg{
			{Role: "system", Content: system},
			{Role: "user", Content: user},
		},
	}

	resp, err := c.post("/v1/chat/completions", payload)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// OpenAI SSE format: "data: {...}\n\n" lines, ends with "data: [DONE]"
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		payload := strings.TrimPrefix(line, "data: ")
		if payload == "[DONE]" {
			break
		}
		var chunk openAIResponse
		if err := json.Unmarshal([]byte(payload), &chunk); err != nil {
			continue
		}
		if len(chunk.Choices) > 0 {
			fmt.Fprint(w, chunk.Choices[0].Delta.Content)
		}
	}
	fmt.Fprintln(w)
	return scanner.Err()
}

func (c *OpenAIClient) Ping() error {
	// Try GET /v1/models — works on all OpenAI-compatible endpoints
	req, err := http.NewRequest("GET", c.BaseURL+"/v1/models", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	client := &http.Client{Timeout: 8 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("cannot reach %s: %w", c.BaseURL, err)
	}
	resp.Body.Close()
	if resp.StatusCode == 401 {
		return fmt.Errorf("invalid API key for %s (HTTP 401)", c.BaseURL)
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("endpoint %s returned HTTP %d", c.BaseURL, resp.StatusCode)
	}
	return nil
}
