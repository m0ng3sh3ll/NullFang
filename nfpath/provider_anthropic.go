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

// AnthropicClient uses the Anthropic Messages API.
// Endpoint: POST /v1/messages
// Auth: x-api-key + anthropic-version headers (no Bearer scheme)
// Format differs from OpenAI: system is a top-level field, not a message role.
type AnthropicClient struct {
	BaseURL string
	Model   string
	APIKey  string
	Timeout time.Duration
}

func (c *AnthropicClient) ModelName() string { return c.Model }

func (c *AnthropicClient) timeout() time.Duration {
	if c.Timeout == 0 {
		return 180 * time.Second
	}
	return c.Timeout
}

type anthropicRequest struct {
	Model     string          `json:"model"`
	MaxTokens int             `json:"max_tokens"`
	System    string          `json:"system"`
	Messages  []anthropicMsg  `json:"messages"`
	Stream    bool            `json:"stream"`
}

type anthropicMsg struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type anthropicResponse struct {
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
	Error *struct {
		Type    string `json:"type"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

const anthropicVersion = "2023-06-01"

func (c *AnthropicClient) post(body any) (*http.Response, error) {
	data, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest("POST", c.BaseURL+"/v1/messages", bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", c.APIKey)
	req.Header.Set("anthropic-version", anthropicVersion)

	client := &http.Client{Timeout: c.timeout()}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("anthropic request: %w", err)
	}
	if resp.StatusCode != 200 {
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		var errResp anthropicResponse
		if json.Unmarshal(b, &errResp) == nil && errResp.Error != nil {
			return nil, fmt.Errorf("anthropic HTTP %d (%s): %s",
				resp.StatusCode, errResp.Error.Type, errResp.Error.Message)
		}
		return nil, fmt.Errorf("anthropic HTTP %d: %s", resp.StatusCode, b)
	}
	return resp, nil
}

func (c *AnthropicClient) Complete(system, user string) (string, error) {
	payload := anthropicRequest{
		Model:     c.Model,
		MaxTokens: 2048,
		System:    system,
		Stream:    false,
		Messages:  []anthropicMsg{{Role: "user", Content: user}},
	}
	resp, err := c.post(payload)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var result anthropicResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return "", fmt.Errorf("anthropic decode: %w", err)
	}
	for _, block := range result.Content {
		if block.Type == "text" {
			return block.Text, nil
		}
	}
	return "", fmt.Errorf("anthropic: no text content in response")
}

func (c *AnthropicClient) Stream(system, user string, w io.Writer) error {
	payload := anthropicRequest{
		Model:     c.Model,
		MaxTokens: 2048,
		System:    system,
		Stream:    true,
		Messages:  []anthropicMsg{{Role: "user", Content: user}},
	}
	resp, err := c.post(payload)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Anthropic SSE events we care about:
	// event: content_block_delta
	// data: {"type":"content_block_delta","delta":{"type":"text_delta","text":"..."}}
	scanner := bufio.NewScanner(resp.Body)
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		raw := strings.TrimPrefix(line, "data: ")
		var event struct {
			Type  string `json:"type"`
			Delta struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"delta"`
		}
		if err := json.Unmarshal([]byte(raw), &event); err != nil {
			continue
		}
		if event.Type == "content_block_delta" && event.Delta.Type == "text_delta" {
			fmt.Fprint(w, event.Delta.Text)
		}
		if event.Type == "message_stop" {
			break
		}
	}
	fmt.Fprintln(w)
	return scanner.Err()
}

func (c *AnthropicClient) Ping() error {
	// Anthropic has no public /v1/models endpoint, so send a minimal request.
	// A 1-token completion is the only reliable way to validate key + model.
	payload := anthropicRequest{
		Model:     c.Model,
		MaxTokens: 1,
		System:    "ping",
		Stream:    false,
		Messages:  []anthropicMsg{{Role: "user", Content: "hi"}},
	}
	resp, err := c.post(payload)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}
