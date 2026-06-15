package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

const systemPromptAnalyze = `You are a red team intelligence extraction engine for offensive security operations.
Analyze the provided file content found on an SMB share and extract intelligence.

Output ONLY a valid JSON object. No markdown, no explanation, no prose — ONLY JSON.

Schema:
{
  "credentials": [
    {
      "username": "extracted username, login, or user field — string or null",
      "password_clear": "extracted plaintext password, secret, or credential value — string or null",
      "hash": "NT hash, bcrypt, MD5, SHA, or any encoded credential string — string or null",
      "token": "API key, bearer token, JWT, connection string secret, or any non-password secret — string or null",
      "host_hint": "IP, hostname, or system name this credential targets — string or null",
      "service_type": "one of: MSSQL|MySQL|PostgreSQL|Oracle|SSH|RDP|LDAP|HTTP|HTTPS|FTP|SMTP|WinRM|SAP|ServiceNow|Workday|PeopleSoft|TOTVS|Senior|Sankhya|HR_System|ERP|CRM|VPN|Active_Directory|AWS|Azure|GCP|API|Generic|Unknown",
      "confidence": "high|medium|low",
      "context": "verbatim line or snippet from the file that contains the credential"
    }
  ],
  "hosts": [
    {
      "identifier": "IP, hostname, FQDN, or named system (e.g. 'SistemaRH', 'ERP_PROD', 'portal_ti')",
      "identifier_type": "ip|hostname|fqdn|service_name|connection_string",
      "inferred_service": "what likely runs there",
      "confidence": "high|medium|low"
    }
  ],
  "services": [
    {
      "name": "service or system name",
      "type": "database|webserver|erp|crm|hr_system|vpn|mail|ldap|file_share|monitoring|ticketing|api|backup|unknown",
      "endpoint": "URL, DSN, connection string, or named identifier",
      "port": 0
    }
  ],
  "attack_paths": [
    "1-sentence operator-facing attack path using this intel"
  ],
  "summary": "2-3 sentence operator summary of findings",
  "priority": "critical|high|medium|low",
  "priority_reason": "why this priority"
}

Rules:
- Empty arrays [] when nothing found — never omit a key
- ALWAYS decompose credentials: if a connection string contains user+password, extract BOTH into username and password_clear separately
- ALWAYS extract: User Id=X → username=X, Password=Y → password_clear=Y, even inside DSNs or config values
- confidence=high: plaintext credentials, explicit usernames and passwords found verbatim
- confidence=medium: implied, partial, encoded, or base64 credentials
- confidence=low: guessed or inferred from indirect context
- Named internal systems without URLs (e.g. 'sistema_rh', 'ERP_Producao') get host entries with identifier_type=service_name
- Include full connection strings in services[].endpoint even if they embed credentials
- port=0 when unknown
- Output ONLY valid JSON. Nothing else.`

const systemPromptDecision = `You are a red team intelligence analyst.

A file was found during an SMB scan but was NOT copied (recon-only mode).
Based ONLY on the provided metadata, assess its intelligence value.

Output ONLY valid JSON:
{
  "inferred_value": "what this file most likely contains",
  "priority": "critical|high|medium|low",
  "recommended_action": "specific tactical action for the operator",
  "reasoning": "1 sentence"
}

Rules:
- Prioritize based on: filename keywords (password, cred, config, backup, secret, key), path context, extension, and match reason
- recommended_action must be concrete: e.g. "Copy and run through nfpath analyze", "Mount share and read manually", "Download and check for connection strings"
- Output ONLY valid JSON. Nothing else.`

// FileIntelRaw mirrors the LLM JSON output for file analysis.
type FileIntelRaw struct {
	Credentials []struct {
		Username      string `json:"username"`
		PasswordClear string `json:"password_clear"`
		Hash          string `json:"hash"`
		Token         string `json:"token"`
		HostHint      string `json:"host_hint"`
		ServiceType   string `json:"service_type"`
		Confidence    string `json:"confidence"`
		Context       string `json:"context"`
	} `json:"credentials"`
	Hosts []struct {
		Identifier      string `json:"identifier"`
		IdentifierType  string `json:"identifier_type"`
		InferredService string `json:"inferred_service"`
		Confidence      string `json:"confidence"`
	} `json:"hosts"`
	Services []struct {
		Name     string `json:"name"`
		Type     string `json:"type"`
		Endpoint string `json:"endpoint"`
		Port     int    `json:"port"`
	} `json:"services"`
	AttackPaths    []string `json:"attack_paths"`
	Summary        string   `json:"summary"`
	Priority       string   `json:"priority"`
	PriorityReason string   `json:"priority_reason"`
}

// DecisionIntelRaw mirrors the LLM JSON output for recon-only decisions.
type DecisionIntelRaw struct {
	InferredValue     string `json:"inferred_value"`
	Priority          string `json:"priority"`
	RecommendedAction string `json:"recommended_action"`
	Reasoning         string `json:"reasoning"`
}

const maxContentBytes = 10000

// analyzeFile reads a local copy of an SMB file, sends it to the LLM, and
// stores extracted credentials, hosts, and services into nfpathDB.
func analyzeFile(nfpathDB *sql.DB, llm LLMClient, fileID int, localPath, remotePath, host, share string, verbose bool) error {
	content, err := os.ReadFile(localPath)
	if err != nil {
		return fmt.Errorf("read %s: %w", localPath, err)
	}

	text := string(content)
	if len(text) > maxContentBytes {
		text = text[:maxContentBytes] + "\n...[truncated]"
	}

	userPrompt := fmt.Sprintf(
		"File: %s\nHost: %s\nShare: %s\nRemote path: %s\n\nContent:\n%s",
		localPath, host, share, remotePath, text,
	)

	if verbose {
		fmt.Printf("  [LLM] analyzing file_id=%d %s\n", fileID, remotePath)
	}

	raw, err := llm.Complete(systemPromptAnalyze, userPrompt)
	if err != nil {
		return fmt.Errorf("LLM: %w", err)
	}

	raw = extractJSON(raw)

	var intel FileIntelRaw
	if err := json.Unmarshal([]byte(raw), &intel); err != nil {
		if verbose {
			fmt.Printf("  [WARN] JSON parse failed for file_id=%d: %v\n  raw: %s\n", fileID, err, truncate(raw, 200))
		}
		return fmt.Errorf("JSON parse: %w", err)
	}
	if verbose && len(intel.Credentials) == 0 {
		fmt.Printf("  [DBG] file_id=%d: no credentials extracted by LLM\n", fileID)
	}

	tx, err := nfpathDB.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	for _, cred := range intel.Credentials {
		hasField := cred.Username != "" || cred.PasswordClear != "" || cred.Hash != "" || cred.Token != ""
		// low-confidence: require at least one actual field — context-only low entries are almost always false positives.
		// medium/high: context-only is acceptable intel (LLM found something but couldn't cleanly decompose).
		if !hasField && (cred.Context == "" || cred.Confidence == "low") {
			continue
		}
		_, err = tx.Exec(`
			INSERT INTO intel_credentials (username, password_clear, hash, token, host_hint, service_type, confidence, context_note, source_file_id)
			VALUES (?,?,?,?,?,?,?,?,?)`,
			nullStr(cred.Username), nullStr(cred.PasswordClear), nullStr(cred.Hash),
			nullStr(cred.Token), nullStr(cred.HostHint), cred.ServiceType, cred.Confidence, cred.Context, fileID,
		)
		if err != nil {
			return fmt.Errorf("insert credential: %w", err)
		}
	}

	for _, h := range intel.Hosts {
		if h.Identifier == "" {
			continue
		}
		// Upsert: on duplicate (identifier, identifier_type) keep highest confidence
		// and append new inferred_type if not already present.
		_, err = tx.Exec(`
			INSERT INTO intel_hosts (identifier, identifier_type, inferred_type, confidence, discovery_note, source_file_id)
			VALUES (?,?,?,?,?,?)
			ON CONFLICT(identifier, identifier_type) DO UPDATE SET
				confidence   = CASE
					WHEN excluded.confidence='high'   THEN 'high'
					WHEN confidence='high'             THEN 'high'
					WHEN excluded.confidence='medium'  THEN 'medium'
					ELSE confidence END,
				inferred_type = CASE
					WHEN excluded.inferred_type IS NULL OR excluded.inferred_type='' THEN inferred_type
					WHEN inferred_type IS NULL OR inferred_type=''                   THEN excluded.inferred_type
					WHEN inferred_type LIKE '%'||excluded.inferred_type||'%'         THEN inferred_type
					ELSE inferred_type||','||excluded.inferred_type END,
				source_file_id = excluded.source_file_id`,
			h.Identifier, h.IdentifierType, h.InferredService, h.Confidence,
			fmt.Sprintf("found in %s on %s", remotePath, host), fileID,
		)
		if err != nil {
			return fmt.Errorf("insert host: %w", err)
		}
	}

	for _, svc := range intel.Services {
		if svc.Name == "" && svc.Endpoint == "" {
			continue
		}
		port := svc.Port
		if port == 0 {
			port = -1
		}
		_, err = tx.Exec(`
			INSERT INTO intel_services (service_name, service_type, endpoint, port, source_file_id)
			VALUES (?,?,?,?,?)`,
			nullStr(svc.Name), svc.Type, nullStr(svc.Endpoint), port, fileID,
		)
		if err != nil {
			return fmt.Errorf("insert service: %w", err)
		}
	}

	_, err = tx.Exec(`
		INSERT OR REPLACE INTO intel_sources (nullfang_file_id, processed_at, llm_model_used)
		VALUES (?,?,?)`,
		fileID, time.Now().Format(time.RFC3339), llm.ModelName(),
	)
	if err != nil {
		return err
	}

	return tx.Commit()
}

// inferDecision uses the LLM to assess a recon-only file (no local copy)
// and creates a decision table entry in nfpathDB.
func inferDecision(nfpathDB *sql.DB, llm LLMClient, lhfID, fileID int, filePath, host, share, matchPattern, matchType, fileType string, size int64, verbose bool) error {
	// Check not already processed
	var existing int
	err := nfpathDB.QueryRow(`SELECT COUNT(*) FROM intel_decisions WHERE nullfang_file_id=?`, fileID).Scan(&existing)
	if err == nil && existing > 0 {
		return nil
	}

	userPrompt := fmt.Sprintf(
		"Filename: %s\nFull path: %s\nShare: %s\nHost: %s\nFile type: %s\nFile size: %d bytes\nMatched keyword/pattern: %s\nMatch type: %s",
		baseName(filePath), filePath, share, host, fileType, size, matchPattern, matchType,
	)

	if verbose {
		fmt.Printf("  [LLM] decision inference for %s on %s\n", filePath, host)
	}

	raw, err := llm.Complete(systemPromptDecision, userPrompt)
	if err != nil {
		return fmt.Errorf("LLM decision: %w", err)
	}

	raw = extractJSON(raw)

	var dec DecisionIntelRaw
	if err := json.Unmarshal([]byte(raw), &dec); err != nil {
		if verbose {
			fmt.Printf("  [WARN] decision JSON parse failed: %v\n  raw: %s\n", err, truncate(raw, 200))
		}
		return fmt.Errorf("decision JSON: %w", err)
	}

	_, err = nfpathDB.Exec(`
		INSERT OR IGNORE INTO intel_decisions
		  (nullfang_file_id, file_path, host, share, match_reason, inferred_value, recommended_action, priority)
		VALUES (?,?,?,?,?,?,?,?)`,
		fileID, filePath, host, share,
		fmt.Sprintf("%s: %s", matchType, matchPattern),
		dec.InferredValue, dec.RecommendedAction, dec.Priority,
	)
	if err != nil {
		return fmt.Errorf("insert decision: %w", err)
	}

	// Mark lhf as processed too
	if lhfID > 0 {
		_, _ = nfpathDB.Exec(`
			INSERT OR IGNORE INTO intel_sources (lhf_id, processed_at, llm_model_used)
			VALUES (?,?,?)`,
			lhfID, time.Now().Format(time.RFC3339), llm.ModelName(),
		)
	}

	return nil
}

func extractJSON(s string) string {
	s = strings.TrimSpace(s)
	if idx := strings.Index(s, "```"); idx >= 0 {
		s = s[idx:]
		s = strings.TrimPrefix(s, "```json")
		s = strings.TrimPrefix(s, "```")
		if end := strings.LastIndex(s, "```"); end > 0 {
			s = s[:end]
		}
	}
	start := strings.Index(s, "{")
	end := strings.LastIndex(s, "}")
	if start >= 0 && end > start {
		return s[start : end+1]
	}
	return s
}

func nullStr(s string) any {
	s = strings.TrimSpace(s)
	if s == "" || strings.EqualFold(s, "null") {
		return nil
	}
	return s
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

func baseName(path string) string {
	path = strings.ReplaceAll(path, "\\", "/")
	parts := strings.Split(path, "/")
	return parts[len(parts)-1]
}
