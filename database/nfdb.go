package database

import (
	"database/sql"
	"fmt"
	"regexp"
	"time"

	_ "modernc.org/sqlite"
)

// Estrutura para regra de classificação
type ClassificationRule struct {
	ID               int
	Name             string
	Description      string
	MatchPattern     string
	MatchType        string
	ClassificationID int
	Priority         int
	Enabled          bool
	CreatedAt        string
	UpdatedAt        string
}

func InitDB(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		fmt.Printf("[DB-ERROR] Failed to open database: %v\n", err)
		return nil, err
	}
	_, err = db.Exec(`
	CREATE TABLE IF NOT EXISTS files (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		path TEXT,
		host TEXT,
		share TEXT,
		domain TEXT,
		user TEXT,
		size INTEGER,
		mod_time DATETIME,
		file_type TEXT,
		match_pattern TEXT,
		match_type TEXT,
		hash TEXT,
		local_path TEXT,
		found_time DATETIME,
		large_file BOOLEAN,
		size_formatted TEXT,
		leet_speak BOOLEAN,
		search_param_type TEXT,
		search_param_value TEXT,
		parent_id INTEGER
	);
	`)
	if err != nil {
		fmt.Printf("[DB-ERROR] Failed to create table: %v\n", err)
		return nil, err
	}
	_, err = db.Exec(`
	CREATE TABLE IF NOT EXISTS low_hanging_fruit (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		path TEXT,
		host TEXT,
		share TEXT,
		domain TEXT,
		user TEXT,
		size INTEGER,
		mod_time DATETIME,
		file_type TEXT,
		match_pattern TEXT,
		match_type TEXT,
		found_time DATETIME,
		large_file BOOLEAN,
		size_formatted TEXT,
		scan_mode TEXT,
		UNIQUE(path, host, share, domain, user, scan_mode, match_pattern, match_type)
	);
	`)
	if err != nil {
		fmt.Printf("[DB-ERROR] Failed to create low_hanging_fruit table: %v\n", err)
		return nil, err
	}
	_, err = db.Exec(`
	CREATE TABLE IF NOT EXISTS domain_credentials (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		domain TEXT,
		user TEXT,
		auth_method TEXT,
		password_clear TEXT,
		password_hash TEXT,
		password_ticket TEXT,
		found_time DATETIME,
		host TEXT,
		isAdmin BOOLEAN,
		UNIQUE(domain, user, host, auth_method)
	);
	`)
	if err != nil {
		fmt.Printf("[DB-ERROR] Failed to create domain_credentials table: %v\n", err)
		return nil, err
	}

	// Criar tabela de classificações
	_, err = db.Exec(`
	CREATE TABLE IF NOT EXISTS classifications (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL UNIQUE,
		description TEXT,
		level INTEGER NOT NULL,
		color TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)
	`)
	if err != nil {
		return nil, fmt.Errorf("error creating classifications table: %v", err)
	}

	// Criar tabela de regras de classificação
	_, err = db.Exec(`
	CREATE TABLE IF NOT EXISTS classification_rules (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		description TEXT,
		match_pattern TEXT NOT NULL,
		match_type TEXT NOT NULL CHECK(match_type IN ('exact', 'regex')),
		classification_id INTEGER NOT NULL,
		priority INTEGER NOT NULL DEFAULT 0,
		enabled BOOLEAN NOT NULL DEFAULT 1,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (classification_id) REFERENCES classifications(id),
		UNIQUE(name, match_pattern, match_type, classification_id)
	)
	`)
	if err != nil {
		return nil, fmt.Errorf("error creating classification rules table: %v", err)
	}

	// Criar tabela de classificação de documentos
	_, err = db.Exec(`
	CREATE TABLE IF NOT EXISTS document_classifications (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		file_id INTEGER NOT NULL,
		classification_id INTEGER NOT NULL,
		notes TEXT,
		classified_by TEXT NOT NULL,
		classified_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (file_id) REFERENCES files(id),
		FOREIGN KEY (classification_id) REFERENCES classifications(id),
		UNIQUE(file_id)
	)
	`)
	if err != nil {
		return nil, fmt.Errorf("error creating document classifications table: %v", err)
	}

	// Tabela de correlação de hosts
	_, err = db.Exec(`
	CREATE TABLE IF NOT EXISTS infrastructure_hosts (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		host TEXT NOT NULL,
		domain TEXT,
		is_domain_controller BOOLEAN DEFAULT 0,
		is_server BOOLEAN DEFAULT 0,
		is_workstation BOOLEAN DEFAULT 0,
		last_seen DATETIME,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		UNIQUE(host, domain)
	)
	`)
	if err != nil {
		return nil, fmt.Errorf("error creating infrastructure_hosts table: %v", err)
	}

	// Tabela de correlação de usuários
	_, err = db.Exec(`
	CREATE TABLE IF NOT EXISTS infrastructure_users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT NOT NULL,
		domain TEXT,
		is_admin BOOLEAN DEFAULT 0,
		last_seen DATETIME,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		UNIQUE(username, domain)
	)
	`)
	if err != nil {
		return nil, fmt.Errorf("error creating infrastructure_users table: %v", err)
	}

	// Tabela de correlação de shares
	_, err = db.Exec(`
	CREATE TABLE IF NOT EXISTS infrastructure_shares (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		host_id INTEGER,
		path TEXT,
		is_accessible BOOLEAN DEFAULT 1,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (host_id) REFERENCES infrastructure_hosts(id),
		UNIQUE(name, host_id)
	)
	`)
	if err != nil {
		return nil, fmt.Errorf("error creating infrastructure_shares table: %v", err)
	}

	// Tabela de correlação de acessos
	_, err = db.Exec(`
	CREATE TABLE IF NOT EXISTS infrastructure_access (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER,
		target_id INTEGER,
		target_type TEXT CHECK(target_type IN ('host', 'share')),
		access_type TEXT CHECK(access_type IN ('read', 'write', 'admin')),
		first_seen DATETIME,
		last_seen DATETIME,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		FOREIGN KEY (user_id) REFERENCES infrastructure_users(id),
		UNIQUE(user_id, target_id, target_type)
	)
	`)
	if err != nil {
		return nil, fmt.Errorf("error creating infrastructure_access table: %v", err)
	}

	// Criar índices para melhorar performance
	_, err = db.Exec(`
	CREATE INDEX IF NOT EXISTS idx_classification_rules_priority 
	ON classification_rules(priority DESC);
	CREATE INDEX IF NOT EXISTS idx_document_classifications_file_id 
	ON document_classifications(file_id);
	CREATE INDEX IF NOT EXISTS idx_document_classifications_classification_id 
	ON document_classifications(classification_id);
	CREATE INDEX IF NOT EXISTS idx_infrastructure_hosts_domain 
	ON infrastructure_hosts(domain);
	CREATE INDEX IF NOT EXISTS idx_infrastructure_users_domain 
	ON infrastructure_users(domain);
	CREATE INDEX IF NOT EXISTS idx_infrastructure_shares_host 
	ON infrastructure_shares(host_id);
	CREATE INDEX IF NOT EXISTS idx_infrastructure_access_user 
	ON infrastructure_access(user_id);
	CREATE INDEX IF NOT EXISTS idx_infrastructure_access_target 
	ON infrastructure_access(target_id, target_type)
	`)
	if err != nil {
		return nil, fmt.Errorf("error creating infrastructure indexes: %v", err)
	}

	// Inserir classificações padrão se não existirem
	_, err = db.Exec(`
	INSERT OR IGNORE INTO classifications (name, description, level, color)
	VALUES 
		('Public', 'Public information, no restrictions', 1, '#28a745'),
		('Internal', 'Internal information, for internal use', 2, '#17a2b8'),
		('Confidential', 'Confidential information', 3, '#ffc107'),
		('Restricted', 'Highly restricted information', 4, '#fd7e14'),
		('Critical', 'Critical information for the organization', 5, '#dc3545')
	`)
	if err != nil {
		return nil, fmt.Errorf("error inserting default classifications: %v", err)
	}

	// Inserir algumas regras padrão
	_, err = db.Exec(`
	INSERT OR IGNORE INTO classification_rules (name, description, match_pattern, match_type, classification_id, priority, enabled)
	VALUES 
		('Passwords', 'Files containing passwords', 'password|senha|passwd|pass', 'regex', 3, 100, 1),
		('Credentials', 'Files containing credentials', 'credential|credencial|login', 'regex', 3, 90, 1),
		('Financial Documents', 'Sensitive financial documents', 'financeiro|financial|invoice|fatura', 'regex', 4, 80, 1),
		('Legal Documents', 'Confidential legal documents', 'legal|contrato|contract|termo', 'regex', 3, 70, 1),
		('Public Documents', 'Public documents', 'public|publico|noticia|news', 'regex', 1, 10, 1);
	`)
	if err != nil {
		return nil, fmt.Errorf("erro ao inserir regras padrão: %v", err)
	}

	// Run migration for existing databases
	err = MigrateAddSearchParamsToUnique(db)
	if err != nil {
		return nil, fmt.Errorf("migration failed: %v", err)
	}

	return db, nil
}

func InsertFile(
	db *sql.DB,
	path, host, share, domain, user string,
	size int64,
	modTime time.Time,
	fileType, matchPattern, matchType, hash, localPath, sizeFormatted string,
	largeFile bool,
	leetSpeak bool,
	searchParamType, searchParamValue string,
	parentID *int,
) error {
	stmt, err := db.Prepare(`
	INSERT INTO files(
		path, host, share, domain, user, size, mod_time, file_type, match_pattern, match_type, hash, local_path, found_time, large_file, size_formatted, leet_speak, search_param_type, search_param_value, parent_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		fmt.Printf("[DB-ERROR] Prepare failed: %v\n", err)
		return err
	}
	defer stmt.Close()
	_, err = stmt.Exec(path, host, share, domain, user, size, modTime, fileType, matchPattern, matchType, hash, localPath, time.Now(), largeFile, sizeFormatted, leetSpeak, searchParamType, searchParamValue, parentID)
	if err != nil {
		fmt.Printf("[DB-ERROR] Exec failed: %v\n", err)
		return err
	}
	return nil
}

func InsertLowHangingFruit(db *sql.DB, path, host, share, domain, user string, size int64, modTime time.Time, fileType, matchPattern, matchType, sizeFormatted, scanMode string, largeFile bool) (bool, error) {
	var exists int
	err := db.QueryRow("SELECT COUNT(1) FROM low_hanging_fruit WHERE path=? AND host=? AND share=? AND domain=? AND user=? AND scan_mode=? AND match_pattern=? AND match_type=?", path, host, share, domain, user, scanMode, matchPattern, matchType).Scan(&exists)
	if err == nil && exists > 0 {
		return false, nil // Already exists with same search parameters
	}
	stmt, err := db.Prepare(`INSERT INTO low_hanging_fruit(path, host, share, domain, user, size, mod_time, file_type, match_pattern, match_type, found_time, large_file, size_formatted, scan_mode) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return false, err
	}
	defer stmt.Close()
	_, err = stmt.Exec(path, host, share, domain, user, size, modTime, fileType, matchPattern, matchType, time.Now(), largeFile, sizeFormatted, scanMode)
	if err != nil {
		return false, err
	}
	return true, nil // Inserted new
}

// Função para inserir arquivo e retornar o id
func InsertFileReturnID(
	db *sql.DB,
	path, host, share, domain, user string,
	size int64,
	modTime time.Time,
	fileType, matchPattern, matchType, hash, localPath, sizeFormatted string,
	largeFile bool,
	leetSpeak bool,
	searchParamType, searchParamValue string,
	parentID *int,
) (int, error) {
	stmt, err := db.Prepare(`
	INSERT INTO files(
		path, host, share, domain, user, size, mod_time, file_type, match_pattern, match_type, hash, local_path, found_time, large_file, size_formatted, leet_speak, search_param_type, search_param_value, parent_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`)
	if err != nil {
		return 0, err
	}
	defer stmt.Close()
	res, err := stmt.Exec(path, host, share, domain, user, size, modTime, fileType, matchPattern, matchType, hash, localPath, time.Now(), largeFile, sizeFormatted, leetSpeak, searchParamType, searchParamValue, parentID)
	if err != nil {
		return 0, err
	}
	lastID, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	return int(lastID), nil
}

// Função para atualizar o parent_id de um arquivo
func UpdateFileParentID(db *sql.DB, id int, parentID int) error {
	_, err := db.Exec("UPDATE files SET parent_id=? WHERE id=?", parentID, id)
	return err
}

func InsertDomainCredentials(db *sql.DB, domain, user, host, authMethod, passwordClear, passwordHash, passwordTicket, foundTime string, isAdmin bool) error {
	_, err := db.Exec("INSERT INTO domain_credentials(domain, user, host, auth_method, password_clear, password_hash, password_ticket, found_time, isAdmin) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) ON CONFLICT(domain, user, host, auth_method) DO UPDATE SET password_clear=excluded.password_clear, password_hash=excluded.password_hash, password_ticket=excluded.password_ticket, isAdmin=excluded.isAdmin", domain, user, host, authMethod, passwordClear, passwordHash, passwordTicket, foundTime, isAdmin)
	return err
}

// Funções para gerenciar classificações
func GetClassifications(db *sql.DB) ([]map[string]interface{}, error) {
	rows, err := db.Query(`
		SELECT id, name, description, level, color, created_at, updated_at
		FROM classifications
		ORDER BY level
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var classifications []map[string]interface{}
	for rows.Next() {
		var c map[string]interface{}
		if err := rows.Scan(&c); err != nil {
			return nil, err
		}
		classifications = append(classifications, c)
	}
	return classifications, nil
}

func AddClassification(db *sql.DB, name, description string, level int, color string) error {
	_, err := db.Exec(`
		INSERT INTO classifications (name, description, level, color, created_at, updated_at)
		VALUES (?, ?, ?, ?, datetime('now'), datetime('now'))
	`, name, description, level, color)
	return err
}

func UpdateClassification(db *sql.DB, id int, name, description string, level int, color string) error {
	_, err := db.Exec(`
		UPDATE classifications
		SET name = ?, description = ?, level = ?, color = ?, updated_at = datetime('now')
		WHERE id = ?
	`, name, description, level, color, id)
	return err
}

func DeleteClassification(db *sql.DB, id int) error {
	_, err := db.Exec("DELETE FROM classifications WHERE id = ?", id)
	return err
}

// Funções para gerenciar classificação de documentos
func ClassifyDocument(db *sql.DB, fileID, classificationID int, notes, classifiedBy string) error {
	_, err := db.Exec(`
		INSERT INTO document_classifications (file_id, classification_id, notes, classified_by, classified_at)
		VALUES (?, ?, ?, ?, datetime('now'))
	`, fileID, classificationID, notes, classifiedBy)
	return err
}

func GetDocumentClassification(db *sql.DB, fileID int) (map[string]interface{}, error) {
	var classification map[string]interface{}
	err := db.QueryRow(`
		SELECT c.id, c.name, c.description, c.level, c.color, dc.notes, dc.classified_by, dc.classified_at
		FROM document_classifications dc
		JOIN classifications c ON c.id = dc.classification_id
		WHERE dc.file_id = ?
		ORDER BY dc.classified_at DESC
		LIMIT 1
	`, fileID).Scan(&classification)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	return classification, err
}

func GetClassificationStats(db *sql.DB) (map[string]interface{}, error) {
	rows, err := db.Query(`
		SELECT c.name, COUNT(dc.id) as count
		FROM classifications c
		LEFT JOIN document_classifications dc ON c.id = dc.classification_id
		GROUP BY c.id
		ORDER BY c.level
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	stats := make(map[string]interface{})
	for rows.Next() {
		var name string
		var count int
		if err := rows.Scan(&name, &count); err != nil {
			return nil, err
		}
		stats[name] = count
	}
	return stats, nil
}

// Adicionar regra de classificação
func AddClassificationRule(db *sql.DB, name, description, matchPattern, matchType string, classificationID, priority int) error {
	_, err := db.Exec(`
		INSERT INTO classification_rules (name, description, match_pattern, match_type, classification_id, priority, enabled)
		VALUES (?, ?, ?, ?, ?, ?, 1)
	`, name, description, matchPattern, matchType, classificationID, priority)
	return err
}

// Atualizar regra de classificação
func UpdateClassificationRule(db *sql.DB, id int, name, description, matchPattern, matchType string, classificationID, priority int, enabled bool) error {
	_, err := db.Exec(`
		UPDATE classification_rules
		SET name = ?, description = ?, match_pattern = ?, match_type = ?, 
			classification_id = ?, priority = ?, enabled = ?, updated_at = datetime('now')
		WHERE id = ?
	`, name, description, matchPattern, matchType, classificationID, priority, enabled, id)
	return err
}

// Excluir regra de classificação
func DeleteClassificationRule(db *sql.DB, id int) error {
	_, err := db.Exec("DELETE FROM classification_rules WHERE id = ?", id)
	return err
}

// Listar regras de classificação
func GetClassificationRules(db *sql.DB) ([]ClassificationRule, error) {
	rows, err := db.Query(`
		SELECT id, name, description, match_pattern, match_type, classification_id, 
			   priority, enabled, created_at, updated_at
		FROM classification_rules
		ORDER BY priority DESC, name
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var rules []ClassificationRule
	for rows.Next() {
		var rule ClassificationRule
		err := rows.Scan(
			&rule.ID, &rule.Name, &rule.Description, &rule.MatchPattern,
			&rule.MatchType, &rule.ClassificationID, &rule.Priority,
			&rule.Enabled, &rule.CreatedAt, &rule.UpdatedAt,
		)
		if err != nil {
			return nil, err
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

// Classificar documento automaticamente
func AutoClassifyDocument(db *sql.DB, fileID int, matchPattern, matchType string) error {
	// Buscar regras ativas ordenadas por prioridade
	rows, err := db.Query(`
		SELECT cr.classification_id, cr.match_pattern, cr.match_type
		FROM classification_rules cr
		WHERE cr.enabled = 1
		ORDER BY cr.priority DESC
	`)
	if err != nil {
		return err
	}
	defer rows.Close()

	// Verificar cada regra
	for rows.Next() {
		var classificationID int
		var rulePattern, ruleType string
		err := rows.Scan(&classificationID, &rulePattern, &ruleType)
		if err != nil {
			return err
		}

		// Se o tipo de match for regex, usar expressão regular
		if ruleType == "regex" {
			matched, err := regexp.MatchString(rulePattern, matchPattern)
			if err != nil {
				continue // Ignorar erros de regex inválida
			}
			if matched {
				// Classificar documento com a primeira regra que corresponder
				return ClassifyDocument(db, fileID, classificationID, "Automatic classification", "system")
			}
		} else if ruleType == "exact" && rulePattern == matchPattern {
			// Match exato
			return ClassifyDocument(db, fileID, classificationID, "Automatic classification", "system")
		}
	}

	return nil
}

// Classificar documentos não classificados
func AutoClassifyUnclassifiedDocuments(db *sql.DB) error {
	// Buscar documentos não classificados
	rows, err := db.Query(`
		SELECT f.id, f.match_pattern, f.match_type
		FROM files f
		LEFT JOIN document_classifications dc ON f.id = dc.file_id
		WHERE dc.file_id IS NULL
	`)
	if err != nil {
		return err
	}
	defer rows.Close()

	// Iniciar transação
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Processar cada documento
	for rows.Next() {
		var fileID int
		var matchPattern, matchType string
		err := rows.Scan(&fileID, &matchPattern, &matchType)
		if err != nil {
			return err
		}

		// Tentar classificar automaticamente
		err = AutoClassifyDocument(db, fileID, matchPattern, matchType)
		if err != nil {
			return err
		}
	}

	// Commit da transação
	return tx.Commit()
}

// Funções para popular as tabelas de infraestrutura com dados existentes
func PopulateInfrastructureTables(db *sql.DB) error {
	// Limpar tabelas de infraestrutura antes de popular
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()

	_, err = tx.Exec(`DELETE FROM infrastructure_access`)
	if err != nil {
		return err
	}
	_, err = tx.Exec(`DELETE FROM infrastructure_shares`)
	if err != nil {
		return err
	}
	_, err = tx.Exec(`DELETE FROM infrastructure_users`)
	if err != nil {
		return err
	}
	_, err = tx.Exec(`DELETE FROM infrastructure_hosts`)
	if err != nil {
		return err
	}

	// Popular hosts
	_, err = tx.Exec(`
	INSERT OR IGNORE INTO infrastructure_hosts (host, domain, last_seen)
	SELECT DISTINCT host, domain, MAX(found_time)
	FROM files
	WHERE host IS NOT NULL AND host != ''
	GROUP BY host, domain
	`)
	if err != nil {
		return err
	}

	// Popular usuários
	_, err = tx.Exec(`
	INSERT OR IGNORE INTO infrastructure_users (username, domain, is_admin, last_seen)
	SELECT DISTINCT user, domain, COALESCE(isAdmin, 0), MAX(found_time)
	FROM domain_credentials
	WHERE user IS NOT NULL AND user != ''
	GROUP BY user, domain
	`)
	if err != nil {
		return err
	}

	// Popular shares
	_, err = tx.Exec(`
	INSERT OR IGNORE INTO infrastructure_shares (name, host_id, path)
	SELECT DISTINCT s.share, h.id, s.path
	FROM files s
	JOIN infrastructure_hosts h ON s.host = h.host AND s.domain = h.domain
	WHERE s.share IS NOT NULL AND s.share != ''
	`)
	if err != nil {
		return err
	}

	// Popular acessos a hosts
	_, err = tx.Exec(`
	INSERT OR IGNORE INTO infrastructure_access (user_id, target_id, target_type, access_type, first_seen, last_seen)
	SELECT 
		u.id,
		h.id,
		'host',
		CASE WHEN COALESCE(dc.isAdmin, 0) = 1 THEN 'admin' ELSE 'read' END,
		MIN(f.found_time),
		MAX(f.found_time)
	FROM files f
	JOIN infrastructure_users u ON f.user = u.username AND (COALESCE(f.domain, '') = COALESCE(u.domain, ''))
	JOIN infrastructure_hosts h ON f.host = h.host AND (COALESCE(f.domain, '') = COALESCE(h.domain, ''))
	LEFT JOIN domain_credentials dc ON f.user = dc.user AND (COALESCE(f.domain, '') = COALESCE(dc.domain, ''))
	WHERE f.user IS NOT NULL AND f.host IS NOT NULL AND f.user != '' AND f.host != ''
	GROUP BY u.id, h.id
	`)
	if err != nil {
		return err
	}

	// Popular acessos a shares
	_, err = tx.Exec(`
	INSERT OR IGNORE INTO infrastructure_access (user_id, target_id, target_type, access_type, first_seen, last_seen)
	SELECT 
		u.id,
		s.id,
		'share',
		CASE WHEN COALESCE(dc.isAdmin, 0) = 1 THEN 'admin' ELSE 'read' END,
		MIN(f.found_time),
		MAX(f.found_time)
	FROM files f
	JOIN infrastructure_users u ON f.user = u.username AND (COALESCE(f.domain, '') = COALESCE(u.domain, ''))
	JOIN infrastructure_hosts h ON f.host = h.host AND (COALESCE(f.domain, '') = COALESCE(h.domain, ''))
	JOIN infrastructure_shares s ON f.share = s.name AND s.host_id = h.id
	LEFT JOIN domain_credentials dc ON f.user = dc.user AND (COALESCE(f.domain, '') = COALESCE(dc.domain, ''))
	WHERE f.user IS NOT NULL AND f.share IS NOT NULL AND f.user != '' AND f.share != ''
	GROUP BY u.id, s.id
	`)
	if err != nil {
		return err
	}

	// Commit da transação
	return tx.Commit()
}

// Funções para consultar dados da infraestrutura
func GetInfrastructureHosts(db *sql.DB) ([]map[string]interface{}, error) {
	rows, err := db.Query(`
		SELECT id, host, domain, is_domain_controller, is_server, is_workstation, last_seen
		FROM infrastructure_hosts
		ORDER BY host
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var hosts []map[string]interface{}
	for rows.Next() {
		var h struct {
			ID                 int
			Host               string
			Domain             sql.NullString
			IsDomainController bool
			IsServer           bool
			IsWorkstation      bool
			LastSeen           sql.NullString
		}
		if err := rows.Scan(&h.ID, &h.Host, &h.Domain, &h.IsDomainController, &h.IsServer, &h.IsWorkstation, &h.LastSeen); err != nil {
			return nil, err
		}
		hosts = append(hosts, map[string]interface{}{
			"id":                   h.ID,
			"host":                 h.Host,
			"domain":               h.Domain.String,
			"is_domain_controller": h.IsDomainController,
			"is_server":            h.IsServer,
			"is_workstation":       h.IsWorkstation,
			"last_seen":            h.LastSeen.String,
		})
	}
	return hosts, nil
}

func GetInfrastructureUsers(db *sql.DB) ([]map[string]interface{}, error) {
	rows, err := db.Query(`
		SELECT id, username, domain, is_admin, last_seen
		FROM infrastructure_users
		ORDER BY username
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []map[string]interface{}
	for rows.Next() {
		var u struct {
			ID       int
			Username string
			Domain   sql.NullString
			IsAdmin  bool
			LastSeen sql.NullString
		}
		if err := rows.Scan(&u.ID, &u.Username, &u.Domain, &u.IsAdmin, &u.LastSeen); err != nil {
			return nil, err
		}
		users = append(users, map[string]interface{}{
			"id":        u.ID,
			"username":  u.Username,
			"domain":    u.Domain.String,
			"is_admin":  u.IsAdmin,
			"last_seen": u.LastSeen.String,
		})
	}
	return users, nil
}

func GetInfrastructureShares(db *sql.DB) ([]map[string]interface{}, error) {
	rows, err := db.Query(`
		SELECT s.id, s.name, s.path, s.is_accessible,
			   h.host, h.domain
		FROM infrastructure_shares s
		JOIN infrastructure_hosts h ON s.host_id = h.id
		ORDER BY s.name
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var shares []map[string]interface{}
	for rows.Next() {
		var s struct {
			ID           int
			Name         string
			Path         sql.NullString
			IsAccessible bool
			Host         string
			Domain       sql.NullString
		}
		if err := rows.Scan(&s.ID, &s.Name, &s.Path, &s.IsAccessible, &s.Host, &s.Domain); err != nil {
			return nil, err
		}
		shares = append(shares, map[string]interface{}{
			"id":            s.ID,
			"name":          s.Name,
			"path":          s.Path.String,
			"is_accessible": s.IsAccessible,
			"host":          s.Host,
			"domain":        s.Domain.String,
		})
	}
	return shares, nil
}

func GetInfrastructureAccess(db *sql.DB) ([]map[string]interface{}, error) {
	rows, err := db.Query(`
		SELECT a.id, a.access_type, a.first_seen, a.last_seen,
			   u.username, u.domain as user_domain,
			   CASE 
				   WHEN a.target_type = 'host' THEN h.host
				   WHEN a.target_type = 'share' THEN s.name
			   END as target_name,
			   CASE 
				   WHEN a.target_type = 'host' THEN h.domain
				   WHEN a.target_type = 'share' THEN h2.domain
			   END as target_domain,
			   a.target_type
		FROM infrastructure_access a
		JOIN infrastructure_users u ON a.user_id = u.id
		LEFT JOIN infrastructure_hosts h ON a.target_type = 'host' AND a.target_id = h.id
		LEFT JOIN infrastructure_shares s ON a.target_type = 'share' AND a.target_id = s.id
		LEFT JOIN infrastructure_hosts h2 ON s.host_id = h2.id
		ORDER BY a.last_seen DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var accesses []map[string]interface{}
	for rows.Next() {
		var a struct {
			ID           int
			AccessType   string
			FirstSeen    sql.NullString
			LastSeen     sql.NullString
			Username     string
			UserDomain   sql.NullString
			TargetName   string
			TargetDomain sql.NullString
			TargetType   string
		}
		if err := rows.Scan(&a.ID, &a.AccessType, &a.FirstSeen, &a.LastSeen,
			&a.Username, &a.UserDomain, &a.TargetName, &a.TargetDomain, &a.TargetType); err != nil {
			return nil, err
		}
		accesses = append(accesses, map[string]interface{}{
			"id":            a.ID,
			"access_type":   a.AccessType,
			"first_seen":    a.FirstSeen.String,
			"last_seen":     a.LastSeen.String,
			"username":      a.Username,
			"user_domain":   a.UserDomain.String,
			"target_name":   a.TargetName,
			"target_domain": a.TargetDomain.String,
			"target_type":   a.TargetType,
		})
	}
	return accesses, nil
}

// LoadKnownFiles returns a map of "share\path" → mod_time for all files previously
// recorded for a given host. Used by delta mode to skip unchanged files.
func LoadKnownFiles(db *sql.DB, host string) (map[string]time.Time, error) {
	rows, err := db.Query(
		`SELECT share, path, mod_time FROM files WHERE host = ?`,
		host,
	)
	if err != nil {
		return nil, fmt.Errorf("delta: query failed: %w", err)
	}
	defer rows.Close()

	known := make(map[string]time.Time)
	for rows.Next() {
		var share, path, modTimeStr string
		if err := rows.Scan(&share, &path, &modTimeStr); err != nil {
			continue
		}
		t, err := time.Parse(time.RFC3339, modTimeStr)
		if err != nil {
			// Try alternative formats stored by the tool
			t, err = time.Parse("2006-01-02 15:04:05", modTimeStr)
			if err != nil {
				continue
			}
		}
		key := share + "\\" + path
		known[key] = t
	}
	return known, rows.Err()
}
