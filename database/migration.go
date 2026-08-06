package database

import (
	"database/sql"
	"fmt"
	"strings"
)

// MigrateAddSearchParamsToUnique updates the low_hanging_fruit table
// to include domain, user, match_pattern and match_type in the UNIQUE constraint.
// This allows the same file to be recorded multiple times if found with
// different search parameters or credentials.
func MigrateAddSearchParamsToUnique(db *sql.DB) error {
	// Check if migration is needed by inspecting the table schema
	var tableSql string
	err := db.QueryRow("SELECT sql FROM sqlite_master WHERE type='table' AND name='low_hanging_fruit'").Scan(&tableSql)
	if err != nil {
		// Table doesn't exist yet, no migration needed
		return nil
	}

	// Check the UNIQUE constraint specifically — not just column definitions.
	// Column names appear in both column defs and the UNIQUE clause; we need
	// to find the UNIQUE clause and verify it contains all expected fields.
	if uniqueConstraintContains(tableSql, "domain") &&
		uniqueConstraintContains(tableSql, "match_pattern") &&
		uniqueConstraintContains(tableSql, "match_type") {
		return nil
	}

	fmt.Println("[MIGRATION] Updating low_hanging_fruit table schema...")

	// SQLite doesn't support ALTER TABLE to modify constraints
	// We need to recreate the table
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %v", err)
	}
	defer tx.Rollback()

	// Create new table with updated constraint
	_, err = tx.Exec(`
		CREATE TABLE IF NOT EXISTS low_hanging_fruit_new (
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
		return fmt.Errorf("failed to create new table: %v", err)
	}

	// Copy data from old table
	_, err = tx.Exec(`
		INSERT INTO low_hanging_fruit_new 
		SELECT * FROM low_hanging_fruit;
	`)
	if err != nil {
		return fmt.Errorf("failed to copy data: %v", err)
	}

	// Drop old table
	_, err = tx.Exec(`DROP TABLE low_hanging_fruit;`)
	if err != nil {
		return fmt.Errorf("failed to drop old table: %v", err)
	}

	// Rename new table
	_, err = tx.Exec(`ALTER TABLE low_hanging_fruit_new RENAME TO low_hanging_fruit;`)
	if err != nil {
		return fmt.Errorf("failed to rename table: %v", err)
	}

	err = tx.Commit()
	if err != nil {
		return fmt.Errorf("failed to commit transaction: %v", err)
	}

	fmt.Println("[MIGRATION] Successfully updated low_hanging_fruit table schema")
	return nil
}

// MigrateClassificationRulesAddContains recreates classification_rules with 'contains'
// added to the match_type CHECK constraint (previously only 'exact' and 'regex').
func MigrateClassificationRulesAddContains(db *sql.DB) error {
	var tableSql string
	err := db.QueryRow("SELECT sql FROM sqlite_master WHERE type='table' AND name='classification_rules'").Scan(&tableSql)
	if err != nil {
		return nil // table doesn't exist yet — InitDB will create it correctly
	}
	if strings.Contains(tableSql, "'contains'") {
		return nil // already migrated
	}

	fmt.Println("[MIGRATION] Adding 'contains' to classification_rules CHECK constraint...")

	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %v", err)
	}
	defer tx.Rollback()

	_, err = tx.Exec(`
		CREATE TABLE IF NOT EXISTS classification_rules_new (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL,
			description TEXT,
			match_pattern TEXT NOT NULL,
			match_type TEXT NOT NULL CHECK(match_type IN ('exact', 'regex', 'contains')),
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
		return fmt.Errorf("failed to create new table: %v", err)
	}

	_, err = tx.Exec(`INSERT INTO classification_rules_new SELECT * FROM classification_rules`)
	if err != nil {
		return fmt.Errorf("failed to copy data: %v", err)
	}

	_, err = tx.Exec(`DROP TABLE classification_rules`)
	if err != nil {
		return fmt.Errorf("failed to drop old table: %v", err)
	}

	_, err = tx.Exec(`ALTER TABLE classification_rules_new RENAME TO classification_rules`)
	if err != nil {
		return fmt.Errorf("failed to rename table: %v", err)
	}

	if err = tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit: %v", err)
	}

	fmt.Println("[MIGRATION] Successfully updated classification_rules CHECK constraint")
	return nil
}

// MigrateUpdateDefaultClassifications renames and re-levels the default classification set
// from the old generic convention (Public=level 1 = least sensitive, Critical=level 5 = most)
// to the offensive-security convention (Critical=level 1 = most critical, Public=level 5 = lowest).
func MigrateUpdateDefaultClassifications(db *sql.DB) error {
	var publicCount, critCount int
	db.QueryRow("SELECT COUNT(*) FROM classifications WHERE name='Public' AND level=1").Scan(&publicCount)
	db.QueryRow("SELECT COUNT(*) FROM classifications WHERE name='Critical' AND level=5").Scan(&critCount)
	if publicCount == 0 || critCount == 0 {
		return nil // already migrated or non-standard DB
	}

	fmt.Println("[MIGRATION] Updating default classifications to offensive-sec convention...")

	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %v", err)
	}
	defer tx.Rollback()

	// Prefix all names to avoid UNIQUE conflicts during the rename cycle
	if _, err = tx.Exec(`UPDATE classifications SET name = 'OLD_' || name`); err != nil {
		return fmt.Errorf("failed to prefix names: %v", err)
	}

	// Delete old generic default rules before migrating classification IDs
	if _, err = tx.Exec(`DELETE FROM classification_rules WHERE name IN ('Passwords','Credentials','Financial Documents','Legal Documents','Public Documents')`); err != nil {
		return fmt.Errorf("failed to delete old rules: %v", err)
	}

	updates := []struct {
		oldPrefixed string
		newName     string
		desc        string
		color       string
		level       int
	}{
		{"OLD_Critical", "Critical", "Direct attack path: credentials, private keys, hashes, SAM/NTDS", "#dc3545", 1},
		{"OLD_Restricted", "Sensitive", "High-value intel: configs with credentials, password managers, DB dumps", "#fd7e14", 2},
		{"OLD_Confidential", "Confidential", "Internal data: financial records, contracts, PII", "#ffc107", 3},
		{"OLD_Internal", "Informational", "General findings: office docs, emails, general configs", "#17a2b8", 4},
		{"OLD_Public", "Public", "Low value: publicly accessible content", "#28a745", 5},
	}
	for _, u := range updates {
		if _, err = tx.Exec(
			`UPDATE classifications SET name=?, description=?, level=?, color=?, updated_at=datetime('now') WHERE name=?`,
			u.newName, u.desc, u.level, u.color, u.oldPrefixed,
		); err != nil {
			return fmt.Errorf("failed to update %s: %v", u.oldPrefixed, err)
		}
	}

	if err = tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit: %v", err)
	}

	fmt.Println("[MIGRATION] Successfully updated default classifications")
	return nil
}

// MigrateAddScanMode adds the scan_mode column to the files table for legacy
// databases created before the scan_mode field existed. It's a no-op if the
// column is already present or the table doesn't exist yet.
func MigrateAddScanMode(db *sql.DB) error {
	rows, err := db.Query("PRAGMA table_info(files)")
	if err != nil {
		return fmt.Errorf("failed to inspect files table: %v", err)
	}
	hasScanMode := false
	for rows.Next() {
		var cid int
		var name, ctype string
		var notnull, pk int
		var dflt sql.NullString
		if err := rows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
			rows.Close()
			return fmt.Errorf("failed to read files column: %v", err)
		}
		if name == "scan_mode" {
			hasScanMode = true
			break
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return fmt.Errorf("failed iterating files columns: %v", err)
	}
	if hasScanMode {
		return nil
	}

	fmt.Println("[MIGRATION] Adding scan_mode column to files table...")
	if _, err := db.Exec("ALTER TABLE files ADD COLUMN scan_mode TEXT DEFAULT 'exfil'"); err != nil {
		return fmt.Errorf("failed to add scan_mode column: %v", err)
	}
	fmt.Println("[MIGRATION] Successfully added scan_mode column to files table")
	return nil
}

// uniqueConstraintContains checks whether `field` appears inside the UNIQUE(...)
// clause of a CREATE TABLE statement, not merely as a column definition.
func uniqueConstraintContains(createSQL, field string) bool {
	upper := strings.ToUpper(createSQL)
	fieldUpper := strings.ToUpper(field)
	idx := strings.Index(upper, "UNIQUE(")
	if idx < 0 {
		// Some SQLite versions write "UNIQUE (" with a space
		idx = strings.Index(upper, "UNIQUE (")
		if idx < 0 {
			return false
		}
	}
	end := strings.Index(upper[idx:], ")")
	if end < 0 {
		return false
	}
	constraint := upper[idx : idx+end+1]
	return strings.Contains(constraint, fieldUpper)
}
