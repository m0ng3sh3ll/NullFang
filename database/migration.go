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
