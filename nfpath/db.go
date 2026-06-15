package main

import (
	"database/sql"

	_ "modernc.org/sqlite"
)

const schema = `
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS intel_credentials (
	id              INTEGER PRIMARY KEY AUTOINCREMENT,
	username        TEXT,
	password_clear  TEXT,
	hash            TEXT,
	token           TEXT,
	service_type    TEXT,
	confidence      TEXT CHECK(confidence IN ('high','medium','low')),
	host_hint       TEXT,
	context_note    TEXT,
	source_file_id  INTEGER,
	created_at      DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS intel_hosts (
	id              INTEGER PRIMARY KEY AUTOINCREMENT,
	identifier      TEXT NOT NULL,
	identifier_type TEXT,
	ip              TEXT,
	inferred_type   TEXT,
	confidence      TEXT CHECK(confidence IN ('high','medium','low')),
	discovery_note  TEXT,
	source_file_id  INTEGER,
	created_at      DATETIME DEFAULT CURRENT_TIMESTAMP,
	UNIQUE(identifier, identifier_type)
);

CREATE TABLE IF NOT EXISTS intel_services (
	id             INTEGER PRIMARY KEY AUTOINCREMENT,
	host_id        INTEGER REFERENCES intel_hosts(id),
	service_name   TEXT,
	service_type   TEXT,
	endpoint       TEXT,
	port           INTEGER,
	notes          TEXT,
	source_file_id INTEGER,
	created_at     DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS intel_edges (
	id           INTEGER PRIMARY KEY AUTOINCREMENT,
	from_type    TEXT NOT NULL,
	from_id      INTEGER NOT NULL,
	to_type      TEXT NOT NULL,
	to_id        INTEGER NOT NULL,
	relationship TEXT NOT NULL,
	confidence   TEXT CHECK(confidence IN ('high','medium','low')),
	created_at   DATETIME DEFAULT CURRENT_TIMESTAMP,
	UNIQUE(from_type, from_id, to_type, to_id, relationship)
);

CREATE TABLE IF NOT EXISTS intel_decisions (
	id                 INTEGER PRIMARY KEY AUTOINCREMENT,
	nullfang_file_id   INTEGER,
	file_path          TEXT NOT NULL,
	host               TEXT,
	share              TEXT,
	match_reason       TEXT,
	inferred_value     TEXT,
	recommended_action TEXT,
	priority           TEXT CHECK(priority IN ('critical','high','medium','low')),
	status             TEXT DEFAULT 'pending' CHECK(status IN ('pending','reviewed','actioned')),
	operator_notes     TEXT,
	created_at         DATETIME DEFAULT CURRENT_TIMESTAMP,
	UNIQUE(nullfang_file_id)
);

CREATE TABLE IF NOT EXISTS intel_sources (
	id                 INTEGER PRIMARY KEY AUTOINCREMENT,
	nullfang_file_id   INTEGER UNIQUE,
	lhf_id             INTEGER UNIQUE,
	processed_at       DATETIME DEFAULT CURRENT_TIMESTAMP,
	llm_model_used     TEXT
);

CREATE TABLE IF NOT EXISTS intel_run_meta (
	id                 INTEGER PRIMARY KEY AUTOINCREMENT,
	nullfang_db_path   TEXT,
	started_at         DATETIME DEFAULT CURRENT_TIMESTAMP,
	finished_at        DATETIME,
	files_processed    INTEGER DEFAULT 0,
	decisions_created  INTEGER DEFAULT 0,
	model_used         TEXT
);
`

func initDB(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err = db.Exec(schema); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

func openNullFangDB(path string) (*sql.DB, error) {
	db, err := sql.Open("sqlite", "file:"+path+"?mode=ro")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(4)
	return db, nil
}
