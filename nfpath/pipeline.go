package main

import (
	"database/sql"
	"fmt"
	"time"
)

// loadProcessedIDs fetches already-processed file and lhf IDs from nfpathDB.
// These come from intel_sources which lives in nfpath.db, not nullfang.db —
// cross-database subqueries are not possible without SQLite ATTACH.
func loadProcessedIDs(nfpathDB *sql.DB) (fileIDs map[int]bool, lhfIDs map[int]bool) {
	fileIDs = make(map[int]bool)
	lhfIDs = make(map[int]bool)

	rows, err := nfpathDB.Query(`SELECT nullfang_file_id FROM intel_sources WHERE nullfang_file_id IS NOT NULL`)
	if err == nil {
		for rows.Next() {
			var id int
			if rows.Scan(&id) == nil {
				fileIDs[id] = true
			}
		}
		rows.Close()
	}

	rows2, err := nfpathDB.Query(`SELECT lhf_id FROM intel_sources WHERE lhf_id IS NOT NULL`)
	if err == nil {
		for rows2.Next() {
			var id int
			if rows2.Scan(&id) == nil {
				lhfIDs[id] = true
			}
		}
		rows2.Close()
	}

	return
}

// runAnalyze processes all unprocessed files from nullfang.db (post-scan, one-shot).
func runAnalyze(nfDB *sql.DB, nfpathDB *sql.DB, llm LLMClient, verbose bool) error {
	fmt.Println("[nfpath] Starting analysis...")

	runID := startRun(nfpathDB, llm.ModelName())
	filesProcessed := 0
	decisionsCreated := 0

	processedFiles, processedLHF := loadProcessedIDs(nfpathDB)

	// Phase 1: files with local copies → full LLM analysis
	rows, err := nfDB.Query(`
		SELECT f.id, f.local_path, f.path, f.host, f.share
		FROM files f
		WHERE f.local_path IS NOT NULL AND f.local_path != ''
		ORDER BY f.id`)
	if err != nil {
		return fmt.Errorf("query files: %w", err)
	}

	for rows.Next() {
		var id int
		var localPath, remotePath, host, share sql.NullString
		if err := rows.Scan(&id, &localPath, &remotePath, &host, &share); err != nil {
			continue
		}
		if !localPath.Valid || localPath.String == "" || processedFiles[id] {
			continue
		}
		if err := analyzeFile(nfpathDB, llm, id,
			localPath.String, remotePath.String, host.String, share.String, verbose,
		); err != nil {
			fmt.Printf("  [WARN] file_id=%d: %v\n", id, err)
			continue
		}
		processedFiles[id] = true
		filesProcessed++
		fmt.Printf("  [+] analyzed (%d) %s\n", id, remotePath.String)
	}
	rows.Close()

	// Phase 2: low_hanging_fruit without local copy → decision table
	lhfRows, err := nfDB.Query(`
		SELECT l.id, l.path, l.host, l.share, l.match_pattern, l.match_type, l.file_type, l.size
		FROM low_hanging_fruit l
		LEFT JOIN files f ON (f.path = l.path AND f.host = l.host AND f.share = l.share)
		WHERE (f.local_path IS NULL OR f.local_path = '' OR f.id IS NULL)
		ORDER BY l.id`)
	if err != nil {
		return fmt.Errorf("query lhf: %w", err)
	}

	for lhfRows.Next() {
		var lhfID int
		var path, host, share, matchPat, matchType, fileType sql.NullString
		var size sql.NullInt64
		if err := lhfRows.Scan(&lhfID, &path, &host, &share, &matchPat, &matchType, &fileType, &size); err != nil {
			continue
		}
		if processedLHF[lhfID] {
			continue
		}
		fileID := lhfID * -1
		if err := inferDecision(nfpathDB, llm, lhfID, fileID,
			path.String, host.String, share.String,
			matchPat.String, matchType.String, fileType.String, size.Int64, verbose,
		); err != nil {
			fmt.Printf("  [WARN] lhf_id=%d: %v\n", lhfID, err)
			continue
		}
		processedLHF[lhfID] = true
		decisionsCreated++
		fmt.Printf("  [!] decision queued (%d) %s on %s\n", lhfID, path.String, host.String)
	}
	lhfRows.Close()

	finishRun(nfpathDB, runID, filesProcessed, decisionsCreated)
	fmt.Printf("\n[nfpath] Done — %d files analyzed, %d decisions queued\n", filesProcessed, decisionsCreated)
	return nil
}

// runPipeline watches nullfang.db for new files and processes them as they arrive.
func runPipeline(nfDB *sql.DB, nfpathDB *sql.DB, llm LLMClient, poll time.Duration, verbose bool) error {
	fmt.Printf("[nfpath] Pipeline mode — polling every %s (Ctrl+C to stop)\n", poll)

	ticker := time.NewTicker(poll)
	defer ticker.Stop()

	runID := startRun(nfpathDB, llm.ModelName())
	total := 0

	for range ticker.C {
		n, err := pipelineTick(nfDB, nfpathDB, llm, verbose)
		if err != nil {
			fmt.Printf("[WARN] tick error: %v\n", err)
			continue
		}
		if n > 0 {
			total += n
			fmt.Printf("[nfpath] +%d new findings processed (total: %d)\n", n, total)
		}
		finishRun(nfpathDB, runID, total, 0)
	}
	return nil
}

func pipelineTick(nfDB *sql.DB, nfpathDB *sql.DB, llm LLMClient, verbose bool) (int, error) {
	processed := 0
	processedFiles, processedLHF := loadProcessedIDs(nfpathDB)

	rows, err := nfDB.Query(`
		SELECT f.id, f.local_path, f.path, f.host, f.share
		FROM files f
		WHERE f.local_path IS NOT NULL AND f.local_path != ''
		ORDER BY f.id
		LIMIT 20`)
	if err != nil {
		return 0, err
	}

	for rows.Next() {
		var id int
		var localPath, remotePath, host, share sql.NullString
		if err := rows.Scan(&id, &localPath, &remotePath, &host, &share); err != nil {
			continue
		}
		if !localPath.Valid || localPath.String == "" || processedFiles[id] {
			continue
		}
		if err := analyzeFile(nfpathDB, llm, id,
			localPath.String, remotePath.String, host.String, share.String, verbose,
		); err != nil {
			fmt.Printf("  [WARN] file_id=%d: %v\n", id, err)
			continue
		}
		processedFiles[id] = true
		processed++
		fmt.Printf("  [+] analyzed (%d) %s\n", id, remotePath.String)
	}
	rows.Close()

	lhfRows, err := nfDB.Query(`
		SELECT l.id, l.path, l.host, l.share, l.match_pattern, l.match_type, l.file_type, l.size
		FROM low_hanging_fruit l
		LEFT JOIN files f ON (f.path = l.path AND f.host = l.host AND f.share = l.share)
		WHERE (f.local_path IS NULL OR f.local_path = '' OR f.id IS NULL)
		ORDER BY l.id
		LIMIT 10`)
	if err != nil {
		return processed, nil
	}

	for lhfRows.Next() {
		var lhfID int
		var path, host, share, matchPat, matchType, fileType sql.NullString
		var size sql.NullInt64
		if err := lhfRows.Scan(&lhfID, &path, &host, &share, &matchPat, &matchType, &fileType, &size); err != nil {
			continue
		}
		if processedLHF[lhfID] {
			continue
		}
		fileID := lhfID * -1
		if err := inferDecision(nfpathDB, llm, lhfID, fileID,
			path.String, host.String, share.String,
			matchPat.String, matchType.String, fileType.String, size.Int64, verbose,
		); err != nil {
			continue
		}
		processedLHF[lhfID] = true
		processed++
		fmt.Printf("  [!] decision queued (%d) %s\n", lhfID, path.String)
	}
	lhfRows.Close()

	return processed, nil
}

func startRun(db *sql.DB, model string) int64 {
	res, _ := db.Exec(`INSERT INTO intel_run_meta (model_used) VALUES (?)`, model)
	if res == nil {
		return 0
	}
	id, _ := res.LastInsertId()
	return id
}

func finishRun(db *sql.DB, runID int64, files, decisions int) {
	if runID <= 0 {
		return
	}
	db.Exec(`
		UPDATE intel_run_meta
		SET finished_at=?, files_processed=?, decisions_created=?
		WHERE id=?`,
		time.Now().Format(time.RFC3339), files, decisions, runID,
	)
}
