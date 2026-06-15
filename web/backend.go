package web

import (
	"database/sql"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/m0ng3sh3ll/NullFang/database"
	_ "modernc.org/sqlite"
)

type Server struct {
	db     *sql.DB
	router *gin.Engine
}

type ClassificationRule struct {
	ID               int    `json:"id"`
	Name             string `json:"name"`
	Description      string `json:"description"`
	MatchPattern     string `json:"match_pattern"`
	MatchType        string `json:"match_type"`
	ClassificationID int    `json:"classification_id"`
	Priority         int    `json:"priority"`
	Enabled          bool   `json:"enabled"`
}

func NewServer(dbPath string) (*Server, error) {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return nil, err
	}

	router := gin.Default()

	// CORS restricted to localhost — the web UI must not be exposed to untrusted networks.
	router.Use(func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")
		if origin == "" || strings.HasPrefix(origin, "http://localhost") || strings.HasPrefix(origin, "http://127.0.0.1") {
			c.Writer.Header().Set("Access-Control-Allow-Origin", origin)
		}
		c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}
		c.Next()
	})

	// Servir arquivos estáticos
	router.Static("/static", "./web/frontend/src")
	router.StaticFile("/router.js", "./web/frontend/src/router.js")
	router.StaticFile("/index.html", "./web/frontend/src/index.html")

	// Rota para página inicial
	router.GET("/", func(c *gin.Context) {
		c.File("./web/frontend/src/index.html")
	})

	// Rota para SPA
	router.NoRoute(func(c *gin.Context) {
		// Se for arquivo estático (ex: .js, .css, .png), retorna 404
		if strings.Contains(c.Request.URL.Path, ".") {
			c.Status(404)
			return
		}
		// Para qualquer outra rota, serve o index.html do frontend
		c.File("./web/frontend/src/index.html")
	})

	server := &Server{
		db:     db,
		router: router,
	}

	// Rotas da API
	api := router.Group("/")
	{
		// Rota para listar domínios disponíveis
		api.GET("/domains", server.listDomains)

		// Rotas de documentos
		api.GET("/documents", server.listDocuments)
		api.GET("/documents/:id", server.getDocument)
		api.POST("/documents/classify", server.classifyDocument)
		api.POST("/documents/bulk-classify", server.bulkClassify)
		api.POST("/documents/auto-classify", server.autoClassifyDocuments)
		api.DELETE("/documents/classify/:id", server.removeClassification)

		// Rotas de classificações
		api.GET("/classifications", server.listClassifications)
		api.POST("/classifications", server.createClassification)
		api.PUT("/classifications/:id", server.updateClassification)
		api.DELETE("/classifications/:id", server.deleteClassification)

		// Rotas de regras
		api.GET("/rules", server.listRules)
		api.GET("/rules/:id", server.getRule)
		api.POST("/rules", server.createRule)
		api.PUT("/rules/:id", server.updateRule)
		api.DELETE("/rules/:id", server.deleteRule)

		// Análise
		api.GET("/analysis/stats", server.getClassificationStats)
		api.GET("/analysis/sensitivity-map", server.getSensitivityMap)

		// Rota para sugestões de classificação
		api.GET("/documents/classification-suggestions", server.classificationSuggestions)

		// Rotas de infraestrutura
		api.GET("/infrastructure/hosts", server.listInfrastructureHosts)
		api.GET("/infrastructure/users", server.listInfrastructureUsers)
		api.GET("/infrastructure/shares", server.listInfrastructureShares)
		api.GET("/infrastructure/access", server.listInfrastructureAccess)
		api.POST("/infrastructure/populate", server.populateInfrastructure)
		api.GET("/infrastructure/nodes/files", server.getNodeFiles)
		api.GET("/infrastructure/nodes/user-access", server.getNodeUserAccess)

		// Report
		api.GET("/report/data", server.getReportData)
	}

	return server, nil
}

func (s *Server) Start(port string) error {
	return s.router.Run("127.0.0.1:" + port)
}

// Função para listar domínios disponíveis
func (s *Server) listDomains(c *gin.Context) {
	// Query mais abrangente para pegar todos os domínios
	rows, err := s.db.Query(`
		SELECT DISTINCT domain FROM (
			SELECT domain FROM domain_credentials WHERE domain IS NOT NULL AND TRIM(domain) != ''
			UNION
			SELECT domain FROM files WHERE domain IS NOT NULL AND TRIM(domain) != ''
			UNION
			SELECT domain FROM low_hanging_fruit WHERE domain IS NOT NULL AND TRIM(domain) != ''
		) 
		WHERE domain IS NOT NULL AND TRIM(domain) != ''
		ORDER BY domain
	`)
	if err != nil {
		fmt.Printf("Erro na query de domínios: %v\n", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	var domains []string
	for rows.Next() {
		var domain string
		if err := rows.Scan(&domain); err != nil {
			fmt.Printf("Erro ao escanear domínio: %v\n", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		// Normalizar o domínio (remover espaços extras)
		domain = strings.TrimSpace(domain)
		if domain != "" {
			domains = append(domains, domain)
		}
	}

	fmt.Printf("Domínios encontrados: %v\n", domains)
	c.JSON(http.StatusOK, domains)
}

// Handlers
func (s *Server) listDocuments(c *gin.Context) {
	// Obter parâmetro de domínio da query string
	domain := c.Query("domain")

	fmt.Printf("Filtrando documentos por domínio: '%s'\n", domain)

	var query string
	var args []interface{}

	if domain != "" {
		query = `
			SELECT 
				f.id, f.path as name, f.host, f.share, f.domain, f.size, f.mod_time as last_modified,
				f.match_pattern, f.match_type, f.search_param_type, f.search_param_value,
				c.id as classification_id, c.name as classification_name, c.color as classification_color,
				dc.classified_by, dc.classified_at
			FROM files f
			LEFT JOIN document_classifications dc ON f.id = dc.file_id
			LEFT JOIN classifications c ON dc.classification_id = c.id
			WHERE f.domain = ? OR f.domain = ? OR f.domain = ?
			ORDER BY f.path ASC
		`
		// Tentar diferentes variações do domínio (original, uppercase, lowercase)
		args = append(args, domain, strings.ToUpper(domain), strings.ToLower(domain))
	} else {
		query = `
			SELECT 
				f.id, f.path as name, f.host, f.share, f.domain, f.size, f.mod_time as last_modified,
				f.match_pattern, f.match_type, f.search_param_type, f.search_param_value,
				c.id as classification_id, c.name as classification_name, c.color as classification_color,
				dc.classified_by, dc.classified_at
			FROM files f
			LEFT JOIN document_classifications dc ON f.id = dc.file_id
			LEFT JOIN classifications c ON dc.classification_id = c.id
			ORDER BY f.path ASC
		`
	}

	rows, err := s.db.Query(query, args...)
	if err != nil {
		fmt.Printf("Erro na query de documentos: %v\n", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	var documents []map[string]interface{}
	for rows.Next() {
		var doc struct {
			ID                  int
			Name                string
			Host                sql.NullString
			Share               sql.NullString
			Domain              sql.NullString
			Size                int64
			LastModified        string
			MatchPattern        sql.NullString
			MatchType           sql.NullString
			SearchParamType     sql.NullString
			SearchParamValue    sql.NullString
			ClassificationID    sql.NullInt64
			ClassificationName  sql.NullString
			ClassificationColor sql.NullString
			ClassifiedBy        sql.NullString
			ClassifiedAt        sql.NullString
		}

		err := rows.Scan(
			&doc.ID,
			&doc.Name,
			&doc.Host,
			&doc.Share,
			&doc.Domain,
			&doc.Size,
			&doc.LastModified,
			&doc.MatchPattern,
			&doc.MatchType,
			&doc.SearchParamType,
			&doc.SearchParamValue,
			&doc.ClassificationID,
			&doc.ClassificationName,
			&doc.ClassificationColor,
			&doc.ClassifiedBy,
			&doc.ClassifiedAt,
		)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		document := map[string]interface{}{
			"id":                 doc.ID,
			"name":               doc.Name,
			"host":               doc.Host.String,
			"share":              doc.Share.String,
			"domain":             doc.Domain.String,
			"size":               doc.Size,
			"last_modified":      doc.LastModified,
			"match_pattern":      doc.MatchPattern.String,
			"match_type":         doc.MatchType.String,
			"search_param_type":  doc.SearchParamType.String,
			"search_param_value": doc.SearchParamValue.String,
		}

		if doc.ClassificationID.Valid {
			document["classification"] = map[string]interface{}{
				"id":    doc.ClassificationID.Int64,
				"name":  doc.ClassificationName.String,
				"color": doc.ClassificationColor.String,
			}
			document["classified_by"] = doc.ClassifiedBy.String
			document["classified_at"] = doc.ClassifiedAt.String
		}

		documents = append(documents, document)
	}

	c.JSON(http.StatusOK, documents)
}

func (s *Server) getDocument(c *gin.Context) {
	id := c.Param("id")
	var doc map[string]interface{}
	err := s.db.QueryRow(`
		SELECT f.id, f.path, f.host, f.share, f.domain, f.size, f.mod_time, f.file_type, f.match_pattern, f.match_type,
			   c.name as classification_name, c.color as classification_color, dc.notes, dc.classified_by, dc.classified_at
		FROM files f
		LEFT JOIN document_classifications dc ON f.id = dc.file_id
		LEFT JOIN classifications c ON dc.classification_id = c.id
		WHERE f.id = ?
		ORDER BY dc.classified_at DESC
		LIMIT 1
	`, id).Scan(&doc)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, doc)
}

func (s *Server) classifyDocument(c *gin.Context) {
	var req struct {
		DocumentID       int    `json:"document_id" binding:"required"`
		ClassificationID int    `json:"classification_id" binding:"required"`
		Notes            string `json:"notes"`
	}

	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Erro ao processar requisição: %v", err)})
		return
	}

	// Verificar se o arquivo existe
	var exists bool
	err := s.db.QueryRow("SELECT EXISTS(SELECT 1 FROM files WHERE id = ?)", req.DocumentID).Scan(&exists)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Erro ao verificar arquivo: %v", err)})
		return
	}
	if !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "Arquivo não encontrado"})
		return
	}

	// Verificar se a classificação existe
	err = s.db.QueryRow("SELECT EXISTS(SELECT 1 FROM classifications WHERE id = ?)", req.ClassificationID).Scan(&exists)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Erro ao verificar classificação: %v", err)})
		return
	}
	if !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "Classificação não encontrada"})
		return
	}

	// Inserir ou atualizar a classificação
	_, err = s.db.Exec(`
		INSERT INTO document_classifications (
			file_id, classification_id, notes, classified_by, classified_at
		) VALUES (?, ?, ?, ?, datetime('now'))
		ON CONFLICT(file_id) DO UPDATE SET
			classification_id = excluded.classification_id,
			notes = excluded.notes,
			classified_by = excluded.classified_by,
			classified_at = datetime('now')
	`, req.DocumentID, req.ClassificationID, req.Notes, "manual")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Erro ao classificar documento: %v", err)})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Documento classificado com sucesso"})
}

func (s *Server) bulkClassify(c *gin.Context) {
	var req struct {
		DocumentIDs      []int `json:"document_ids"`
		ClassificationID int   `json:"classification_id"`
	}

	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Iniciar transação
	tx, err := s.db.Begin()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer tx.Rollback()

	// Classificar cada documento
	for _, docID := range req.DocumentIDs {
		err := database.ClassifyDocument(s.db, docID, req.ClassificationID, "", "web")
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
	}

	// Commit da transação
	if err := tx.Commit(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Documents classified successfully"})
}

func (s *Server) listClassifications(c *gin.Context) {
	rows, err := s.db.Query(`
		SELECT id, name, description, level, color
		FROM classifications
		ORDER BY level ASC
	`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	var classifications []map[string]interface{}
	for rows.Next() {
		var classification struct {
			ID          int
			Name        string
			Description string
			Level       int
			Color       string
		}

		err := rows.Scan(&classification.ID, &classification.Name, &classification.Description, &classification.Level, &classification.Color)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		classifications = append(classifications, map[string]interface{}{
			"id":          classification.ID,
			"name":        classification.Name,
			"description": classification.Description,
			"level":       classification.Level,
			"color":       classification.Color,
		})
	}

	c.JSON(http.StatusOK, classifications)
}

func (s *Server) createClassification(c *gin.Context) {
	var req struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		Level       int    `json:"level"`
		Color       string `json:"color"`
	}

	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	err := database.AddClassification(s.db, req.Name, req.Description, req.Level, req.Color)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Classification created successfully"})
}

func (s *Server) updateClassification(c *gin.Context) {
	idStr := c.Param("id")
	var id int
	if _, err := fmt.Sscanf(idStr, "%d", &id); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid ID"})
		return
	}

	var req struct {
		Name        string `json:"name"`
		Description string `json:"description"`
		Level       int    `json:"level"`
		Color       string `json:"color"`
	}

	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	err := database.UpdateClassification(s.db, id, req.Name, req.Description, req.Level, req.Color)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Classification updated successfully"})
}

func (s *Server) deleteClassification(c *gin.Context) {
	idStr := c.Param("id")
	var id int
	if _, err := fmt.Sscanf(idStr, "%d", &id); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid ID"})
		return
	}

	err := database.DeleteClassification(s.db, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Classification deleted successfully"})
}

func (s *Server) getClassificationStats(c *gin.Context) {
	// Obter parâmetro de domínio da query string
	domain := c.Query("domain")

	var query string
	var args []interface{}

	if domain != "" {
		query = `
			SELECT 
				c.id, c.name, c.color,
				COUNT(dc.id) as document_count
			FROM classifications c
			LEFT JOIN document_classifications dc ON c.id = dc.classification_id
			LEFT JOIN files f ON dc.file_id = f.id
			WHERE f.domain = ? OR f.domain IS NULL
			GROUP BY c.id
			ORDER BY c.level ASC
		`
		args = append(args, domain)
	} else {
		query = `
			SELECT 
				c.id, c.name, c.color,
				COUNT(dc.id) as document_count
			FROM classifications c
			LEFT JOIN document_classifications dc ON c.id = dc.classification_id
			GROUP BY c.id
			ORDER BY c.level ASC
		`
	}

	rows, err := s.db.Query(query, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	var stats []map[string]interface{}
	for rows.Next() {
		var s struct {
			ID            int
			Name          string
			Color         string
			DocumentCount int
		}

		err := rows.Scan(&s.ID, &s.Name, &s.Color, &s.DocumentCount)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		stats = append(stats, map[string]interface{}{
			"id":             s.ID,
			"name":           s.Name,
			"color":          s.Color,
			"document_count": s.DocumentCount,
		})
	}

	c.JSON(http.StatusOK, stats)
}

func (s *Server) getSensitivityMap(c *gin.Context) {
	rows, err := s.db.Query(`
		SELECT 
			c.id, c.name, c.description, c.level, c.color,
			COUNT(dc.id) as document_count
		FROM classifications c
		LEFT JOIN document_classifications dc ON c.id = dc.classification_id
		GROUP BY c.id
		ORDER BY c.level ASC
	`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	var mapData []map[string]interface{}
	for rows.Next() {
		var m struct {
			ID            int
			Name          string
			Description   string
			Level         int
			Color         string
			DocumentCount int
		}

		err := rows.Scan(&m.ID, &m.Name, &m.Description, &m.Level, &m.Color, &m.DocumentCount)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		mapData = append(mapData, map[string]interface{}{
			"id":             m.ID,
			"name":           m.Name,
			"description":    m.Description,
			"level":          m.Level,
			"color":          m.Color,
			"document_count": m.DocumentCount,
		})
	}

	c.JSON(http.StatusOK, mapData)
}

// Handlers para regras de classificação
func (s *Server) listRules(c *gin.Context) {
	rows, err := s.db.Query(`
		SELECT id, name, description, match_pattern, match_type, 
			   classification_id, priority, enabled
		FROM classification_rules
		ORDER BY priority DESC, name ASC
	`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	var rules []ClassificationRule
	for rows.Next() {
		var rule ClassificationRule
		err := rows.Scan(
			&rule.ID,
			&rule.Name,
			&rule.Description,
			&rule.MatchPattern,
			&rule.MatchType,
			&rule.ClassificationID,
			&rule.Priority,
			&rule.Enabled,
		)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		rules = append(rules, rule)
	}

	c.JSON(http.StatusOK, rules)
}

func (s *Server) getRule(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "ID inválido"})
		return
	}

	var rule ClassificationRule
	err = s.db.QueryRow(`
		SELECT id, name, description, match_pattern, match_type, 
			   classification_id, priority, enabled
		FROM classification_rules
		WHERE id = ?
	`, id).Scan(
		&rule.ID,
		&rule.Name,
		&rule.Description,
		&rule.MatchPattern,
		&rule.MatchType,
		&rule.ClassificationID,
		&rule.Priority,
		&rule.Enabled,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, rule)
}

func (s *Server) createRule(c *gin.Context) {
	var rule ClassificationRule
	if err := c.ShouldBindJSON(&rule); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	result, err := s.db.Exec(`
		INSERT INTO classification_rules (
			name, description, match_pattern, match_type,
			classification_id, priority, enabled
		) VALUES (?, ?, ?, ?, ?, ?, ?)
	`,
		rule.Name,
		rule.Description,
		rule.MatchPattern,
		rule.MatchType,
		rule.ClassificationID,
		rule.Priority,
		true, // Nova regra começa ativa
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	id, err := result.LastInsertId()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	rule.ID = int(id)
	rule.Enabled = true
	c.JSON(http.StatusCreated, rule)
}

func (s *Server) updateRule(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "ID inválido"})
		return
	}

	var rule ClassificationRule
	if err := c.ShouldBindJSON(&rule); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	_, err = s.db.Exec(`
		UPDATE classification_rules
		SET name = ?, description = ?, match_pattern = ?, match_type = ?,
			classification_id = ?, priority = ?, enabled = ?
		WHERE id = ?
	`,
		rule.Name,
		rule.Description,
		rule.MatchPattern,
		rule.MatchType,
		rule.ClassificationID,
		rule.Priority,
		rule.Enabled,
		id,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	rule.ID = id
	c.JSON(http.StatusOK, rule)
}

func (s *Server) deleteRule(c *gin.Context) {
	id, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "ID inválido"})
		return
	}

	_, err = s.db.Exec("DELETE FROM classification_rules WHERE id = ?", id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.Status(http.StatusNoContent)
}

func (s *Server) autoClassifyDocuments(c *gin.Context) {
	// Buscar regras de classificação
	rules, err := s.db.Query(`
		SELECT id, name, description, match_pattern, match_type, classification_id, priority
		FROM classification_rules
		WHERE enabled = 1
		ORDER BY priority DESC
	`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rules.Close()

	var classificationRules []struct {
		ID               int
		Name             string
		Description      string
		MatchPattern     string
		MatchType        string
		ClassificationID int
		Priority         int
	}

	for rules.Next() {
		var rule struct {
			ID               int
			Name             string
			Description      string
			MatchPattern     string
			MatchType        string
			ClassificationID int
			Priority         int
		}
		if err := rules.Scan(&rule.ID, &rule.Name, &rule.Description, &rule.MatchPattern, &rule.MatchType, &rule.ClassificationID, &rule.Priority); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		classificationRules = append(classificationRules, rule)
	}

	// Buscar todos os documentos não classificados com campos relevantes
	documents, err := s.db.Query(`
		SELECT f.id, f.path, f.match_pattern, f.match_type, f.search_param_type, f.search_param_value
		FROM files f
		LEFT JOIN document_classifications dc ON f.id = dc.file_id
		WHERE dc.id IS NULL
	`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer documents.Close()

	var classifiedCount int
	for documents.Next() {
		var doc struct {
			ID               int
			Path             string
			MatchPattern     sql.NullString
			MatchType        sql.NullString
			SearchParamType  sql.NullString
			SearchParamValue sql.NullString
		}

		if err := documents.Scan(&doc.ID, &doc.Path, &doc.MatchPattern, &doc.MatchType, &doc.SearchParamType, &doc.SearchParamValue); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		// Para cada documento, verificar todas as regras
		for _, rule := range classificationRules {
			var matches bool
			// Tentar matching com todos os campos relevantes
			fields := []string{doc.Path, doc.MatchPattern.String, doc.MatchType.String, doc.SearchParamType.String, doc.SearchParamValue.String}
			for _, field := range fields {
				if field == "" {
					continue
				}
				switch rule.MatchType {
				case "regex":
					re, err := regexp.Compile(rule.MatchPattern)
					if err != nil {
						continue
					}
					matches = re.MatchString(field)
				case "contains":
					matches = strings.Contains(strings.ToLower(field), strings.ToLower(rule.MatchPattern))
				case "exact":
					matches = strings.EqualFold(field, rule.MatchPattern)
				}
				if matches {
					_, err := s.db.Exec(`
						INSERT INTO document_classifications (file_id, classification_id, classified_by, classified_at)
						VALUES (?, ?, ?, datetime('now'))
					`, doc.ID, rule.ClassificationID, "auto-classifier")
					if err != nil {
						c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
						return
					}
					classifiedCount++
					break // Para de verificar as regras para este documento
				}
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"message": fmt.Sprintf("Classificados %d documentos automaticamente", classifiedCount),
	})
}

func (s *Server) removeClassification(c *gin.Context) {
	fileID, err := strconv.Atoi(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "ID inválido"})
		return
	}

	// Verificar se o arquivo existe
	var exists bool
	err = s.db.QueryRow("SELECT EXISTS(SELECT 1 FROM files WHERE id = ?)", fileID).Scan(&exists)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	if !exists {
		c.JSON(http.StatusNotFound, gin.H{"error": "Arquivo não encontrado"})
		return
	}

	// Remover a classificação
	_, err = s.db.Exec("DELETE FROM document_classifications WHERE file_id = ?", fileID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.Status(http.StatusNoContent)
}

// Rota para sugestões de classificação
func (s *Server) classificationSuggestions(c *gin.Context) {
	// Obter parâmetro de domínio da query string
	domain := c.Query("domain")

	// Buscar regras de classificação
	rules, err := s.db.Query(`
		SELECT id, name, description, match_pattern, match_type, classification_id, priority
		FROM classification_rules
		WHERE enabled = 1
		ORDER BY priority DESC
	`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rules.Close()

	var classificationRules []struct {
		ID               int
		Name             string
		Description      string
		MatchPattern     string
		MatchType        string
		ClassificationID int
		Priority         int
	}
	for rules.Next() {
		var rule struct {
			ID               int
			Name             string
			Description      string
			MatchPattern     string
			MatchType        string
			ClassificationID int
			Priority         int
		}
		if err := rules.Scan(&rule.ID, &rule.Name, &rule.Description, &rule.MatchPattern, &rule.MatchType, &rule.ClassificationID, &rule.Priority); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		classificationRules = append(classificationRules, rule)
	}

	// Buscar documentos com filtro de domínio
	var documentsQuery string
	var args []interface{}

	if domain != "" {
		documentsQuery = `
			SELECT f.id, f.path, f.match_pattern, f.match_type, f.search_param_type, f.search_param_value,
			       c.id as current_classification_id, c.name as current_classification_name, c.color as current_classification_color
			FROM files f
			LEFT JOIN document_classifications dc ON f.id = dc.file_id
			LEFT JOIN classifications c ON dc.classification_id = c.id
			WHERE f.domain = ?
		`
		args = append(args, domain)
	} else {
		documentsQuery = `
			SELECT f.id, f.path, f.match_pattern, f.match_type, f.search_param_type, f.search_param_value,
			       c.id as current_classification_id, c.name as current_classification_name, c.color as current_classification_color
			FROM files f
			LEFT JOIN document_classifications dc ON f.id = dc.file_id
			LEFT JOIN classifications c ON dc.classification_id = c.id
		`
	}

	documents, err := s.db.Query(documentsQuery, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer documents.Close()

	var suggestions []map[string]interface{}
	for documents.Next() {
		var doc struct {
			ID                         int
			Path                       string
			MatchPattern               sql.NullString
			MatchType                  sql.NullString
			SearchParamType            sql.NullString
			SearchParamValue           sql.NullString
			CurrentClassificationID    sql.NullInt64
			CurrentClassification      sql.NullString
			CurrentClassificationColor sql.NullString
		}
		if err := documents.Scan(
			&doc.ID,
			&doc.Path,
			&doc.MatchPattern,
			&doc.MatchType,
			&doc.SearchParamType,
			&doc.SearchParamValue,
			&doc.CurrentClassificationID,
			&doc.CurrentClassification,
			&doc.CurrentClassificationColor,
		); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		// Encontrar a melhor regra aplicável
		var bestRule *struct {
			ID               int
			Name             string
			Description      string
			MatchPattern     string
			MatchType        string
			ClassificationID int
			Priority         int
		}
		for _, rule := range classificationRules {
			fields := []string{doc.Path, doc.MatchPattern.String, doc.MatchType.String, doc.SearchParamType.String, doc.SearchParamValue.String}
			for _, field := range fields {
				if field == "" {
					continue
				}
				var matches bool
				switch rule.MatchType {
				case "regex":
					re, err := regexp.Compile(rule.MatchPattern)
					if err != nil {
						continue
					}
					matches = re.MatchString(field)
				case "contains":
					matches = strings.Contains(strings.ToLower(field), strings.ToLower(rule.MatchPattern))
				case "exact":
					matches = strings.EqualFold(field, rule.MatchPattern)
				}
				if matches {
					bestRule = &rule
					break
				}
			}
			if bestRule != nil {
				break
			}
		}

		var suggestedClassification map[string]interface{}
		var ruleName, ruleDescription string
		if bestRule != nil {
			var className, color string
			_ = s.db.QueryRow("SELECT name, color FROM classifications WHERE id = ?", bestRule.ClassificationID).Scan(&className, &color)
			suggestedClassification = map[string]interface{}{
				"id":    bestRule.ClassificationID,
				"name":  className,
				"color": color,
			}
			ruleName = bestRule.Name
			ruleDescription = bestRule.Description
		}

		suggestions = append(suggestions, map[string]interface{}{
			"id":   doc.ID,
			"path": doc.Path,
			"current_classification": map[string]interface{}{
				"id":    doc.CurrentClassificationID.Int64,
				"name":  doc.CurrentClassification.String,
				"color": doc.CurrentClassificationColor.String,
			},
			"suggested_classification": suggestedClassification,
			"rule_name":                ruleName,
			"rule_description":         ruleDescription,
		})
	}

	c.JSON(http.StatusOK, suggestions)
}

// Handlers para infraestrutura
func (s *Server) listInfrastructureHosts(c *gin.Context) {
	// Obter parâmetro de domínio da query string
	domain := c.Query("domain")

	hosts, err := database.GetInfrastructureHosts(s.db)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Filtrar por domínio se especificado
	if domain != "" {
		var filteredHosts []map[string]interface{}
		for _, host := range hosts {
			if hostDomain, ok := host["domain"].(string); ok && hostDomain == domain {
				filteredHosts = append(filteredHosts, host)
			}
		}
		c.JSON(http.StatusOK, filteredHosts)
	} else {
		c.JSON(http.StatusOK, hosts)
	}
}

func (s *Server) listInfrastructureUsers(c *gin.Context) {
	// Obter parâmetro de domínio da query string
	domain := c.Query("domain")

	users, err := database.GetInfrastructureUsers(s.db)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Filtrar por domínio se especificado
	if domain != "" {
		var filteredUsers []map[string]interface{}
		for _, user := range users {
			if userDomain, ok := user["domain"].(string); ok && userDomain == domain {
				filteredUsers = append(filteredUsers, user)
			}
		}
		c.JSON(http.StatusOK, filteredUsers)
	} else {
		c.JSON(http.StatusOK, users)
	}
}

func (s *Server) listInfrastructureShares(c *gin.Context) {
	// Obter parâmetro de domínio da query string
	domain := c.Query("domain")

	shares, err := database.GetInfrastructureShares(s.db)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Filtrar por domínio se especificado
	if domain != "" {
		var filteredShares []map[string]interface{}
		for _, share := range shares {
			if shareDomain, ok := share["domain"].(string); ok && shareDomain == domain {
				filteredShares = append(filteredShares, share)
			}
		}
		c.JSON(http.StatusOK, filteredShares)
	} else {
		c.JSON(http.StatusOK, shares)
	}
}

func (s *Server) listInfrastructureAccess(c *gin.Context) {
	// Obter parâmetro de domínio da query string
	domain := c.Query("domain")

	access, err := database.GetInfrastructureAccess(s.db)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Filtrar por domínio se especificado
	if domain != "" {
		var filteredAccess []map[string]interface{}
		for _, acc := range access {
			if accDomain, ok := acc["domain"].(string); ok && accDomain == domain {
				filteredAccess = append(filteredAccess, acc)
			}
		}
		c.JSON(http.StatusOK, filteredAccess)
	} else {
		c.JSON(http.StatusOK, access)
	}
}

func (s *Server) populateInfrastructure(c *gin.Context) {
	err := database.PopulateInfrastructureTables(s.db)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Infraestrutura atualizada com sucesso"})
}

// getNodeFiles returns files associated with a given host or share node.
// Query params: type=host|share, name=<label>, domain=<domain>
func (s *Server) getNodeFiles(c *gin.Context) {
	nodeType := c.Query("type")
	name := c.Query("name")
	domain := c.Query("domain")

	if nodeType != "host" && nodeType != "share" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "type must be 'host' or 'share'"})
		return
	}
	if name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name is required"})
		return
	}

	col := "f.host"
	if nodeType == "share" {
		col = "f.share"
	}

	query := fmt.Sprintf(`
		SELECT f.id, f.path, f.host, f.share, COALESCE(f.domain,'') as domain,
		       f.size, COALESCE(f.mod_time,'') as mod_time,
		       COALESCE(c.name,'') as class_name, COALESCE(c.color,'') as class_color
		FROM files f
		LEFT JOIN document_classifications dc ON f.id = dc.file_id
		LEFT JOIN classifications c ON dc.classification_id = c.id
		WHERE %s = ?`, col)
	args := []interface{}{name}
	if domain != "" {
		query += " AND f.domain = ?"
		args = append(args, domain)
	}
	query += " ORDER BY c.level ASC, f.path LIMIT 100"

	rows, err := s.db.Query(query, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	var files []map[string]interface{}
	for rows.Next() {
		var id int
		var path, host, share, domain2, modTime, className, classColor string
		var size int64
		if err := rows.Scan(&id, &path, &host, &share, &domain2, &size, &modTime, &className, &classColor); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		files = append(files, map[string]interface{}{
			"id": id, "path": path, "host": host, "share": share,
			"domain": domain2, "size": size, "mod_time": modTime,
			"classification_name": className, "classification_color": classColor,
		})
	}
	if files == nil {
		files = []map[string]interface{}{}
	}
	c.JSON(http.StatusOK, files)
}

// getNodeUserAccess returns access relationships for a given user node.
// Query params: username=<label>, domain=<domain>
func (s *Server) getNodeUserAccess(c *gin.Context) {
	username := c.Query("username")
	domain := c.Query("domain")

	if username == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "username is required"})
		return
	}

	query := `
		SELECT a.access_type, COALESCE(a.first_seen,'') as first_seen, COALESCE(a.last_seen,'') as last_seen,
		       CASE WHEN a.target_type='host' THEN h.host ELSE sh.name END as target_name,
		       a.target_type
		FROM infrastructure_access a
		JOIN infrastructure_users u ON a.user_id = u.id
		LEFT JOIN infrastructure_hosts h ON a.target_type='host' AND a.target_id = h.id
		LEFT JOIN infrastructure_shares sh ON a.target_type='share' AND a.target_id = sh.id
		WHERE u.username = ?`
	args := []interface{}{username}
	if domain != "" {
		query += " AND u.domain = ?"
		args = append(args, domain)
	}
	query += " ORDER BY a.access_type, target_name"

	rows, err := s.db.Query(query, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	defer rows.Close()

	var accesses []map[string]interface{}
	for rows.Next() {
		var accessType, firstSeen, lastSeen, targetName, targetType string
		if err := rows.Scan(&accessType, &firstSeen, &lastSeen, &targetName, &targetType); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}
		accesses = append(accesses, map[string]interface{}{
			"access_type": accessType, "first_seen": firstSeen,
			"last_seen": lastSeen, "target_name": targetName, "target_type": targetType,
		})
	}
	if accesses == nil {
		accesses = []map[string]interface{}{}
	}
	c.JSON(http.StatusOK, accesses)
}

func (s *Server) getReportData(c *gin.Context) {
	domain := c.Query("domain")
	data, err := database.GetReportData(s.db, domain)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, data)
}
