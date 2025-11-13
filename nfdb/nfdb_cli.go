package main

import (
	"bufio"
	"context"
	"database/sql"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
	"github.com/m0ng3sh3ll/NullFang/utils"
	_ "github.com/mattn/go-sqlite3"
	"github.com/sahilm/fuzzy"
)

var currentDomain string
var db *sql.DB
var shouldExit bool

type state int

const (
	stateDomainSelect state = iota
	statePrompt
	stateResult
	stateInputExtra state = iota + 100 // valor alto para não conflitar
	stateSuggest
	statePagination
)

type model struct {
	state          state
	domains        []string
	domainList     list.Model
	selectedDomain string
	input          textinput.Model
	result         string
	db             *sql.DB
	pendingCommand string   // para comandos que precisam de input extra
	inputLabel     string   // label do input extra
	suggestions    []string // sugestões para navegação
	suggestIndex   int      // índice selecionado na lista de sugestões
	// Pagination fields
	currentPage    int    // página atual
	totalPages     int    // total de páginas
	currentCommand string // comando atual sendo paginado
	pageSize       int    // tamanho da página
}

type listItem string

func (i listItem) Title() string       { return string(i) }
func (i listItem) Description() string { return "" }
func (i listItem) FilterValue() string { return string(i) }

// Lista de comandos para autocomplete
var autocompleteCommands = []string{
	"list files",
	"list credentials",
	"list hosts",
	"list shares",
	"list users",
	"list low-hanging-fruits",
	"list large-files",
	"find file ",
	"show history",
	"export files",
	"export lhf",
	"export credentials",
	"export all",
	"switch domain",
	"help",
	"exit",
}

// Subcomandos para autocomplete dinâmico
var listSubcommands = []string{
	"files",
	"credentials",
	"hosts",
	"shares",
	"users",
	"low-hanging-fruits",
	"large-files",
}
var exportSubcommands = []string{
	"files",
	"lhf",
	"credentials",
	"all",
}

func initialModel(domains []string, db *sql.DB) model {
	items := make([]list.Item, len(domains))
	for i, d := range domains {
		items[i] = listItem(d)
	}
	l := list.New(items, list.NewDefaultDelegate(), 40, 10)
	l.Title = "Select the domain"
	ti := textinput.New()
	ti.Placeholder = "Enter a command (ex: list files, exit)"
	ti.Focus()
	return model{
		state:       stateDomainSelect,
		domains:     domains,
		domainList:  l,
		input:       ti,
		db:          db,
		currentPage: 1,
		totalPages:  1,
		pageSize:    50,
	}
}

func (m model) Init() tea.Cmd {
	return nil
}

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch m.state {
	case stateDomainSelect:
		var cmd tea.Cmd
		m.domainList, cmd = m.domainList.Update(msg)
		switch msg := msg.(type) {
		case tea.KeyMsg:
			switch msg.String() {
			case "enter":
				if i, ok := m.domainList.SelectedItem().(listItem); ok {
					m.selectedDomain = string(i)
					m.state = statePrompt
				}
			case "ctrl+c", "q":
				return m, tea.Quit
			}
		}
		return m, cmd
	case statePrompt:
		var cmd tea.Cmd
		m.input, cmd = m.input.Update(msg)
		switch msg := msg.(type) {
		case tea.KeyMsg:
			switch msg.String() {
			case "enter":
				cmdStr := strings.TrimSpace(m.input.Value())
				if cmdStr == "exit" || cmdStr == "quit" {
					return m, tea.Quit
				}
				if strings.HasPrefix(cmdStr, "show history") {
					m.pendingCommand = cmdStr
					m.inputLabel = "Enter the filename to see the history: "
					m.input.SetValue("")
					m.state = stateInputExtra
					return m, nil
				}
				res := m.processCommand(cmdStr)
				if m.state == stateDomainSelect {
					m.input.SetValue("")
					return m, nil // não vai para stateResult
				}
				m.result = res
				// processCommand já define o estado corretamente (statePagination ou stateResult)
				// então não precisamos sobrescrever aqui
				if m.state != statePagination {
					m.state = stateResult
				}
				m.input.SetValue("")
			case "tab":
				current := strings.TrimSpace(m.input.Value())
				// Fuzzy para find file
				if strings.HasPrefix(current, "find file ") {
					pattern := strings.TrimSpace(current[len("find file "):])
					files := m.getFileNames(200)
					matches := fuzzy.Find(pattern, files)
					if len(matches) == 1 {
						m.input.SetValue("find file " + matches[0].Str)
					} else if len(matches) > 1 {
						sugs := make([]string, len(matches))
						for i, match := range matches {
							sugs[i] = match.Str
						}
						m.suggestions = sugs
						m.suggestIndex = 0
						m.state = stateSuggest
					}
					break
				}
				var candidates []string
				if strings.HasPrefix(current, "list ") {
					prefix := current[5:]
					candidates = make([]string, len(listSubcommands))
					for i, c := range listSubcommands {
						candidates[i] = "list " + c
					}
					pattern := prefix
					if pattern == "" {
						pattern = " " // força fuzzy sugerir todos
					}
					matches := fuzzy.Find(pattern, candidates)
					if len(matches) == 1 {
						m.input.SetValue(matches[0].Str)
					} else if len(matches) > 1 {
						sugs := make([]string, len(matches))
						for i, match := range matches {
							sugs[i] = match.Str
						}
						m.suggestions = sugs
						m.suggestIndex = 0
						m.state = stateSuggest
					}
					// Se não houver match, não faz nada
				} else if strings.HasPrefix(current, "export ") {
					prefix := current[7:]
					candidates = make([]string, len(exportSubcommands))
					for i, c := range exportSubcommands {
						candidates[i] = "export " + c
					}
					pattern := prefix
					if pattern == "" {
						pattern = " "
					}
					matches := fuzzy.Find(pattern, candidates)
					if len(matches) == 1 {
						m.input.SetValue(matches[0].Str)
					} else if len(matches) > 1 {
						sugs := make([]string, len(matches))
						for i, match := range matches {
							sugs[i] = match.Str
						}
						m.suggestions = sugs
						m.suggestIndex = 0
						m.state = stateSuggest
					}
				} else {
					pattern := current
					if pattern == "" {
						pattern = " "
					}
					matches := fuzzy.Find(pattern, autocompleteCommands)
					if len(matches) == 1 {
						m.input.SetValue(matches[0].Str)
					} else if len(matches) > 1 {
						sugs := make([]string, len(matches))
						for i, match := range matches {
							sugs[i] = match.Str
						}
						m.suggestions = sugs
						m.suggestIndex = 0
						m.state = stateSuggest
					}
				}
			case "ctrl+c", "q":
				return m, tea.Quit
			}
		}
		return m, cmd
	case stateResult:
		switch msg := msg.(type) {
		case tea.KeyMsg:
			switch msg.String() {
			case "enter":
				m.state = statePrompt
			case "ctrl+c", "q":
				return m, tea.Quit
			}
		}
		return m, nil
	case statePagination:
		switch msg := msg.(type) {
		case tea.KeyMsg:
			switch msg.String() {
			case "left", "h":
				if m.currentPage > 1 {
					m.currentPage--
					m.result = m.executeListCommand(m.currentCommand, m.currentPage)
				}
			case "right", "l":
				if m.currentPage < m.totalPages {
					m.currentPage++
					m.result = m.executeListCommand(m.currentCommand, m.currentPage)
				}
			case "enter", "esc", "q":
				m.state = statePrompt
				m.currentPage = 1
				m.totalPages = 1
				m.currentCommand = ""
			case "ctrl+c":
				return m, tea.Quit
			}
		}
		return m, nil
	case stateInputExtra:
		var cmd tea.Cmd
		m.input, cmd = m.input.Update(msg)
		switch msg := msg.(type) {
		case tea.KeyMsg:
			switch msg.String() {
			case "enter":
				if strings.HasPrefix(m.pendingCommand, "show history") {
					filename := strings.TrimSpace(m.input.Value())
					m.result = m.showHistory(filename)
					m.state = stateResult
					m.input.SetValue("")
					m.pendingCommand = ""
					return m, nil
				}
			case "tab":
				// Fuzzy autocomplete para nomes de arquivos reais no show history
				pattern := strings.TrimSpace(m.input.Value())
				files := m.getFileNames(200)
				matches := fuzzy.Find(pattern, files)
				if len(matches) == 1 {
					m.input.SetValue(matches[0].Str)
				} else if len(matches) > 1 {
					sugs := make([]string, len(matches))
					for i, match := range matches {
						sugs[i] = match.Str
					}
					m.result = "Suggestions:\n" + strings.Join(sugs, "\n")
					m.state = stateResult
				}
			}
		}
		return m, cmd
	case stateSuggest:
		switch msg := msg.(type) {
		case tea.KeyMsg:
			switch msg.String() {
			case "tab", "down", "j":
				if len(m.suggestions) > 0 {
					m.suggestIndex = (m.suggestIndex + 1) % len(m.suggestions)
				}
			case "up", "k":
				if len(m.suggestions) > 0 {
					m.suggestIndex = (m.suggestIndex - 1 + len(m.suggestions)) % len(m.suggestions)
				}
			case "enter":
				if len(m.suggestions) > 0 {
					m.input.SetValue(m.suggestions[m.suggestIndex])
				}
				m.suggestions = nil
				m.suggestIndex = 0
				m.state = statePrompt
			case "esc":
				m.suggestions = nil
				m.suggestIndex = 0
				m.state = statePrompt
			}
		}
		return m, nil
	}
	return m, nil
}

func (m model) View() string {
	switch m.state {
	case stateDomainSelect:
		return m.domainList.View()
	case statePrompt:
		return fmt.Sprintf("Domain selected: %s\n\n%s\n\n(enter to send, exit to quit)", m.selectedDomain, m.input.View())
	case stateResult:
		return fmt.Sprintf("Result:\n%s\n\n(enter to go back to prompt)", m.result)
	case stateInputExtra:
		return fmt.Sprintf("%s\n%s\n\n(enter to send, esc to cancel)", m.inputLabel, m.input.View())
	case stateSuggest:
		var sb strings.Builder
		sb.WriteString("Suggestions:\n")
		for i, s := range m.suggestions {
			if i == m.suggestIndex {
				sb.WriteString("> " + s + "\n")
			} else {
				sb.WriteString(" " + s + "\n")
			}
		}
		sb.WriteString("\n(TAB/↓/j for down, ↑/k for up, ENTER to select, ESC to cancel)")
		return sb.String()
	case statePagination:
		paginationInfo := fmt.Sprintf("\nPage %d of %d", m.currentPage, m.totalPages)
		navInfo := ""
		if m.totalPages > 1 {
			navInfo = "\n(←/h: previous page, →/l: next page, ENTER/ESC/q: back to prompt)"
		} else {
			navInfo = "\n(ENTER/ESC/q: back to prompt)"
		}
		return fmt.Sprintf("Result:\n%s%s%s", m.result, paginationInfo, navInfo)
	}
	return ""
}

// executeListCommand executes a list command with pagination
func (m *model) executeListCommand(cmd string, page int) string {
	cmd = strings.ToLower(cmd)
	switch {
	case cmd == "list files":
		return m.listFilesWithPagination(page)
	case cmd == "list credentials":
		return m.listCredentialsWithPagination(page)
	case cmd == "list hosts":
		return m.listHostsWithPagination(page)
	case cmd == "list shares":
		return m.listSharesWithPagination(page)
	case cmd == "list users":
		return m.listUsersWithPagination(page)
	case cmd == "list low-hanging-fruits":
		return m.listLowHangingFruitsWithPagination(page)
	case cmd == "list large-files":
		return m.listLargeFilesWithPagination(page)
	default:
		return fmt.Sprintf("Command not recognized: %s", cmd)
	}
}

// Comando simples: list files
func (m *model) processCommand(cmd string) string {
	cmdLower := strings.ToLower(cmd)
	switch {
	case cmdLower == "list files":
		result, totalPages := m.listFilesWithPaginationAndCount(1)
		m.currentCommand = cmdLower
		m.currentPage = 1
		m.totalPages = totalPages
		if totalPages > 1 {
			m.state = statePagination
		} else {
			m.state = stateResult
		}
		return result
	case cmdLower == "list credentials":
		result, totalPages := m.listCredentialsWithPaginationAndCount(1)
		m.currentCommand = cmdLower
		m.currentPage = 1
		m.totalPages = totalPages
		if totalPages > 1 {
			m.state = statePagination
		} else {
			m.state = stateResult
		}
		return result
	case cmdLower == "list hosts":
		result, totalPages := m.listHostsWithPaginationAndCount(1)
		m.currentCommand = cmdLower
		m.currentPage = 1
		m.totalPages = totalPages
		if totalPages > 1 {
			m.state = statePagination
		} else {
			m.state = stateResult
		}
		return result
	case cmdLower == "list shares":
		result, totalPages := m.listSharesWithPaginationAndCount(1)
		m.currentCommand = cmdLower
		m.currentPage = 1
		m.totalPages = totalPages
		if totalPages > 1 {
			m.state = statePagination
		} else {
			m.state = stateResult
		}
		return result
	case cmdLower == "list users":
		result, totalPages := m.listUsersWithPaginationAndCount(1)
		m.currentCommand = cmdLower
		m.currentPage = 1
		m.totalPages = totalPages
		if totalPages > 1 {
			m.state = statePagination
		} else {
			m.state = stateResult
		}
		return result
	case cmdLower == "list low-hanging-fruits":
		result, totalPages := m.listLowHangingFruitsWithPaginationAndCount(1)
		m.currentCommand = cmdLower
		m.currentPage = 1
		m.totalPages = totalPages
		if totalPages > 1 {
			m.state = statePagination
		} else {
			m.state = stateResult
		}
		return result
	case cmdLower == "list large-files":
		result, totalPages := m.listLargeFilesWithPaginationAndCount(1)
		m.currentCommand = cmdLower
		m.currentPage = 1
		m.totalPages = totalPages
		if totalPages > 1 {
			m.state = statePagination
		} else {
			m.state = stateResult
		}
		return result
	case strings.HasPrefix(cmdLower, "find file "):
		pattern := strings.TrimSpace(strings.TrimPrefix(cmdLower, "find file "))
		m.state = stateResult
		return m.findFile(pattern)
	case strings.HasPrefix(cmdLower, "export "):
		m.state = stateResult
		return m.exportCommand(cmdLower)
	case cmdLower == "switch domain":
		m.selectedDomain = ""
		m.input.SetValue("")
		m.state = stateDomainSelect
		return ""
	case cmdLower == "help":
		m.state = stateResult
		return m.helpText()
	default:
		m.state = stateResult
		return fmt.Sprintf("Command not recognized: %s", cmd)
	}
}

// Função utilitária para formatar tabelas bonitas
func formatTableBox(title string, headers []string, rows [][]string) string {
	border := "═"
	sep := "─"
	colWidths := make([]int, len(headers))
	for i, h := range headers {
		colWidths[i] = len(h)
	}
	for _, row := range rows {
		for i, cell := range row {
			if len(cell) > colWidths[i] {
				colWidths[i] = len(cell)
			}
		}
	}
	totalWidth := 1
	for _, w := range colWidths {
		totalWidth += w + 3
	}
	var sb strings.Builder
	sb.WriteString("╔" + strings.Repeat(border, totalWidth-2) + "╗\n")
	if title != "" {
		titleLine := padCenter(title, totalWidth-2)
		sb.WriteString("║" + titleLine + "║\n")
		sb.WriteString("╠" + strings.Repeat(border, totalWidth-2) + "╣\n")
	}
	sb.WriteString("║")
	for i, h := range headers {
		sb.WriteString(fmt.Sprintf(" %-*s │", colWidths[i], padCenter(h, colWidths[i])))
	}
	sb.WriteString("\n")
	sb.WriteString("╠" + strings.Repeat(sep, totalWidth-2) + "╣\n")
	for _, row := range rows {
		sb.WriteString("║")
		for i, cell := range row {
			sb.WriteString(fmt.Sprintf(" %-*s │", colWidths[i], cell))
		}
		sb.WriteString("\n")
	}
	sb.WriteString("╚" + strings.Repeat(border, totalWidth-2) + "╝\n")
	return sb.String()
}

func (m *model) countFiles() int {
	var count int
	query := `SELECT COUNT(*) FROM files WHERE LOWER(domain) = ?`
	err := m.db.QueryRowContext(context.Background(), query, strings.ToLower(m.selectedDomain)).Scan(&count)
	if err != nil {
		return 0
	}
	return count
}

func (m *model) listFiles() string {
	return m.listFilesWithPagination(1)
}

func (m *model) listFilesWithPagination(page int) string {
	offset := (page - 1) * m.pageSize
	query := "SELECT id, path, share, domain, user, size, mod_time, file_type, match_pattern, match_type, local_path, found_time, leet_speak, search_param_type, search_param_value FROM files WHERE LOWER(domain) = ? ORDER BY id DESC LIMIT ? OFFSET ?"
	rows, err := m.db.QueryContext(context.Background(), query, strings.ToLower(m.selectedDomain), m.pageSize, offset)
	if err != nil {
		return fmt.Sprintf("Error querying files: %v", err)
	}
	defer rows.Close()
	var data [][]string
	for rows.Next() {
		var id int
		var path, share, domain, user, fileType, modTime, matchPattern, matchType, localPath, foundTime, leetSpeak, searchParamType, searchParamValue string
		var size int64
		rows.Scan(&id, &path, &share, &domain, &user, &size, &modTime, &fileType, &matchPattern, &matchType, &localPath, &foundTime, &leetSpeak, &searchParamType, &searchParamValue)
		data = append(data, []string{
			fmt.Sprintf("%d", id), path, share, user, fmt.Sprintf("%d", size), modTime, fileType, matchPattern, matchType, localPath, foundTime, leetSpeak, searchParamType, searchParamValue,
		})
	}
	if len(data) == 0 {
		return "No results found for this query."
	}
	headers := []string{"ID", "File", "Share", "User", "Size", "ModTime", "FileType", "MatchPattern", "MatchType", "LocalPath", "FoundTime", "LeetSpeak", "SearchParamType", "SearchParamValue"}
	return formatTableBox("Files", headers, data)
}

func (m *model) listFilesWithPaginationAndCount(page int) (string, int) {
	result := m.listFilesWithPagination(page)
	total := m.countFiles()
	totalPages := (total + m.pageSize - 1) / m.pageSize
	if totalPages == 0 {
		totalPages = 1
	}
	return result, totalPages
}

func (m *model) countCredentials() int {
	var count int
	query := `SELECT COUNT(*) FROM domain_credentials WHERE LOWER(domain) = ? AND NOT (password_clear = '' AND password_hash = '' AND password_ticket = '')`
	err := m.db.QueryRowContext(context.Background(), query, strings.ToLower(m.selectedDomain)).Scan(&count)
	if err != nil {
		return 0
	}
	return count
}

func (m *model) listCredentials() string {
	return m.listCredentialsWithPagination(1)
}

func (m *model) listCredentialsWithPagination(page int) string {
	offset := (page - 1) * m.pageSize
	query := `SELECT domain, user, host, auth_method, password_clear, password_hash, password_ticket, found_time, isAdmin FROM domain_credentials WHERE LOWER(domain) = ? AND NOT (password_clear = '' AND password_hash = '' AND password_ticket = '') ORDER BY user, host LIMIT ? OFFSET ?`
	rows, err := m.db.QueryContext(context.Background(), query, strings.ToLower(m.selectedDomain), m.pageSize, offset)
	if err != nil {
		return fmt.Sprintf("Error querying credentials: %v", err)
	}
	defer rows.Close()
	var data [][]string
	for rows.Next() {
		var d, u, h, a, pc, ph, pt, ft, isAdmin string
		rows.Scan(&d, &u, &h, &a, &pc, &ph, &pt, &ft, &isAdmin)
		data = append(data, []string{d, u, h, a, pc, ph, pt, ft, isAdmin})
	}
	if len(data) == 0 {
		return "No credentials found for this domain"
	}
	headers := []string{"Domain", "User", "Host", "AuthMethod", "PasswordClear", "PasswordHash", "PasswordTicket", "FoundTime", "IsAdmin"}
	return formatTableBox("Credentials", headers, data)
}

func (m *model) listCredentialsWithPaginationAndCount(page int) (string, int) {
	result := m.listCredentialsWithPagination(page)
	total := m.countCredentials()
	totalPages := (total + m.pageSize - 1) / m.pageSize
	if totalPages == 0 {
		totalPages = 1
	}
	return result, totalPages
}

func (m *model) countHosts() int {
	var count int
	query := `SELECT COUNT(DISTINCT host) FROM files WHERE LOWER(domain) = ?`
	err := m.db.QueryRowContext(context.Background(), query, strings.ToLower(m.selectedDomain)).Scan(&count)
	if err != nil {
		return 0
	}
	return count
}

func (m *model) listHosts() string {
	return m.listHostsWithPagination(1)
}

func (m *model) listHostsWithPagination(page int) string {
	offset := (page - 1) * m.pageSize
	query := `SELECT DISTINCT host FROM files WHERE LOWER(domain) = ? ORDER BY host LIMIT ? OFFSET ?`
	rows, err := m.db.QueryContext(context.Background(), query, strings.ToLower(m.selectedDomain), m.pageSize, offset)
	if err != nil {
		return fmt.Sprintf("Error querying hosts: %v", err)
	}
	defer rows.Close()
	var data [][]string
	for rows.Next() {
		var host string
		rows.Scan(&host)
		data = append(data, []string{host})
	}
	if len(data) == 0 {
		return "No hosts found for this domain"
	}
	headers := []string{"Hosts"}
	return formatTableBox("Hosts", headers, data)
}

func (m *model) listHostsWithPaginationAndCount(page int) (string, int) {
	result := m.listHostsWithPagination(page)
	total := m.countHosts()
	totalPages := (total + m.pageSize - 1) / m.pageSize
	if totalPages == 0 {
		totalPages = 1
	}
	return result, totalPages
}

func (m *model) countShares() int {
	var count int
	query := `SELECT COUNT(DISTINCT share) FROM files WHERE LOWER(domain) = ?`
	err := m.db.QueryRowContext(context.Background(), query, strings.ToLower(m.selectedDomain)).Scan(&count)
	if err != nil {
		return 0
	}
	return count
}

func (m *model) listShares() string {
	return m.listSharesWithPagination(1)
}

func (m *model) listSharesWithPagination(page int) string {
	offset := (page - 1) * m.pageSize
	query := `SELECT DISTINCT share FROM files WHERE LOWER(domain) = ? ORDER BY share LIMIT ? OFFSET ?`
	rows, err := m.db.QueryContext(context.Background(), query, strings.ToLower(m.selectedDomain), m.pageSize, offset)
	if err != nil {
		return fmt.Sprintf("Error querying shares: %v", err)
	}
	defer rows.Close()
	var data [][]string
	for rows.Next() {
		var share string
		rows.Scan(&share)
		data = append(data, []string{share})
	}
	if len(data) == 0 {
		return "No shares found for this domain"
	}
	headers := []string{"Shares"}
	return formatTableBox("Shares", headers, data)
}

func (m *model) listSharesWithPaginationAndCount(page int) (string, int) {
	result := m.listSharesWithPagination(page)
	total := m.countShares()
	totalPages := (total + m.pageSize - 1) / m.pageSize
	if totalPages == 0 {
		totalPages = 1
	}
	return result, totalPages
}

func (m *model) countUsers() int {
	var count int
	query := `SELECT COUNT(DISTINCT user) FROM files WHERE LOWER(domain) = ?`
	err := m.db.QueryRowContext(context.Background(), query, strings.ToLower(m.selectedDomain)).Scan(&count)
	if err != nil {
		return 0
	}
	return count
}

func (m *model) listUsers() string {
	return m.listUsersWithPagination(1)
}

func (m *model) listUsersWithPagination(page int) string {
	offset := (page - 1) * m.pageSize
	query := `SELECT DISTINCT user FROM files WHERE LOWER(domain) = ? ORDER BY user LIMIT ? OFFSET ?`
	rows, err := m.db.QueryContext(context.Background(), query, strings.ToLower(m.selectedDomain), m.pageSize, offset)
	if err != nil {
		return fmt.Sprintf("Error querying users: %v", err)
	}
	defer rows.Close()
	var data [][]string
	for rows.Next() {
		var user string
		rows.Scan(&user)
		data = append(data, []string{user})
	}
	if len(data) == 0 {
		return "No users found for this domain"
	}
	headers := []string{"Users"}
	return formatTableBox("Users", headers, data)
}

func (m *model) listUsersWithPaginationAndCount(page int) (string, int) {
	result := m.listUsersWithPagination(page)
	total := m.countUsers()
	totalPages := (total + m.pageSize - 1) / m.pageSize
	if totalPages == 0 {
		totalPages = 1
	}
	return result, totalPages
}

// Helper function to count total records
func (m *model) countLowHangingFruits() int {
	var count int
	query := `SELECT COUNT(*) FROM low_hanging_fruit WHERE LOWER(domain) = ?`
	err := m.db.QueryRowContext(context.Background(), query, strings.ToLower(m.selectedDomain)).Scan(&count)
	if err != nil {
		return 0
	}
	return count
}

func (m *model) listLowHangingFruits() string {
	return m.listLowHangingFruitsWithPagination(1)
}

func (m *model) listLowHangingFruitsWithPagination(page int) string {
	offset := (page - 1) * m.pageSize
	query := `SELECT id, path, host, share, user, size, mod_time, match_pattern, match_type, scan_mode FROM low_hanging_fruit WHERE LOWER(domain) = ? ORDER BY id DESC LIMIT ? OFFSET ?`
	rows, err := m.db.QueryContext(context.Background(), query, strings.ToLower(m.selectedDomain), m.pageSize, offset)
	if err != nil {
		return fmt.Sprintf("Error querying low-hanging fruits: %v", err)
	}
	defer rows.Close()
	var data [][]string
	for rows.Next() {
		var id int
		var path, host, share, user, modTime, matchPattern, matchType, scanMode string
		var size int64
		rows.Scan(&id, &path, &host, &share, &user, &size, &modTime, &matchPattern, &matchType, &scanMode)
		data = append(data, []string{fmt.Sprintf("%d", id), path, host, share, user, fmt.Sprintf("%d", size), modTime, matchPattern, matchType, scanMode})
	}
	if len(data) == 0 {
		return "No low-hanging fruits found for this domain"
	}
	headers := []string{"ID", "Path", "Host", "Share", "User", "Size", "ModTime", "Pattern", "Type", "Mode"}
	return formatTableBox("Low Hanging Fruits", headers, data)
}

func (m *model) listLowHangingFruitsWithPaginationAndCount(page int) (string, int) {
	result := m.listLowHangingFruitsWithPagination(page)
	total := m.countLowHangingFruits()
	totalPages := (total + m.pageSize - 1) / m.pageSize
	if totalPages == 0 {
		totalPages = 1
	}
	return result, totalPages
}

func (m *model) countLargeFiles() int {
	var count int
	query := `SELECT COUNT(*) FROM low_hanging_fruit WHERE large_file = 1 AND LOWER(domain) = ?`
	err := m.db.QueryRowContext(context.Background(), query, strings.ToLower(m.selectedDomain)).Scan(&count)
	if err != nil {
		return 0
	}
	return count
}

func (m *model) listLargeFiles() string {
	return m.listLargeFilesWithPagination(1)
}

func (m *model) listLargeFilesWithPagination(page int) string {
	offset := (page - 1) * m.pageSize
	query := `SELECT l.id, l.path, l.host, l.share, l.user, l.size, l.mod_time, l.match_pattern, l.match_type, l.scan_mode, l.large_file FROM low_hanging_fruit l WHERE l.large_file = 1 AND LOWER(l.domain) = ? ORDER BY l.id DESC LIMIT ? OFFSET ?`
	rows, err := m.db.QueryContext(context.Background(), query, strings.ToLower(m.selectedDomain), m.pageSize, offset)
	if err != nil {
		return fmt.Sprintf("Error querying large files: %v", err)
	}
	defer rows.Close()
	var data [][]string
	for rows.Next() {
		var id int
		var path, host, share, user, modTime, matchPattern, matchType, scanMode string
		var size int64
		var largeFile bool
		rows.Scan(&id, &path, &host, &share, &user, &size, &modTime, &matchPattern, &matchType, &scanMode, &largeFile)
		data = append(data, []string{fmt.Sprintf("%d", id), path, host, share, user, fmt.Sprintf("%d", size), modTime, matchPattern, matchType, scanMode, fmt.Sprintf("%v", largeFile)})
	}
	if len(data) == 0 {
		return "No large files found for this domain"
	}
	headers := []string{"ID", "Path", "Host", "Share", "User", "Size", "ModTime", "Pattern", "Type", "Mode", "LargeFile"}
	return formatTableBox("Large Files", headers, data)
}

func (m *model) listLargeFilesWithPaginationAndCount(page int) (string, int) {
	result := m.listLargeFilesWithPagination(page)
	total := m.countLargeFiles()
	totalPages := (total + m.pageSize - 1) / m.pageSize
	if totalPages == 0 {
		totalPages = 1
	}
	return result, totalPages
}

func (m *model) findFile(pattern string) string {
	rows, err := m.db.QueryContext(context.Background(), "SELECT id, path, host, share, size, mod_time, local_path FROM files WHERE LOWER(domain) = ? AND path LIKE ? ORDER BY id DESC LIMIT 100", strings.ToLower(m.selectedDomain), "%"+pattern+"%")
	if err != nil {
		return fmt.Sprintf("Error querying large files: %v", err)
	}
	defer rows.Close()
	var data [][]string
	for rows.Next() {
		var id int
		var path, host, share, localPath string
		var size int64
		var modTime string
		rows.Scan(&id, &path, &host, &share, &size, &modTime, &localPath)
		data = append(data, []string{fmt.Sprintf("%d", id), path, host, share, fmt.Sprintf("%d", size), modTime, localPath})
	}
	if len(data) == 0 {
		return "No file found for that pattern."
	}
	headers := []string{"ID", "Path", "Host", "Share", "Size", "ModTime", "LocalPath"}
	return formatTableBox("Files found", headers, data)
}

func (m *model) showHistory(filename string) string {
	ctx := context.Background()
	rows, err := m.db.QueryContext(ctx, "SELECT id, parent_id, mod_time, size, local_path FROM files WHERE LOWER(domain) = ? AND path LIKE ? ORDER BY id DESC", strings.ToLower(m.selectedDomain), "%"+filename+"%")
	if err != nil {
		return fmt.Sprintf("Error querying file history: %v", err)
	}
	defer rows.Close()
	var results []struct {
		ID        int64
		ParentID  sql.NullInt64
		ModTime   string
		Size      int64
		LocalPath string
	}
	for rows.Next() {
		var id int64
		var parentID sql.NullInt64
		var modTime string
		var size int64
		var localPath string
		rows.Scan(&id, &parentID, &modTime, &size, &localPath)
		results = append(results, struct {
			ID        int64
			ParentID  sql.NullInt64
			ModTime   string
			Size      int64
			LocalPath string
		}{id, parentID, modTime, size, localPath})
	}
	if len(results) == 0 {
		return "No version history found for that file."
	}
	var data [][]string
	for _, r := range results {
		pid := ""
		if r.ParentID.Valid {
			pid = fmt.Sprintf("%d", r.ParentID.Int64)
		}
		modTimeStr := r.ModTime
		if t, err := time.Parse(time.RFC3339, r.ModTime); err == nil {
			modTimeStr = t.Local().Format("2006-01-02 15:04:05")
		}
		data = append(data, []string{fmt.Sprintf("%d", r.ID), pid, modTimeStr, fmt.Sprintf("%d", r.Size), r.LocalPath})
	}
	headers := []string{"ID", "ParentID", "ModTime", "Size", "LocalPath"}
	return formatTableBox("File history", headers, data) + fmt.Sprintf("\nFound %d version(s) for that file.\n", len(results))
}

func (m *model) exportCommand(cmd string) string {
	args := strings.Fields(cmd)
	if len(args) < 2 {
		return "Usage: export files|lhf|credentials|all [to <file>]"
	}
	tipo := args[1]
	outFile := ""
	for i := 2; i < len(args); i++ {
		if args[i] == "to" && i+1 < len(args) {
			outFile = args[i+1]
			break
		}
	}
	if outFile == "" {
		outFile = getExportFilename(tipo)
	}
	var err error
	switch tipo {
	case "files":
		err = m.exportFiles(outFile)
	case "lhf":
		err = m.exportLHF(outFile)
	case "credentials":
		err = m.exportCredentials(outFile)
	case "all":
		err = m.exportAll(outFile)
	default:
		return "Unknown export type. Use: files, lhf, credentials or all."
	}
	if err != nil {
		return fmt.Sprintf("Error exporting: %v", err)
	}
	return fmt.Sprintf("Export completed: %s", outFile)
}

func (m *model) exportFiles(outFile string) error {
	files, err := exportFilesTable(m.db)
	if err != nil {
		return err
	}
	if len(files) == 0 {
		return fmt.Errorf("No results to export.")
	}
	f, err := os.Create(outFile)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(files)
}

func (m *model) exportLHF(outFile string) error {
	lhf, err := exportLHFTable(m.db)
	if err != nil {
		return err
	}
	if len(lhf) == 0 {
		return fmt.Errorf("No results to export.")
	}
	f, err := os.Create(outFile)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(lhf)
}

func (m *model) exportCredentials(outFile string) error {
	creds, err := exportCredentialsTable(m.db)
	if err != nil {
		return err
	}
	if len(creds) == 0 {
		return fmt.Errorf("No results to export.")
	}
	f, err := os.Create(outFile)
	if err != nil {
		return err
	}
	defer f.Close()
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(creds)
}

func (m *model) exportAll(outFile string) error {
	files, err := exportFilesTable(m.db)
	if err != nil {
		return err
	}
	lhf, err := exportLHFTable(m.db)
	if err != nil {
		return err
	}
	creds, err := exportCredentialsTable(m.db)
	if err != nil {
		return err
	}
	if len(files) == 0 && len(lhf) == 0 && len(creds) == 0 {
		return fmt.Errorf("No results to export.")
	}
	f, err := os.Create(outFile)
	if err != nil {
		return err
	}
	defer f.Close()
	result := map[string]interface{}{
		"files":             files,
		"low_hanging_fruit": lhf,
		"credentials":       creds,
	}
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}

func (m *model) helpText() string {
	return `Commands available:
  list files                 - List all copied files
  list credentials           - List all credentials
  list hosts                 - List all hosts
  list shares                - List all shares
  list users                 - List all users
  list low-hanging-fruits    - List easy files/fruits
  list large-files           - List large files
  find file <pattern>         - Search files by name
  show history               - Show file version history
  export files|lhf|credentials|all [to <file>] - Export data to JSON
  switch domain              - Switch domain
  help                       - Show this help message
  exit                       - Exit the CLI`
}

func getDomains(db *sql.DB) ([]string, error) {
	rows, err := db.Query(`
        SELECT DISTINCT domain FROM (
            SELECT domain FROM domain_credentials
            UNION
            SELECT domain FROM files
        ) WHERE domain IS NOT NULL AND TRIM(domain) != ''
        ORDER BY domain
    `)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var domains []string
	for rows.Next() {
		var domain string
		rows.Scan(&domain)
		domains = append(domains, domain)
	}
	return domains, nil
}

func main() {
	dbPath := flag.String("db-path", utils.GetDefaultDBPath(), "Path to the SQLite database file (default: database/nfdb.db)")
	flag.Parse()

	db, err := sql.Open("sqlite3", *dbPath)
	if err != nil {
		fmt.Printf("Error opening database: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()
	domains, err := getDomains(db)
	if err != nil || len(domains) == 0 {
		fmt.Println("No domains found in the database.")
		os.Exit(1)
	}
	p := tea.NewProgram(initialModel(domains, db))
	if _, err := p.Run(); err != nil {
		fmt.Printf("Erro: %v\n", err)
		os.Exit(1)
	}
}

func printTableBox(title string, headers []string, rows [][]string) {
	border := "═"
	sep := "─"
	// Calcula o tamanho de cada coluna
	colWidths := make([]int, len(headers))
	for i, h := range headers {
		colWidths[i] = len(h)
	}
	for _, row := range rows {
		for i, cell := range row {
			if len(cell) > colWidths[i] {
				colWidths[i] = len(cell)
			}
		}
	}
	// Calcula largura total da tabela
	totalWidth := 1 // borda esquerda
	for _, w := range colWidths {
		totalWidth += w + 3 // espaço + borda
	}
	// Topo
	fmt.Printf("╔%s╗\n", strings.Repeat(border, totalWidth-2))
	if title != "" {
		fmt.Printf("║%s║\n", padCenter(title, totalWidth-2))
		fmt.Printf("╠%s╣\n", strings.Repeat(border, totalWidth-2))
	}
	// Cabeçalho
	fmt.Print("║")
	for i, h := range headers {
		fmt.Printf(" %-*s │", colWidths[i], padCenter(h, colWidths[i]))
	}
	fmt.Println()
	fmt.Printf("╠%s╣\n", strings.Repeat(sep, totalWidth-2))
	// Linhas
	for _, row := range rows {
		fmt.Print("║")
		for i, cell := range row {
			fmt.Printf(" %-*s │", colWidths[i], cell)
		}
		fmt.Println()
	}
	fmt.Printf("╚%s╝\n", strings.Repeat(border, totalWidth-2))
}

func printDBCLIBox(title string, lines []string, width int) {
	border := "═"
	fmt.Printf("╔%s╗\n", strings.Repeat(border, width-2))
	if title != "" {
		fmt.Printf("║%s║\n", padCenter(title, width-2))
		fmt.Printf("╠%s╣\n", strings.Repeat(border, width-2))
	}
	for _, line := range lines {
		for len(line) > 0 {
			var part string
			if utf8.RuneCountInString(line) > width-2 {
				part = string([]rune(line)[:width-2])
				line = string([]rune(line)[width-2:])
			} else {
				part = line
				line = ""
			}
			fmt.Printf("║ %-*s ║\n", width-4, part)
		}
	}
	fmt.Printf("╚%s╝\n", strings.Repeat(border, width-2))
}
func padCenter(s string, width int) string {
	if len(s) >= width {
		return s
	}
	padding := width - len(s)
	left := padding / 2
	right := padding - left
	return strings.Repeat(" ", left) + s + strings.Repeat(" ", right)
}

func promptForDomain(db *sql.DB) string {
	rows, err := db.Query(`
        SELECT DISTINCT domain FROM (
            SELECT domain FROM domain_credentials
            UNION
            SELECT domain FROM files
        ) WHERE domain IS NOT NULL AND TRIM(domain) != ''
        ORDER BY domain
    `)
	if err != nil {
		fmt.Println("Error querying domains:", err)
		os.Exit(1)
	}
	defer rows.Close()
	var domains []string
	for rows.Next() {
		var domain string
		rows.Scan(&domain)
		domains = append(domains, domain)
	}
	if len(domains) == 0 {
		fmt.Println("No domains found in the database.")
		os.Exit(1)
	}
	fmt.Println("Available domains:")
	for i, d := range domains {
		fmt.Printf("  [%d] %s\n", i+1, d)
	}
	reader := bufio.NewReader(os.Stdin)
	for {
		fmt.Print("Select the domain number to access: ")
		input, err := reader.ReadString('\n')
		if err != nil {
			fmt.Println("\n[!] Error reading input. Exiting...")
			os.Exit(1)
		}
		input = strings.TrimSpace(input)
		if input == "" {
			fmt.Println("Invalid selection. Please enter a valid number.")
			continue
		}
		choice, err := strconv.Atoi(input)
		if err == nil && choice > 0 && choice <= len(domains) {
			return domains[choice-1]
		}
		fmt.Println("Invalid selection. Please enter a valid number.")
	}
}

func checkIncompleteFilters(filters []string, usage string) bool {
	for i := 0; i < len(filters); i++ {
		switch filters[i] {
		case "user", "host", "page":
			if i+1 >= len(filters) || strings.HasPrefix(filters[i+1], "-") {
				fmt.Printf("Missing value for filter '%s'.\n", filters[i])
				fmt.Println("Usage:", usage)
				return true
			}
			i++ // skip value
		}
	}
	return false
}

func executor(in string) {
	line := strings.TrimSpace(in)
	if line == "" {
		return
	}
	args := strings.Fields(line)
	cmd := strings.ToLower(args[0])

	switch cmd {
	case "exit", "quit":
		fmt.Println("Exiting...")
		os.Exit(0)
	case "help":
	case "list":
		if len(args) < 2 {
			fmt.Println("Usage: list files|credentials|hosts|shares|users|large-files")
			return
		}
		subcmd := strings.ToLower(args[1])
		filters := args[2:]
		var usage string
		switch subcmd {
		case "files":
			usage = "list files [user <username>] [host <host>] [page <n>]"
		case "credentials":
			usage = "list credentials [user <username>] [host <host>] [page <n>]"
		case "hosts":
			usage = "list hosts [page <n>]"
		case "shares":
			usage = "list shares [host <host>] [page <n>]"
		case "users":
			usage = "list users [host <host>] [page <n>]"
		case "low-hanging-fruits":
			usage = "list low-hanging-fruits [user <username>] [host <host>] [page <n>]"
		case "large-files":
			usage = "list large-files [user <username>] [host <host>] [page <n>]"
		}
		if usage != "" && checkIncompleteFilters(filters, usage) {
			return
		}
		switch subcmd {
		case "files":
			listFiles(db, filters...)
		case "credentials":
			ListCredentials(db, filters...)
		case "hosts":
			listHosts(db, filters...)
		case "shares":
			listShares(db, filters...)
		default:
			fmt.Println("Unknown option for list:", args[1])
		}
	case "find":
		if len(args) < 3 || args[1] != "file" {
			fmt.Println("Usage: find file <pattern>")
			return
		}
	case "show":
		if len(args[1]) < 2 || args[1] != "history" {
			fmt.Println("Usage: show history")
			return
		}
	case "export":
		if len(args) < 2 {
			fmt.Println("Usage: export files|lhf|credentials|all [page <n>]")
			return
		}
		subcmd := strings.ToLower(args[1])
		filters := args[2:]
		var usage string
		switch subcmd {
		case "files":
			usage = "export files [page <n>]"
		case "lhf":
			usage = "export lhf [page <n>]"
		case "credentials":
			usage = "export credentials [page <n>]"
		case "all":
			usage = "export all [page <n>]"
		}
		if usage != "" && checkIncompleteFilters(filters, usage) {
			return
		}
		switch subcmd {
		case "files":
			exportFilesCmd(db, filters...)
		case "lhf":
			exportLHFCmd(db, filters...)
		case "credentials":
			exportCredentialsCmd(db, filters...)
		case "all":
			exportAllCmd(db, filters...)
		default:
			fmt.Println("Unknown option for export:", args[1])
		}
	case "switch":
		if len(args) < 2 || args[1] != "domain" {
			fmt.Println("Usage: switch domain")
			return
		}
		newDomain := selectDomainInteractive(db)
		if newDomain != "" {
			currentDomain = newDomain
			fmt.Printf("Switched to domain: %s\n", currentDomain)
		}
	default:
		fmt.Println("Unknown command. Type 'help' for help.")
	}
}

func selectDomainInteractive(db *sql.DB) string {
	rows, err := db.Query(`
        SELECT DISTINCT domain FROM (
            SELECT domain FROM domain_credentials
            UNION
            SELECT domain FROM files
        ) WHERE domain IS NOT NULL AND TRIM(domain) != ''
        ORDER BY domain
    `)
	if err != nil {
		fmt.Println("Error querying domains:", err)
		return ""
	}
	defer rows.Close()
	var domains []string
	for rows.Next() {
		var domain string
		rows.Scan(&domain)
		domains = append(domains, domain)
	}
	if len(domains) == 0 {
		fmt.Println("No domains found in the database.")
		return ""
	}
	fmt.Println("Available domains:")
	for i, d := range domains {
		fmt.Printf("  [%d] %s\n", i+1, d)
	}
	for {
		fmt.Print("Select the domain number to switch: ")
		var choice int
		_, err := fmt.Scanln(&choice)
		if err == nil && choice > 0 && choice <= len(domains) {
			return domains[choice-1]
		}
		fmt.Println("Invalid selection. Please enter a valid number.")
	}
}

// Função utilitária para parsing de filtros opcionais
func parseFilters(args []string) map[string]string {
	filters := make(map[string]string)
	for i := 0; i < len(args)-1; i += 2 {
		key := strings.ToLower(args[i])
		value := args[i+1]
		filters[key] = value
	}
	return filters
}

func ListCredentials(db *sql.DB, filters ...string) {
	domain := currentDomain
	filterMap := parseFilters(filters)
	user := filterMap["user"]
	host := filterMap["host"]

	query := "SELECT DISTINCT domain, user, host, auth_method, password_clear, password_hash, password_ticket, found_time FROM domain_credentials WHERE LOWER(domain) = ?"
	var conds []string
	var args []interface{}
	args = append(args, strings.ToLower(domain))
	if user != "" {
		conds = append(conds, "LOWER(user) = ?")
		args = append(args, strings.ToLower(user))
	}
	if host != "" {
		conds = append(conds, "LOWER(host) = ?")
		args = append(args, strings.ToLower(host))
	}
	conds = append(conds, "NOT (password_clear = '' AND password_hash = '' AND password_ticket = '')")
	if len(conds) > 0 {
		query += " AND " + strings.Join(conds, " AND ")
	}
	// query += " ORDER BY domain, user"

	rows, err := db.Query(query, args...)
	if err != nil {
		fmt.Println("Error querying credentials:", err)
		return
	}
	defer rows.Close()

	headers := []string{"Domain", "User", "Host", "AuthMethod", "PasswordClear", "PasswordHash", "PasswordTicket", "FoundTime"}
	var data [][]string
	for rows.Next() {
		var d, h, u, a, pc, ph, pt, ft string
		rows.Scan(&d, &h, &u, &a, &pc, &ph, &pt, &ft)
		data = append(data, []string{d, h, u, a, pc, ph, pt, ft})
	}
	printTableBox("Credentials", headers, data)
}

func listFiles(db *sql.DB, filters ...string) {
	domain := currentDomain
	filterMap := parseFilters(filters)
	user := filterMap["user"]
	host := filterMap["host"]
	page := 1
	if p, ok := filterMap["page"]; ok {
		if n, err := strconv.Atoi(p); err == nil && n > 0 {
			page = n
		}
	}
	limit := 50
	offset := (page - 1) * limit

	query := "SELECT id, path, share, domain, user, size, mod_time, file_type, match_pattern, match_type, local_path, leet_speak, search_param_type, search_param_value, parent_id FROM files WHERE LOWER(domain) = ?"
	var args []interface{}
	args = append(args, strings.ToLower(domain))
	if user != "" {
		query += " AND LOWER(user) = ?"
		args = append(args, strings.ToLower(user))
	}
	if host != "" {
		query += " AND LOWER(host) = ?"
		args = append(args, strings.ToLower(host))
	}
	query += fmt.Sprintf(" ORDER BY id DESC LIMIT %d OFFSET %d", limit, offset)

	rows, err := db.QueryContext(context.Background(), query, args...)
	if err != nil {
		fmt.Println("Error querying files:", err)
		return
	}
	defer rows.Close()

	parentCount := make(map[int]int)
	allIDs := make(map[int]struct{})
	parentIDs := make(map[int]int)
	var fileRows []struct {
		ID                                                                                                                    int
		Path, Share, Domain, User, FileType, MatchPattern, MatchType, LocalPath, LeetSpeak, SearchParamType, SearchParamValue string
		Size                                                                                                                  int64
		ModTime                                                                                                               string
		ParentID                                                                                                              sql.NullInt64
	}
	for rows.Next() {
		var r struct {
			ID                                                                                                                    int
			Path, Share, Domain, User, FileType, MatchPattern, MatchType, LocalPath, LeetSpeak, SearchParamType, SearchParamValue string
			Size                                                                                                                  int64
			ModTime                                                                                                               string
			ParentID                                                                                                              sql.NullInt64
		}
		rows.Scan(&r.ID, &r.Path, &r.Share, &r.Domain, &r.User, &r.Size, &r.ModTime, &r.FileType, &r.MatchPattern, &r.MatchType, &r.LocalPath, &r.LeetSpeak, &r.SearchParamType, &r.SearchParamValue, &r.ParentID)
		fileRows = append(fileRows, r)
		allIDs[r.ID] = struct{}{}
		if r.ParentID.Valid {
			parentID := int(r.ParentID.Int64)
			parentCount[parentID]++
			parentIDs[r.ID] = parentID
		}
	}

	if len(fileRows) == 0 {
		fmt.Println("No results found for this query.")
		return
	}

	var data [][]string
	for _, r := range fileRows {
		versionTag := "base"
		originalID := "-"
		versionsCount := "-"
		if r.ParentID.Valid {
			versionTag = "snapshot"
			originalID = fmt.Sprintf("%d", int(r.ParentID.Int64))
		} else {
			if c, ok := parentCount[r.ID]; ok && c > 0 {
				versionsCount = fmt.Sprintf("%d", c)
			}
		}
		truncLocalPath := r.LocalPath
		sep := string(os.PathSeparator)
		parts := strings.Split(r.LocalPath, sep)
		if len(parts) > 3 {
			truncLocalPath = strings.Join(parts[:3], sep) + sep + "..."
		}
		modTimeStr := r.ModTime
		if t, err := time.Parse(time.RFC3339, r.ModTime); err == nil {
			modTimeStr = t.Local().Format("2006-01-02 15:04:05")
		}
		// Truncar match_pattern se for muito grande
		truncMatchPattern := r.MatchPattern
		if len(truncMatchPattern) > 40 {
			truncMatchPattern = truncMatchPattern[:40] + "..."
		}
		data = append(data, []string{fmt.Sprintf("%d", r.ID), r.Path, versionTag, originalID, versionsCount, r.Share, r.Domain, r.User, fmt.Sprintf("%d", r.Size), modTimeStr, r.FileType, truncMatchPattern, r.MatchType, truncLocalPath, r.LeetSpeak, r.SearchParamType, r.SearchParamValue})
	}
	if len(data) == limit {
		fmt.Printf("Showing page %d. There may be more results. Use 'page %d' to see the next page.\n", page, page+1)
	}
	printTableBox("Files Extracted", []string{"ID", "File", "Version", "OriginalID", "VersionsCount", "Share", "Domain", "User", "Size", "LastModified", "FileType", "SearchPattern", "MatchType", "LocalPath", "LeetSpeak", "SearchParamType", "SearchParamValue"}, data)
}

func listHosts(db *sql.DB, filters ...string) {
	domain := currentDomain
	filterMap := parseFilters(filters)
	page := 1
	if p, ok := filterMap["page"]; ok {
		if n, err := strconv.Atoi(p); err == nil && n > 0 {
			page = n
		}
	}
	limit := 50
	offset := (page - 1) * limit

	query := "SELECT DISTINCT host FROM files WHERE LOWER(domain) = ? ORDER BY host LIMIT ? OFFSET ?"
	var args []interface{}
	args = append(args, strings.ToLower(domain), limit, offset)

	rows, err := db.QueryContext(context.Background(), query, args...)
	if err != nil {
		fmt.Println("Error querying hosts:", err)
		return
	}
	defer rows.Close()
	var data [][]string
	for rows.Next() {
		var host string
		rows.Scan(&host)
		data = append(data, []string{host})
	}
	if len(data) == 0 {
		fmt.Println("No results found for this query.")
		return
	}
	if len(data) == limit {
		fmt.Printf("Showing page %d. There may be more results. Use 'page %d' to see the next page.\n", page, page+1)
	}
	printTableBox("List of found", []string{"Hosts"}, data)
}

func listShares(db *sql.DB, filters ...string) {
	domain := currentDomain
	filterMap := parseFilters(filters)
	host := filterMap["host"]

	query := "SELECT DISTINCT share FROM files WHERE LOWER(domain) = ?"
	var args []interface{}
	args = append(args, strings.ToLower(domain))
	if host != "" {
		query += " AND LOWER(host) = ?"
		args = append(args, strings.ToLower(host))
	}
	query += " ORDER BY share"

	rows, err := db.QueryContext(context.Background(), query, args...)
	if err != nil {
		fmt.Println("Error querying shares:", err)
		return
	}
	defer rows.Close()
	var data [][]string
	for rows.Next() {
		var share string
		rows.Scan(&share)
		data = append(data, []string{share})
	}
	printTableBox("List of found", []string{"Shares"}, data)
}

func showHistory(db *sql.DB, _ string) {
	ctx := context.Background()
	fmt.Print("Enter the file name to view its history: ")
	var filename string
	fmt.Scanln(&filename)
	rows, err := db.QueryContext(ctx, "SELECT id, parent_id, mod_time, size, local_path FROM files WHERE LOWER(domain) = ? AND path LIKE ? ORDER BY id DESC", strings.ToLower(currentDomain), "%"+filename+"%")
	if err != nil {
		fmt.Println("Error searching files:", err)
		return
	}
	defer rows.Close()
	var results []struct {
		ID        int64
		ParentID  sql.NullInt64
		ModTime   string
		Size      int64
		LocalPath string
	}
	for rows.Next() {
		var id int64
		var parentID sql.NullInt64
		var modTime string
		var size int64
		var localPath string
		rows.Scan(&id, &parentID, &modTime, &size, &localPath)
		results = append(results, struct {
			ID        int64
			ParentID  sql.NullInt64
			ModTime   string
			Size      int64
			LocalPath string
		}{id, parentID, modTime, size, localPath})
	}
	if len(results) == 0 {
		fmt.Println("No version history found for this file.")
		return
	}
	var data [][]string
	for _, r := range results {
		pid := ""
		if r.ParentID.Valid {
			pid = fmt.Sprintf("%d", r.ParentID.Int64)
		}
		modTimeStr := r.ModTime
		if t, err := time.Parse(time.RFC3339, r.ModTime); err == nil {
			modTimeStr = t.Local().Format("2006-01-02 15:04:05")
		}
		data = append(data, []string{fmt.Sprintf("%d", r.ID), pid, modTimeStr, fmt.Sprintf("%d", r.Size), r.LocalPath})
	}
	printTableBox("File history", []string{"ID", "ParentID", "ModTime", "Size", "LocalPath"}, data)
	fmt.Printf("Found %d version(s) for this file.\n", len(results))
}

type FileRow struct {
	ID           int    `json:"id"`
	Path         string `json:"path"`
	Host         string `json:"host"`
	Share        string `json:"share"`
	Domain       string `json:"domain"`
	User         string `json:"user"`
	Size         int64  `json:"size"`
	ModTime      string `json:"mod_time"`
	FileType     string `json:"file_type"`
	MatchPattern string `json:"match_pattern"`
	MatchType    string `json:"match_type"`
	//Hash             string `json:"hash"`
	LocalPath        string `json:"local_path"`
	SizeFormatted    string `json:"size_formatted"`
	LargeFile        bool   `json:"large_file"`
	LeetSpeak        bool   `json:"leet_speak"`
	SearchParamType  string `json:"search_param_type"`
	SearchParamValue string `json:"search_param_value"`
	ParentID         *int   `json:"parent_id,omitempty"`
	FoundTime        string `json:"found_time"`
}

type LHFRow struct {
	ID      int    `json:"id"`
	Path    string `json:"path"`
	Host    string `json:"host"`
	Share   string `json:"share"`
	Domain  string `json:"domain"`
	User    string `json:"user"`
	Size    int64  `json:"size"`
	ModTime string `json:"mod_time"`
	//Hash          string `json:"hash"`
	MatchPattern  string `json:"match_pattern"`
	MatchType     string `json:"match_type"`
	SizeFormatted string `json:"size_formatted"`
	ScanMode      string `json:"scan_mode"`
	LargeFile     bool   `json:"large_file"`
}

type CredentialRow struct {
	Domain         string `json:"domain"`
	User           string `json:"user"`
	Host           string `json:"host"`
	AuthMethod     string `json:"auth_method"`
	PasswordClear  string `json:"password_clear"`
	PasswordHash   string `json:"password_hash"`
	PasswordTicket string `json:"password_ticket"`
	FoundTime      string `json:"found_time"`
	IsAdmin        bool   `json:"is_admin"`
}

func exportFilesTable(db *sql.DB, filters ...string) ([]FileRow, error) {
	filterMap := parseFilters(filters)
	page := 1
	if p, ok := filterMap["page"]; ok {
		if n, err := strconv.Atoi(p); err == nil && n > 0 {
			page = n
		}
	}
	limit := 50
	offset := (page - 1) * limit
	query := `SELECT id, path, host, share, domain, user, size, mod_time, file_type, match_pattern, match_type, local_path, size_formatted, large_file, leet_speak, search_param_type, search_param_value, parent_id, found_time FROM files WHERE LOWER(domain) = ? ORDER BY id LIMIT ? OFFSET ?`
	rows, err := db.Query(query, strings.ToLower(currentDomain), limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var files []FileRow
	for rows.Next() {
		var r FileRow
		var parentID sql.NullInt64
		if err := rows.Scan(&r.ID, &r.Path, &r.Host, &r.Share, &r.Domain, &r.User, &r.Size, &r.ModTime, &r.FileType, &r.MatchPattern, &r.MatchType, &r.LocalPath, &r.SizeFormatted, &r.LargeFile, &r.LeetSpeak, &r.SearchParamType, &r.SearchParamValue, &parentID, &r.FoundTime); err != nil {
			return nil, err
		}
		if parentID.Valid {
			pid := int(parentID.Int64)
			r.ParentID = &pid
		}
		files = append(files, r)
	}
	return files, nil
}

func exportCredentialsTable(db *sql.DB, filters ...string) ([]CredentialRow, error) {
	filterMap := parseFilters(filters)
	page := 1
	if p, ok := filterMap["page"]; ok {
		if n, err := strconv.Atoi(p); err == nil && n > 0 {
			page = n
		}
	}
	limit := 50
	offset := (page - 1) * limit
	query := `SELECT domain, user, host, auth_method, password_clear, password_hash, password_ticket, found_time FROM domain_credentials WHERE LOWER(domain) = ? ORDER BY id LIMIT ? OFFSET ?`
	rows, err := db.Query(query, strings.ToLower(currentDomain), limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var credentials []CredentialRow
	for rows.Next() {
		var r CredentialRow
		if err := rows.Scan(&r.Domain, &r.User, &r.Host, &r.AuthMethod, &r.PasswordClear, &r.PasswordHash, &r.PasswordTicket, &r.FoundTime); err != nil {
			return nil, err
		}
		credentials = append(credentials, r)
	}
	return credentials, nil
}

func exportLHFTable(db *sql.DB, filters ...string) ([]LHFRow, error) {
	filterMap := parseFilters(filters)
	page := 1
	if p, ok := filterMap["page"]; ok {
		if n, err := strconv.Atoi(p); err == nil && n > 0 {
			page = n
		}
	}
	limit := 50
	offset := (page - 1) * limit
	query := `SELECT id, path, host, share, domain, user, size, mod_time, match_pattern, match_type, size_formatted, scan_mode, large_file FROM low_hanging_fruit WHERE LOWER(domain) = ? ORDER BY id LIMIT ? OFFSET ?`
	rows, err := db.Query(query, strings.ToLower(currentDomain), limit, offset)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var lhfs []LHFRow
	for rows.Next() {
		var r LHFRow
		if err := rows.Scan(&r.ID, &r.Path, &r.Host, &r.Share, &r.Domain, &r.User, &r.Size, &r.ModTime, &r.MatchPattern, &r.MatchType, &r.SizeFormatted, &r.ScanMode, &r.LargeFile); err != nil {
			return nil, err
		}
		lhfs = append(lhfs, r)
	}
	return lhfs, nil
}

func getExportFilename(defaultType string) string {
	timestamp := time.Now().Format("20060102_150405")
	dir := "exports"
	os.MkdirAll(dir, 0755)
	return filepath.Join(dir, fmt.Sprintf("exported_%s_%s.json", defaultType, timestamp))
}

func confirmOverwrite(path string) bool {
	fmt.Printf("Warning: File '%s' already exists. Overwrite? (y/N): ", path)
	var resp string
	fmt.Scanln(&resp)
	return strings.ToLower(strings.TrimSpace(resp)) == "y"
}

func exportFilesCmd(db *sql.DB, filters ...string) {
	var outFile string
	for i := 0; i < len(filters); i++ {
		if filters[i] == "to" && i+1 < len(filters) {
			outFile = filters[i+1]
			filters = append(filters[:i], filters[i+2:]...)
			break
		}
	}
	if outFile == "" {
		outFile = getExportFilename("files")
	}
	if _, err := os.Stat(outFile); err == nil {
		if !confirmOverwrite(outFile) {
			fmt.Println("Export cancelled. File not overwritten.")
			return
		}
	}
	files, err := exportFilesTable(db, filters...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error exporting files: %v\n", err)
		return
	}
	if len(files) == 0 {
		fmt.Println("No results found for this export query.")
		return
	}
	f, err := os.Create(outFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating file: %v\n", err)
		return
	}
	defer f.Close()
	absPath, err := filepath.Abs(outFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting absolute path: %v\n", err)
		return
	}
	fmt.Printf("Exporting to file: %s\n", absPath)
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	enc.Encode(files)
}

func exportLHFCmd(db *sql.DB, filters ...string) {
	var outFile string
	for i := 0; i < len(filters); i++ {
		if filters[i] == "to" && i+1 < len(filters) {
			outFile = filters[i+1]
			filters = append(filters[:i], filters[i+2:]...)
			break
		}
	}
	if outFile == "" {
		outFile = getExportFilename("lhf")
	}
	if _, err := os.Stat(outFile); err == nil {
		if !confirmOverwrite(outFile) {
			fmt.Println("Export cancelled. File not overwritten.")
			return
		}
	}
	lhf, err := exportLHFTable(db, filters...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error exporting low_hanging_fruit: %v\n", err)
		return
	}
	if len(lhf) == 0 {
		fmt.Println("No results found for this export query.")
		return
	}
	f, err := os.Create(outFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating file: %v\n", err)
		return
	}
	defer f.Close()
	absPath, err := filepath.Abs(outFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting absolute path: %v\n", err)
		return
	}
	fmt.Printf("Exporting to file: %s\n", absPath)
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	enc.Encode(lhf)
}

func exportCredentialsCmd(db *sql.DB, filters ...string) {
	var outFile string
	for i := 0; i < len(filters); i++ {
		if filters[i] == "to" && i+1 < len(filters) {
			outFile = filters[i+1]
			filters = append(filters[:i], filters[i+2:]...)
			break
		}
	}
	if outFile == "" {
		outFile = getExportFilename("credentials")
	}
	if _, err := os.Stat(outFile); err == nil {
		if !confirmOverwrite(outFile) {
			fmt.Println("Export cancelled. File not overwritten.")
			return
		}
	}
	credentials, err := exportCredentialsTable(db, filters...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error exporting credentials: %v\n", err)
		return
	}
	if len(credentials) == 0 {
		fmt.Println("No results found for this export query.")
		return
	}
	f, err := os.Create(outFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating file: %v\n", err)
		return
	}
	defer f.Close()
	absPath, err := filepath.Abs(outFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting absolute path: %v\n", err)
		return
	}
	fmt.Printf("Exporting to file: %s\n", absPath)
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	enc.Encode(credentials)
}

func exportAllCmd(db *sql.DB, filters ...string) {
	var outFile string
	for i := 0; i < len(filters); i++ {
		if filters[i] == "to" && i+1 < len(filters) {
			outFile = filters[i+1]
			filters = append(filters[:i], filters[i+2:]...)
			break
		}
	}
	if outFile == "" {
		outFile = getExportFilename("all")
	}
	if _, err := os.Stat(outFile); err == nil {
		if !confirmOverwrite(outFile) {
			fmt.Println("Export cancelled. File not overwritten.")
			return
		}
	}
	files, err := exportFilesTable(db, filters...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error exporting files: %v\n", err)
		return
	}
	lhf, err := exportLHFTable(db, filters...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error exporting low_hanging_fruit: %v\n", err)
		return
	}
	credentials, err := exportCredentialsTable(db, filters...)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error exporting credentials: %v\n", err)
		return
	}
	if len(files) == 0 && len(lhf) == 0 && len(credentials) == 0 {
		fmt.Println("No results found for this export query.")
		return
	}
	f, err := os.Create(outFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating file: %v\n", err)
		return
	}
	defer f.Close()
	absPath, err := filepath.Abs(outFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error getting absolute path: %v\n", err)
		return
	}
	fmt.Printf("Exporting to file: %s\n", absPath)
	result := map[string]interface{}{
		"files":             files,
		"low_hanging_fruit": lhf,
		"credentials":       credentials,
	}
	enc := json.NewEncoder(f)
	enc.SetIndent("", "  ")
	enc.Encode(result)
}

// Função utilitária para buscar nomes de arquivos do domínio atual
func (m *model) getFileNames(limit int) []string {
	if m.selectedDomain == "" {
		return nil
	}
	rows, err := m.db.Query("SELECT DISTINCT path FROM files WHERE LOWER(domain) = ? ORDER BY id DESC LIMIT ?", strings.ToLower(m.selectedDomain), limit)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var files []string
	for rows.Next() {
		var path string
		rows.Scan(&path)
		files = append(files, path)
	}
	return files
}
