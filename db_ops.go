package main

import (
	"database/sql"
	"fmt"
	"strings"

	"github.com/m0ng3sh3ll/NullFang/database"
)

func saveCredential(db *sql.DB, domain, user, authMethod, host, passwordClear, passwordHash, passwordTicket, foundTime string, isAdmin bool) {
	if err := database.InsertDomainCredentials(
		db,
		domain,
		user,
		host,
		authMethod,
		passwordClear,
		passwordHash,
		passwordTicket,
		foundTime,
		isAdmin,
	); err != nil {
		fmt.Printf("[-] Error saving credential: %v\n", err)
	}
	if *verboseFlag {
		fmt.Printf("[-] Credential saved: %s:%s@%s\n", domain, user, host)
	}
}

// getUserStatus retorna o status do usuário baseado nos privilégios de admin
func getUserStatus(db *sql.DB, host, user string) string {
	var isAdmin bool
	err := db.QueryRow("SELECT isAdmin FROM domain_credentials WHERE host = ? AND LOWER(user) = LOWER(?)", host, strings.ToLower(user)).Scan(&isAdmin)
	if err != nil {
		return ""
	}
	if isAdmin {
		return "Pwn3d"
	}
	return "not admin"
}

// getDisplayDomain retorna o domínio correto para exibir nas mensagens do Telegram
func getDisplayDomain(db *sql.DB, host string) string {
	if *localAuthFlag {
		// Tenta obter o hostname salvo no banco de dados para o host
		var domain string
		err := db.QueryRow("SELECT domain FROM domain_credentials WHERE host = ? ORDER BY ROWID DESC LIMIT 1", host).Scan(&domain)
		if err == nil && domain != "" {
			return domain
		}
		// Fallback: retorna o próprio host (IP)
		return host
	}
	// Caso padrão: retorna o valor da flag -d
	return *domainFlag
}
