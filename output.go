package main

import (
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/m0ng3sh3ll/NullFang/checkpoint"
	"github.com/m0ng3sh3ll/NullFang/utils"
	"github.com/m0ng3sh3ll/NullFang/web"
)

// Helper function to format file sizes
func formatSize(size int64) string {
	const (
		B  = 1
		KB = 1024 * B
		MB = 1024 * KB
		GB = 1024 * MB
	)

	switch {
	case size >= GB:
		return fmt.Sprintf("%.2f GB", float64(size)/float64(GB))
	case size >= MB:
		return fmt.Sprintf("%.2f MB", float64(size)/float64(MB))
	case size >= KB:
		return fmt.Sprintf("%.2f KB", float64(size)/float64(KB))
	default:
		return fmt.Sprintf("%d B", size)
	}
}

// Função utilitária para garantir que o campo network seja sempre preenchido corretamente
func getNetworkContext() string {
	if *networkFlag != "" {
		return *networkFlag
	}
	if *hostFlag != "" {
		return *hostFlag
	}
	if *listFlag != "" {
		return *listFlag
	}
	return ""
}

func printSummaryBox(title string, lines []string, width int) {
	border := "═"
	fmt.Printf("╔%s╗\n", strings.Repeat(border, width-2))
	if title != "" {
		fmt.Printf("║%s║\n", padCenter(title, width-2))
		fmt.Printf("╠%s╣\n", strings.Repeat(border, width-2))
	}
	for _, line := range lines {
		for len(line) > 0 {
			var part string
			if utf8.RuneCountInString(line) > width-4 {
				part = string([]rune(line)[:width-4])
				line = string([]rune(line)[width-4:])
			} else {
				part = line
				line = ""
			}
			fmt.Printf("║ %-*s ║\n", width-4, part)
		}
	}
	fmt.Printf("╚%s╝\n", strings.Repeat(border, width-2))
}

func padCenter(str string, width int) string {
	pad := width - len(str)
	left := pad / 2
	right := pad - left
	return strings.Repeat(" ", left) + str + strings.Repeat(" ", right)
}

func printUsageError(msg, example string) {
	fmt.Printf("[ERROR] %s\n", msg)
	if example != "" {
		fmt.Printf("Example:\n  %s\n", example)
	}
	fmt.Println("For more options, use: NullFang -help")
	os.Exit(1)
}

// Função para iniciar o servidor web
func startWebServer() {
	showBanner()
	fmt.Printf("\n═══════════════════════════════════════════════════════\n")
	fmt.Printf("   	NullFang - Web Interface\n")
	fmt.Printf("═══════════════════════════════════════════════════════\n\n")

	// Determinar caminho do banco de dados
	var dbPath string
	if *dbFlag != "" {
		// Usar caminho customizado fornecido via flag -db
		dbPath = *dbFlag
	} else {
		// Usar caminho padrão
		dbPath = utils.GetDefaultDBPath()
	}

	// Validar se o banco de dados existe
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		fmt.Printf("❌ Database not found: %s\n", dbPath)
		fmt.Printf("💡 Execute NullFang first to create the database:\n")
		fmt.Printf("   NullFang -H 192.168.1.10 -u admin -p password\n")
		if *dbFlag != "" {
			fmt.Printf("   Or specify a different database with: -db /path/to/database\n\n")
		} else {
			fmt.Printf("\n")
		}
		os.Exit(1)
	}

	// Validar porta
	port := *webPortFlag
	if port == "" {
		port = "9090"
	}

	// Tentar converter porta para número para validação
	if _, err := strconv.Atoi(port); err != nil {
		fmt.Printf("❌ Invalid port: %s\n", port)
		os.Exit(1)
	}

	fmt.Printf("🗄️  Database: %s\n", dbPath)
	fmt.Printf("🌐 Web server: http://localhost:%s\n", port)
	fmt.Printf("📊 Interface available for data analysis\n\n")

	// Iniciar servidor web
	server, err := web.NewServer(dbPath)
	if err != nil {
		fmt.Printf("❌ Error starting web server: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("🚀 Web server started successfully!\n")
	fmt.Printf("📱 Access: http://localhost:%s\n", port)
	fmt.Printf("⏹️  Press Ctrl+C to stop the server\n\n")

	// Configurar tratamento de sinais para graceful shutdown
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		sig := <-c
		fmt.Printf("\n🛑 Web server stopped by %v\n", sig)
		os.Exit(0)
	}()

	// Iniciar servidor
	if err := server.Start(port); err != nil {
		fmt.Printf("❌ Error starting web server: %v\n", err)
		os.Exit(1)
	}
}

func finalizeRun(cp *checkpoint.Checkpoint) {
	if cp != nil {
		checkpointPath := cp.GetFilename()
		historyDir := filepath.Join("history")
		os.MkdirAll(historyDir, 0755)
		name := filepath.Base(checkpointPath)
		historyName := strings.Replace(name, "nullfang_resume_", "nullfang_history_", 1)
		if historyName == name {
			historyName = "nullfang_history_" + time.Now().Format("20060102_150405") + ".json"
		}
		historyPath := filepath.Join(historyDir, historyName)
		if err := os.Rename(checkpointPath, historyPath); err == nil {
			fmt.Printf("The history was saved to: %s\n", historyPath)
		} else {
			fmt.Printf("[WARN] Could not move checkpoint to history: %v\n", err)
		}
	}
	fmt.Printf("\n═══════════════════════════════════════════════════════\n")
	fmt.Printf(" ✨ NullFang execution completed successfully! ✨\n")
	fmt.Printf("═══════════════════════════════════════════════════════\n")
}
