package logger

import (
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// LogLevel define os níveis de log disponíveis
type LogLevel int

const (
	DEBUG LogLevel = iota
	INFO
	SUCCESS
	WARNING
	ERROR
	FATAL
)

var (
	// Cores ANSI
	reset   = "\033[0m"
	red     = "\033[31m"
	green   = "\033[32m"
	yellow  = "\033[33m"
	blue    = "\033[34m"
	magenta = "\033[35m"
	cyan    = "\033[36m"

	// Prefixos dos níveis de log
	levelPrefixes = map[LogLevel]string{
		DEBUG:   "[DEBUG] ",
		INFO:    "[*] ",
		SUCCESS: "[+] ",
		WARNING: "[!] ",
		ERROR:   "[-] ",
		FATAL:   "[FATAL] ",
	}

	// Cores dos níveis de log
	levelColors = map[LogLevel]string{
		DEBUG:   cyan,
		INFO:    blue,
		SUCCESS: green,
		WARNING: yellow,
		ERROR:   red,
		FATAL:   magenta,
	}
)

// Logger é a estrutura principal do logger
type Logger struct {
	mu        sync.Mutex
	out       io.Writer
	level     LogLevel
	verbose   bool
	timestamp bool
}

// NewLogger cria uma nova instância do logger
func NewLogger() *Logger {
	return &Logger{
		out:       os.Stdout,
		level:     INFO,
		verbose:   false,
		timestamp: false,
	}
}

// SetOutput define o writer de saída
func (l *Logger) SetOutput(w io.Writer) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.out = w
}

// SetLevel define o nível mínimo de log
func (l *Logger) SetLevel(level LogLevel) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.level = level
}

// SetVerbose define se o modo verbose está ativo
func (l *Logger) SetVerbose(verbose bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.verbose = verbose
}

// SetTimestamp define se o timestamp deve ser incluído
func (l *Logger) SetTimestamp(timestamp bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.timestamp = timestamp
}

// log é o método interno que realiza o logging
func (l *Logger) log(level LogLevel, format string, args ...interface{}) {
	if level < l.level {
		return
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	// Se não for verbose e for DEBUG, não loga
	if !l.verbose && level == DEBUG {
		return
	}

	var prefix string
	// Só adiciona timestamp se estiver em modo verbose
	if l.timestamp && l.verbose {
		prefix = time.Now().Format("2006-01-02 15:04:05 ")
	}

	msg := fmt.Sprintf(format, args...)
	color := levelColors[level]
	levelPrefix := levelPrefixes[level]

	fmt.Fprintf(l.out, "%s%s%s%s%s\n", prefix, color, levelPrefix, msg, reset)

	if level == FATAL {
		os.Exit(1)
	}
}

// Debug loga mensagens de debug (apenas em modo verbose)
func (l *Logger) Debug(format string, args ...interface{}) {
	l.log(DEBUG, format, args...)
}

// Info loga mensagens informativas
func (l *Logger) Info(format string, args ...interface{}) {
	l.log(INFO, format, args...)
}

// Success loga mensagens de sucesso
func (l *Logger) Success(format string, args ...interface{}) {
	l.log(SUCCESS, format, args...)
}

// Warning loga mensagens de aviso
func (l *Logger) Warning(format string, args ...interface{}) {
	l.log(WARNING, format, args...)
}

// Error loga mensagens de erro
func (l *Logger) Error(format string, args ...interface{}) {
	l.log(ERROR, format, args...)
}

// Fatal loga mensagens fatais e encerra o programa
func (l *Logger) Fatal(format string, args ...interface{}) {
	l.log(FATAL, format, args...)
}

// Fatalf loga uma mensagem fatal e encerra o programa
func (l *Logger) Fatalf(format string, args ...interface{}) {
	l.log(FATAL, format, args...)
}

// Printf loga uma mensagem com nível INFO
func (l *Logger) Printf(format string, args ...interface{}) {
	l.log(INFO, format, args...)
}

// Default é a instância global do logger
var Default = NewLogger()

// Funções helper para usar a instância global
func Debug(format string, args ...interface{})   { Default.Debug(format, args...) }
func Info(format string, args ...interface{})    { Default.Info(format, args...) }
func Success(format string, args ...interface{}) { Default.Success(format, args...) }
func Warning(format string, args ...interface{}) { Default.Warning(format, args...) }
func Error(format string, args ...interface{})   { Default.Error(format, args...) }
func Fatal(format string, args ...interface{})   { Default.Fatal(format, args...) }
func Fatalf(format string, args ...interface{})  { Default.Fatalf(format, args...) }
func Printf(format string, args ...interface{})  { Default.Printf(format, args...) }

// SetGlobalVerbose define o modo verbose para a instância global
func SetGlobalVerbose(verbose bool) { Default.SetVerbose(verbose) }

// SetGlobalLevel define o nível de log para a instância global
func SetGlobalLevel(level LogLevel) { Default.SetLevel(level) }

// SetGlobalTimestamp define se o timestamp deve ser incluído na instância global
func SetGlobalTimestamp(timestamp bool) { Default.SetTimestamp(timestamp) }
