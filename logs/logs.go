package logs

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"multirepo-proxy/config"
	logsfile "multirepo-proxy/logs/file"
	"multirepo-proxy/logs/logstash"
	"multirepo-proxy/logs/loki"
)

// ─────────────────────────────────────────────
// Level
// ─────────────────────────────────────────────

type Level int

const (
	LevelDebug Level = iota
	LevelInfo
	LevelWarn
	LevelError
)

func (l Level) String() string {
	switch l {
	case LevelDebug:
		return "debug"
	case LevelInfo:
		return "info"
	case LevelWarn:
		return "warn"
	case LevelError:
		return "error"
	default:
		return "unknown"
	}
}

func parseLevel(s string) Level {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "debug":
		return LevelDebug
	case "warn", "warning":
		return LevelWarn
	case "error":
		return LevelError
	default:
		return LevelInfo
	}
}

// ─────────────────────────────────────────────
// Field — structured key/value pair
// ─────────────────────────────────────────────

type Field struct {
	Key   string
	Value any
}

// Field constructors.
func String(key, val string) Field          { return Field{key, val} }
func Int(key string, val int) Field         { return Field{key, val} }
func Int64(key string, val int64) Field     { return Field{key, val} }
func Bool(key string, val bool) Field       { return Field{key, val} }
func Dur(key string, d time.Duration) Field { return Field{key, d.String()} }
func Err(err error) Field                   { return Field{"error", err.Error()} }
func Any(key string, val any) Field         { return Field{key, val} }

// ─────────────────────────────────────────────
// Entry — complete log entry
// ─────────────────────────────────────────────

// Entry is a log entry ready to be written.
// Backends receive the timestamp and the serialized JSON line —
// they do not need to import this package (no circular import).
type Entry struct {
	Time    time.Time
	Level   Level
	Message string
	Fields  []Field
}

// JSON serializes the entry as a JSON line (without trailing \n).
// Manual construction to avoid reflection and stay fast.
func (e Entry) JSON() []byte {
	var b strings.Builder
	b.WriteString(`{"ts":"`)
	b.WriteString(e.Time.UTC().Format(time.RFC3339Nano))
	b.WriteString(`","level":"`)
	b.WriteString(e.Level.String())
	b.WriteString(`","msg":`)
	b.WriteString(jsonString(e.Message))
	for _, f := range e.Fields {
		b.WriteByte(',')
		b.WriteString(jsonString(f.Key))
		b.WriteByte(':')
		b.WriteString(jsonValue(f.Value))
	}
	b.WriteByte('}')
	return []byte(b.String())
}

// ─────────────────────────────────────────────
// Backend — interface satisfied by sub-packages
// ─────────────────────────────────────────────

// Backend is the interface implemented by each log destination.
// The signature uses only stdlib types to avoid circular imports.
// Sub-packages (file, logstash, loki) implement it without importing "logs".
type Backend interface {
	Write(ts time.Time, line []byte) error
	Close() error
}

// ─────────────────────────────────────────────
// Logger — public interface
// ─────────────────────────────────────────────

type Logger interface {
	Debug(msg string, fields ...Field)
	Info(msg string, fields ...Field)
	Warn(msg string, fields ...Field)
	Error(msg string, fields ...Field)
	// With returns a derived Logger carrying permanent fields.
	With(fields ...Field) Logger
	Close() error
}

// ─────────────────────────────────────────────
// MultiLogger — fan-out to multiple backends
// ─────────────────────────────────────────────

type MultiLogger struct {
	mu       sync.Mutex
	level    Level
	backends []Backend
	fields   []Field
}

func (m *MultiLogger) emit(level Level, msg string, fields []Field) {
	if level < m.level {
		return
	}
	all := make([]Field, 0, len(m.fields)+len(fields))
	all = append(all, m.fields...)
	all = append(all, fields...)

	e := Entry{Time: time.Now(), Level: level, Message: msg, Fields: all}
	line := e.JSON()

	m.mu.Lock()
	for _, b := range m.backends {
		_ = b.Write(e.Time, line)
	}
	m.mu.Unlock()
}

func (m *MultiLogger) Debug(msg string, fields ...Field) { m.emit(LevelDebug, msg, fields) }
func (m *MultiLogger) Info(msg string, fields ...Field)  { m.emit(LevelInfo, msg, fields) }
func (m *MultiLogger) Warn(msg string, fields ...Field)  { m.emit(LevelWarn, msg, fields) }
func (m *MultiLogger) Error(msg string, fields ...Field) { m.emit(LevelError, msg, fields) }

func (m *MultiLogger) With(fields ...Field) Logger {
	merged := make([]Field, len(m.fields)+len(fields))
	copy(merged, m.fields)
	copy(merged[len(m.fields):], fields)
	return &MultiLogger{level: m.level, backends: m.backends, fields: merged}
}

func (m *MultiLogger) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, b := range m.backends {
		_ = b.Close()
	}
	return nil
}

// ─────────────────────────────────────────────
// stdout backend (built into this package)
// ─────────────────────────────────────────────

type stdoutBackend struct {
	mu     sync.Mutex
	w      io.Writer
	format string // "text" or "json"
}

var levelANSI = map[Level]string{
	LevelDebug: "\033[36m", // cyan
	LevelInfo:  "\033[32m", // green
	LevelWarn:  "\033[33m", // yellow
	LevelError: "\033[31m", // red
}

const ansiReset = "\033[0m"

func (b *stdoutBackend) Write(ts time.Time, line []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.format == "json" {
		_, err := fmt.Fprintf(b.w, "%s\n", line)
		return err
	}
	// Text format — reparse the minimal JSON for clean display
	// (we receive JSON we just built, so parsing is fast)
	e := parseLineForText(line)
	color := levelANSI[e.level]
	_, err := fmt.Fprintf(b.w, "%s  %s%-5s%s  %s  %s\n",
		ts.Format("2006-01-02 15:04:05.000"),
		color, strings.ToUpper(e.level.String()), ansiReset,
		e.msg, e.extra,
	)
	return err
}

func (b *stdoutBackend) Close() error { return nil }

// parsedLine is the minimal parsing result for text display.
type parsedLine struct {
	level Level
	msg   string
	extra string
}

// parseLineForText extracts level, msg and extra fields from the JSON produced by Entry.JSON().
// Simplified parsing — we trust our own format.
func parseLineForText(line []byte) parsedLine {
	s := string(line)
	p := parsedLine{level: LevelInfo}

	if i := strings.Index(s, `"level":"`); i >= 0 {
		rest := s[i+9:]
		if j := strings.IndexByte(rest, '"'); j >= 0 {
			p.level = parseLevel(rest[:j])
		}
	}
	if i := strings.Index(s, `"msg":`); i >= 0 {
		rest := s[i+6:]
		if len(rest) > 0 && rest[0] == '"' {
			rest = rest[1:]
			if j := strings.IndexByte(rest, '"'); j >= 0 {
				p.msg = rest[:j]
			}
		}
	}
	// Extra fields: everything after "msg":"..." to the end of the JSON
	// Format: ,"key":"val","key2":123
	if i := strings.Index(s, `"msg":`); i >= 0 {
		after := s[i+6:]
		if j := strings.Index(after, `",`); j >= 0 {
			extra := after[j+2 : len(after)-1] // strip last }
			// Convert ,"key":"val" to key=val
			extra = strings.ReplaceAll(extra, `":"`, `=`)
			extra = strings.ReplaceAll(extra, `",`, ` `)
			extra = strings.ReplaceAll(extra, `"`, ``)
			extra = strings.ReplaceAll(extra, `:`, `=`)
			p.extra = strings.TrimSpace(extra)
		}
	}
	return p
}

// ─────────────────────────────────────────────
// Factory
// ─────────────────────────────────────────────

// NewFromConfig builds a Logger from the configuration.
// If no backend is enabled, stdout text is used by default.
func NewFromConfig(cfg config.LoggingConfig) (Logger, error) {
	level := parseLevel(cfg.Level)
	var backends []Backend

	if cfg.Stdout.Enabled {
		format := cfg.Stdout.Format
		if format == "" {
			format = "text"
		}
		backends = append(backends, &stdoutBackend{w: os.Stdout, format: format})
	}

	if cfg.File.Enabled {
		fb, err := logsfile.New(cfg.File.Path, cfg.File.MaxSizeMB, cfg.File.MaxBackups, cfg.File.Compress)
		if err != nil {
			return nil, fmt.Errorf("log file: %w", err)
		}
		backends = append(backends, fb)
	}

	if cfg.Logstash.Enabled {
		if cfg.Logstash.Host == "" {
			return nil, fmt.Errorf("log logstash: host required")
		}
		proto := cfg.Logstash.Protocol
		if proto == "" {
			proto = "tcp"
		}
		backends = append(backends, logstash.New(cfg.Logstash.Host, proto))
	}

	if cfg.Loki.Enabled {
		if cfg.Loki.URL == "" {
			return nil, fmt.Errorf("log loki: url required")
		}
		lb, err := loki.New(cfg.Loki.URL, cfg.Loki.Labels, cfg.Loki.BatchSize, cfg.Loki.BatchWait, cfg.Loki.Timeout)
		if err != nil {
			return nil, fmt.Errorf("log loki: %w", err)
		}
		backends = append(backends, lb)
	}

	if len(backends) == 0 {
		backends = append(backends, &stdoutBackend{w: os.Stdout, format: "text"})
	}

	return &MultiLogger{level: level, backends: backends}, nil
}

// Discard returns a Logger that ignores all entries.
func Discard() Logger {
	return &MultiLogger{level: Level(999)}
}

// ─────────────────────────────────────────────
// Minimal JSON helpers (without reflection)
// ─────────────────────────────────────────────

func jsonString(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	s = strings.ReplaceAll(s, "\r", `\r`)
	s = strings.ReplaceAll(s, "\t", `\t`)
	return `"` + s + `"`
}

func jsonValue(v any) string {
	switch t := v.(type) {
	case string:
		return jsonString(t)
	case bool:
		if t {
			return "true"
		}
		return "false"
	case int:
		return fmt.Sprintf("%d", t)
	case int64:
		return fmt.Sprintf("%d", t)
	case float64:
		return fmt.Sprintf("%g", t)
	case nil:
		return "null"
	default:
		return jsonString(fmt.Sprintf("%v", t))
	}
}
