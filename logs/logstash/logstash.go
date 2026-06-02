package logstash

import (
	"fmt"
	"net"
	"sync"
	"time"
)

// LogstashBackend sends JSON lines to a Logstash server via TCP or UDP.
// The connection is established lazily and re-established on failure.
type LogstashBackend struct {
	mu       sync.Mutex
	host     string
	proto    string // "tcp" or "udp"
	conn     net.Conn
	deadline time.Duration
}

// New creates a Logstash backend. The connection is established on the first Write.
func New(host, proto string) *LogstashBackend {
	if proto != "tcp" && proto != "udp" {
		proto = "tcp"
	}
	return &LogstashBackend{
		host:     host,
		proto:    proto,
		deadline: 5 * time.Second,
	}
}

func (b *LogstashBackend) Write(_ time.Time, line []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if err := b.ensureConn(); err != nil {
		return err
	}

	b.conn.SetWriteDeadline(time.Now().Add(b.deadline))
	_, err := fmt.Fprintf(b.conn, "%s\n", line)
	if err != nil {
		b.conn.Close()
		b.conn = nil
	}
	return err
}

func (b *LogstashBackend) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.conn != nil {
		err := b.conn.Close()
		b.conn = nil
		return err
	}
	return nil
}

func (b *LogstashBackend) ensureConn() error {
	if b.conn != nil {
		return nil
	}
	conn, err := net.DialTimeout(b.proto, b.host, b.deadline)
	if err != nil {
		return fmt.Errorf("logstash dial %s %s: %w", b.proto, b.host, err)
	}
	b.conn = conn
	return nil
}
