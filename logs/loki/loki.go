package loki

import (
	"bytes"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

type entry struct {
	ts   time.Time
	line []byte
}

// LokiBackend pushes entries to Grafana Loki via the HTTP push API.
// Entries are grouped into batches sent periodically or when the max size is reached.
type LokiBackend struct {
	url       string
	labels    string // pre-serialized Loki stream labels: {"app":"x","env":"y"}
	batchSize int
	batchWait time.Duration
	client    *http.Client

	ch   chan entry
	done chan struct{}
	wg   sync.WaitGroup
}

// New creates and starts a LokiBackend.
func New(url string, labels map[string]string, batchSize int, batchWait, timeout string) (*LokiBackend, error) {
	wait, err := time.ParseDuration(batchWait)
	if err != nil || wait <= 0 {
		wait = 2 * time.Second
	}
	to, err := time.ParseDuration(timeout)
	if err != nil || to <= 0 {
		to = 5 * time.Second
	}
	if batchSize <= 0 {
		batchSize = 100
	}

	b := &LokiBackend{
		url:       strings.TrimRight(url, "/") + "/loki/api/v1/push",
		labels:    buildLabels(labels),
		batchSize: batchSize,
		batchWait: wait,
		client:    &http.Client{Timeout: to},
		ch:        make(chan entry, batchSize*2),
		done:      make(chan struct{}),
	}

	b.wg.Add(1)
	go b.loop()
	return b, nil
}

func (b *LokiBackend) Write(ts time.Time, line []byte) error {
	cp := make([]byte, len(line))
	copy(cp, line)
	select {
	case b.ch <- entry{ts: ts, line: cp}:
	default:
		// Channel full: drop this entry rather than blocking.
	}
	return nil
}

func (b *LokiBackend) Close() error {
	close(b.done)
	b.wg.Wait()
	return nil
}

func (b *LokiBackend) loop() {
	defer b.wg.Done()
	ticker := time.NewTicker(b.batchWait)
	defer ticker.Stop()

	batch := make([]entry, 0, b.batchSize)

	flush := func() {
		if len(batch) == 0 {
			return
		}
		_ = b.push(batch)
		batch = batch[:0]
	}

	for {
		select {
		case e := <-b.ch:
			batch = append(batch, e)
			if len(batch) >= b.batchSize {
				flush()
			}
		case <-ticker.C:
			flush()
		case <-b.done:
			// Drain the channel before exiting.
			for {
				select {
				case e := <-b.ch:
					batch = append(batch, e)
				default:
					flush()
					return
				}
			}
		}
	}
}

// push sends a batch to Loki.
func (b *LokiBackend) push(batch []entry) error {
	body := b.buildPayload(batch)
	req, err := http.NewRequest(http.MethodPost, b.url, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := b.client.Do(req)
	if err != nil {
		return fmt.Errorf("loki push: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("loki push: status %d", resp.StatusCode)
	}
	return nil
}

// buildPayload builds the JSON expected by the Loki v1/push API.
func (b *LokiBackend) buildPayload(batch []entry) []byte {
	var sb strings.Builder
	sb.WriteString(`{"streams":[{"stream":`)
	sb.WriteString(b.labels)
	sb.WriteString(`,"values":[`)
	for i, e := range batch {
		if i > 0 {
			sb.WriteByte(',')
		}
		ns := e.ts.UnixNano()
		sb.WriteString(`["`)
		sb.WriteString(fmt.Sprintf("%d", ns))
		sb.WriteString(`",`)
		sb.WriteString(jsonString(string(e.line)))
		sb.WriteByte(']')
	}
	sb.WriteString(`]}]}`)
	return []byte(sb.String())
}

func buildLabels(labels map[string]string) string {
	if len(labels) == 0 {
		return `{}`
	}
	var sb strings.Builder
	sb.WriteByte('{')
	first := true
	for k, v := range labels {
		if !first {
			sb.WriteByte(',')
		}
		sb.WriteString(jsonString(k))
		sb.WriteByte(':')
		sb.WriteString(jsonString(v))
		first = false
	}
	sb.WriteByte('}')
	return sb.String()
}

func jsonString(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, "\n", `\n`)
	s = strings.ReplaceAll(s, "\r", `\r`)
	s = strings.ReplaceAll(s, "\t", `\t`)
	return `"` + s + `"`
}
