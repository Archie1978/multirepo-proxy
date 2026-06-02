// Package bruteforce provides a per-IP failure counter with temporary blocking.
// After MaxFailures failed attempts, the IP is blocked for BlockDuration.
package bruteforce

import (
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"
)

type entry struct {
	failures     int
	blockedUntil time.Time
}

// Tracker maintains a failure counter per IP and applies temporary blocking.
type Tracker struct {
	mu            sync.Mutex
	entries       map[string]*entry
	maxFailures   int
	blockDuration time.Duration
}

// New creates a Tracker and starts the periodic cleanup goroutine.
func New(maxFailures int, blockDuration time.Duration) *Tracker {
	t := &Tracker{
		entries:       make(map[string]*entry),
		maxFailures:   maxFailures,
		blockDuration: blockDuration,
	}
	go t.cleanup()
	return t
}

// IsBlocked returns true if the IP is currently blocked, along with the remaining time.
func (t *Tracker) IsBlocked(ip string) (bool, time.Duration) {
	t.mu.Lock()
	defer t.mu.Unlock()

	e, ok := t.entries[ip]
	if !ok {
		return false, 0
	}
	remaining := time.Until(e.blockedUntil)
	if remaining > 0 {
		return true, remaining
	}
	delete(t.entries, ip)
	return false, 0
}

// RecordFailure increments the counter for the IP; triggers blocking if the threshold is reached.
func (t *Tracker) RecordFailure(ip string) {
	t.mu.Lock()
	defer t.mu.Unlock()

	e, ok := t.entries[ip]
	if !ok {
		e = &entry{}
		t.entries[ip] = e
	}
	// Reset if a previous block has just expired.
	if !e.blockedUntil.IsZero() && time.Now().After(e.blockedUntil) {
		e.failures = 0
		e.blockedUntil = time.Time{}
	}
	e.failures++
	if e.failures >= t.maxFailures {
		e.blockedUntil = time.Now().Add(t.blockDuration)
	}
}

// RecordSuccess resets the counter for the IP after a successful authentication.
func (t *Tracker) RecordSuccess(ip string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.entries, ip)
}

// Failures returns the number of recorded failures for the IP.
func (t *Tracker) Failures(ip string) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	if e, ok := t.entries[ip]; ok {
		return e.failures
	}
	return 0
}

// Deny writes a 429 Too Many Requests response with the Retry-After header.
func (t *Tracker) Deny(w http.ResponseWriter, remaining time.Duration) {
	secs := int(remaining.Seconds()) + 1
	w.Header().Set("Retry-After", fmt.Sprintf("%d", secs))
	http.Error(w,
		fmt.Sprintf("Too many failed authentication attempts — retry in %d s", secs),
		http.StatusTooManyRequests,
	)
}

// ExtractIP extracts the IP address (without port) from r.RemoteAddr.
func ExtractIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// cleanup removes expired entries every 10 minutes.
func (t *Tracker) cleanup() {
	ticker := time.NewTicker(10 * time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		now := time.Now()
		t.mu.Lock()
		for ip, e := range t.entries {
			if !e.blockedUntil.IsZero() && now.After(e.blockedUntil) {
				delete(t.entries, ip)
			}
		}
		t.mu.Unlock()
	}
}
