package gpg

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
)

// ─────────────────────────────────────────────
// Verifier — GPG verification of .deb packages
//
// A .deb is an archive in POSIX "ar" format.
// Internal structure:
//   !<arch>\n
//   debian-binary   (format version, "2.0\n")
//   control.tar.*   (package metadata)
//   data.tar.*      (installed files)
//   _gpgorigin      (detached OpenPGP signature, optional)
//
// Cryptographic verification is delegated to gpgv (same tool as apt).
// ─────────────────────────────────────────────

// Verifier manages a GPG keyring and verifies incoming .deb packages.
type Verifier struct {
	mu          sync.RWMutex
	keyringDir  string // directory containing .gpg files
	gpgvPath    string
	gpgPath     string
	rejectUnsigned bool // reject .deb packages without a signature?
}

// Config configures the Verifier.
type Config struct {
	// KeyringDir: directory where public keys (.gpg) are stored.
	// Created automatically if it does not exist.
	KeyringDir string

	// RejectUnsigned: if true, a .deb without _gpgorigin is rejected.
	// If false, it passes into quarantine without GPG verification
	// (useful for unsigned internal packages).
	RejectUnsigned bool
}

// NewVerifier creates a Verifier.
func NewVerifier(cfg Config) (*Verifier, error) {
	gpgvPath, err := exec.LookPath("gpgv")
	if err != nil {
		return nil, fmt.Errorf("gpgv not found in PATH: %w", err)
	}
	gpgPath, _ := exec.LookPath("gpg")

	if err := os.MkdirAll(cfg.KeyringDir, 0o755); err != nil {
		return nil, fmt.Errorf("create keyring dir: %w", err)
	}

	return &Verifier{
		keyringDir:     cfg.KeyringDir,
		gpgvPath:       gpgvPath,
		gpgPath:        gpgPath,
		rejectUnsigned: cfg.RejectUnsigned,
	}, nil
}

// AddKeyFromFile imports a public key from a file (ASCII-armored or binary GPG).
func (v *Verifier) AddKeyFromFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return v.AddKey(data)
}

// AddKey imports a public key (ASCII-armored or binary GPG).
func (v *Verifier) AddKey(keyData []byte) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	if v.gpgPath == "" {
		return fmt.Errorf("gpg not found in PATH, cannot import keys")
	}

	// If ASCII-armored → dearmor to binary GPG
	raw := keyData
	if bytes.HasPrefix(keyData, []byte("-----BEGIN")) {
		cmd := exec.Command(v.gpgPath, "--dearmor")
		cmd.Stdin = bytes.NewReader(keyData)
		out, err := cmd.Output()
		if err != nil {
			return fmt.Errorf("gpg --dearmor: %w", err)
		}
		raw = out
	}

	// Filename based on first bytes (short fingerprint)
	fp := fmt.Sprintf("%08x", binary.BigEndian.Uint32(raw[:min(4, len(raw))]))
	dest := filepath.Join(v.keyringDir, fp+".gpg")
	if err := os.WriteFile(dest, raw, 0o644); err != nil {
		return fmt.Errorf("write keyring: %w", err)
	}
	return nil
}

// ListKeys lists the fingerprints of imported keys.
func (v *Verifier) ListKeys() []string {
	v.mu.RLock()
	defer v.mu.RUnlock()
	entries, _ := os.ReadDir(v.keyringDir)
	var keys []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".gpg") {
			keys = append(keys, strings.TrimSuffix(e.Name(), ".gpg"))
		}
	}
	return keys
}

// VerifyDeb verifies the GPG signature of a .deb package.
//
// Steps:
//  1. Verify the ar magic
//  2. Extract _gpgorigin (detached signature)
//  3. Reconstruct the signed message (ar archive without _gpgorigin)
//  4. Call gpgv with the local keyring
//
// Returns nil if valid, ErrNoSignature if no _gpgorigin,
// or a descriptive error if the signature is invalid.
func (v *Verifier) VerifyDeb(debData []byte) error {
	v.mu.RLock()
	defer v.mu.RUnlock()

	// 1. Parse the ar archive
	members, order, err := parseAr(debData)
	if err != nil {
		return fmt.Errorf("parse ar archive: %w", err)
	}

	// 2. Signature present?
	sig, hasSig := members["_gpgorigin"]
	if !hasSig {
		if v.rejectUnsigned {
			return ErrNoSignature
		}
		// No signature but accepted → verification skipped
		return nil
	}

	// 3. Reconstruct the signed message
	// The debsig-verify signature covers an ar archive
	// containing all members EXCEPT _gpgorigin, in original order.
	signed := rebuildArWithout(debData, order, "_gpgorigin")

	// 4. Temporary files for gpgv
	tmpDir, err := os.MkdirTemp("", "multirepo-gpg-*")
	if err != nil {
		return fmt.Errorf("mktemp: %w", err)
	}
	defer os.RemoveAll(tmpDir)

	sigFile := filepath.Join(tmpDir, "sig.gpg")
	msgFile := filepath.Join(tmpDir, "message.ar")

	if err := os.WriteFile(sigFile, sig, 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(msgFile, signed, 0o600); err != nil {
		return err
	}

	// 5. Build gpgv arguments
	args := []string{"--status-fd", "1", "--no-default-keyring"}
	entries, _ := os.ReadDir(v.keyringDir)
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".gpg") {
			args = append(args, "--keyring", filepath.Join(v.keyringDir, e.Name()))
		}
	}
	if len(args) == 3 {
		// No imported keys
		return fmt.Errorf("no keys in keyring %q — import at least one key first", v.keyringDir)
	}
	args = append(args, sigFile, msgFile)

	// 6. Verification
	cmd := exec.Command(v.gpgvPath, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	cmd.Stdout = &bytes.Buffer{} // absorb --status-fd 1

	if err := cmd.Run(); err != nil {
		// Parse gpgv output for a readable error message
		detail := parseGpgvError(stderr.String())
		return fmt.Errorf("%w: %s", ErrInvalidSignature, detail)
	}
	return nil
}

// ─────────────────────────────────────────────
// ar parser — POSIX ar format (reference: man 5 ar)
//
// Each ar header = 60 bytes:
//   offset  0, len 16: filename (space-padded, terminated by '/')
//   offset 16, len 12: timestamp (decimal)
//   offset 28, len  6: uid (decimal)
//   offset 34, len  6: gid (decimal)
//   offset 40, len  8: octal mode
//   offset 48, len 10: file size (decimal)
//   offset 58, len  2: magic "`\n"
// ─────────────────────────────────────────────

const (
	arMagic    = "!<arch>\n"
	arHdrSize  = 60
	arFileMagic = "`\n"
)

type arEntry struct {
	name string
	data []byte
}

func parseAr(data []byte) (members map[string][]byte, order []arEntry, err error) {
	if len(data) < len(arMagic) || string(data[:len(arMagic)]) != arMagic {
		return nil, nil, fmt.Errorf("not an ar archive (magic mismatch)")
	}

	members = make(map[string][]byte)
	pos := len(arMagic)

	for pos < len(data) {
		if pos+arHdrSize > len(data) {
			break
		}
		hdr := data[pos : pos+arHdrSize]

		// Verify ar magic
		if string(hdr[58:60]) != arFileMagic {
			return nil, nil, fmt.Errorf("invalid ar header magic at offset %d", pos)
		}

		name := strings.TrimRight(string(hdr[0:16]), " /")
		var size int
		if _, err := fmt.Sscanf(strings.TrimSpace(string(hdr[48:58])), "%d", &size); err != nil {
			return nil, nil, fmt.Errorf("invalid ar file size at offset %d", pos)
		}

		pos += arHdrSize
		if pos+size > len(data) {
			return nil, nil, fmt.Errorf("truncated ar member %q (need %d bytes, have %d)", name, size, len(data)-pos)
		}

		fileData := make([]byte, size)
		copy(fileData, data[pos:pos+size])

		members[name] = fileData
		order = append(order, arEntry{name: name, data: fileData})

		pos += size
		if size%2 != 0 {
			pos++ // padding byte
		}
	}
	return members, order, nil
}

// rebuildArWithout reconstructs an ar archive omitting one member.
// Reproduces original headers from the source archive to
// preserve exact order and metadata.
func rebuildArWithout(original []byte, order []arEntry, skip string) []byte {
	var buf bytes.Buffer
	buf.WriteString(arMagic)

	pos := len(arMagic)
	for _, entry := range order {
		if entry.name == skip {
			// Advance pos in the original
			pos += arHdrSize + len(entry.data)
			if len(entry.data)%2 != 0 {
				pos++
			}
			continue
		}
		// Copy the original header (preserves timestamp, uid, gid, mode)
		if pos+arHdrSize <= len(original) {
			buf.Write(original[pos : pos+arHdrSize])
		}
		buf.Write(entry.data)
		if len(entry.data)%2 != 0 {
			buf.WriteByte(0) // padding
		}
		pos += arHdrSize + len(entry.data)
		if len(entry.data)%2 != 0 {
			pos++
		}
	}
	return buf.Bytes()
}

// ─────────────────────────────────────────────
// Helpers
// ─────────────────────────────────────────────

func parseGpgvError(stderr string) string {
	for _, line := range strings.Split(stderr, "\n") {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "BAD signature") {
			return "bad signature (data tampered)"
		}
		if strings.Contains(line, "No public key") {
			return "no matching public key in keyring"
		}
		if strings.Contains(line, "key expired") {
			return "signing key has expired"
		}
		if strings.Contains(line, "key revoked") {
			return "signing key has been revoked"
		}
	}
	if stderr != "" {
		return strings.TrimSpace(stderr)
	}
	return "signature verification failed"
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ─────────────────────────────────────────────
// Sentinel errors
// ─────────────────────────────────────────────

type gpgError string

func (e gpgError) Error() string { return string(e) }

const (
	ErrNoSignature     = gpgError("deb has no GPG signature (_gpgorigin absent)")
	ErrInvalidSignature = gpgError("GPG signature verification failed")
)

func IsNoSignature(err error) bool     { return err == ErrNoSignature }
func IsInvalidSignature(err error) bool { return err == ErrInvalidSignature }
