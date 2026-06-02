package logsfile

import (
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// FileBackend writes JSON lines to a file with size-based rotation.
type FileBackend struct {
	mu         sync.Mutex
	path       string
	maxSizeB   int64
	maxBackups int
	compress   bool
	f          *os.File
	size       int64
}

// New opens (or creates) the log file and returns a FileBackend.
func New(path string, maxSizeMB, maxBackups int, compress bool) (*FileBackend, error) {
	if maxSizeMB <= 0 {
		maxSizeMB = 100
	}
	if maxBackups <= 0 {
		maxBackups = 5
	}
	b := &FileBackend{
		path:       path,
		maxSizeB:   int64(maxSizeMB) * 1024 * 1024,
		maxBackups: maxBackups,
		compress:   compress,
	}
	if err := b.open(); err != nil {
		return nil, err
	}
	return b, nil
}

func (b *FileBackend) open() error {
	if err := os.MkdirAll(filepath.Dir(b.path), 0o755); err != nil {
		return fmt.Errorf("log file mkdir: %w", err)
	}
	f, err := os.OpenFile(b.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("log file open: %w", err)
	}
	info, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	b.f = f
	b.size = info.Size()
	return nil
}

func (b *FileBackend) Write(_ time.Time, line []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.size+int64(len(line))+1 > b.maxSizeB {
		if err := b.rotate(); err != nil {
			return err
		}
	}

	n, err := fmt.Fprintf(b.f, "%s\n", line)
	b.size += int64(n)
	return err
}

func (b *FileBackend) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.f != nil {
		return b.f.Close()
	}
	return nil
}

// rotate closes the current file, shifts archives, and recreates the file.
func (b *FileBackend) rotate() error {
	if b.f != nil {
		b.f.Close()
		b.f = nil
	}

	ext := filepath.Ext(b.path)
	base := b.path[:len(b.path)-len(ext)]

	// Supprime la plus ancienne archive si on a atteint maxBackups.
	oldest := fmt.Sprintf("%s.%d%s", base, b.maxBackups, ext)
	if b.compress {
		oldest += ".gz"
	}
	os.Remove(oldest)

	// Shift existing archives: .4 → .5, .3 → .4, …
	for i := b.maxBackups - 1; i >= 1; i-- {
		src := fmt.Sprintf("%s.%d%s", base, i, ext)
		dst := fmt.Sprintf("%s.%d%s", base, i+1, ext)
		if b.compress {
			src += ".gz"
			dst += ".gz"
		}
		os.Rename(src, dst)
	}

	// Move/compress the current file to .1
	dest := fmt.Sprintf("%s.1%s", base, ext)
	if b.compress {
		if err := gzipFile(b.path, dest+".gz"); err == nil {
			os.Remove(b.path)
		}
	} else {
		os.Rename(b.path, dest)
	}

	return b.open()
}

func gzipFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.OpenFile(dst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return err
	}
	defer out.Close()

	gz := gzip.NewWriter(out)
	if _, err := io.Copy(gz, in); err != nil {
		return err
	}
	return gz.Close()
}
