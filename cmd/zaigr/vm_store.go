package main

import (
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

const resourceVersionBytes = 6

func canonicalPath(path string) string {
	cleaned := path
	if abs, err := filepath.Abs(path); err == nil {
		cleaned = abs
	}
	cleaned = filepath.Clean(cleaned)
	if resolved, err := filepath.EvalSymlinks(cleaned); err == nil {
		cleaned = resolved
	}
	return cleaned
}

// storeDir returns the project-specific store directory under ~/.zaigr/store/<hash>.
// The hash is derived from the current working directory so each project gets its own store.
func storeDir() string {
	cwd, _ := os.Getwd()
	return storeDirForPath(cwd)
}

func storeDirForPath(path string) string {
	home, _ := os.UserHomeDir()
	h := sha256.Sum256([]byte(canonicalPath(path)))
	return filepath.Join(home, ".zaigr", "store", fmt.Sprintf("%x", h[:4])[:7])
}

func contentVersion(content []byte) string {
	sum := sha256.Sum256(content)
	return fmt.Sprintf("%x", sum[:resourceVersionBytes])
}

func resourceVersionTimestamp(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format("060102-1504")
}

func storedResourceVersionLabel(hash, timestamp string) string {
	if hash == "" {
		return timestamp
	}
	if timestamp == "" {
		return hash
	}
	return hash + "-" + timestamp
}

func versionedResourceIdentity(name, version string) string {
	if name == "" {
		return ""
	}
	if version == "" {
		return name
	}
	return name + "@" + version
}
