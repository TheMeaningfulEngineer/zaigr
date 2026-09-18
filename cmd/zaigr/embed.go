package main

import (
	"bytes"
	_ "embed"
	"strings"
)

//go:embed vm_data/bzImage
var embeddedKernel []byte

//go:embed vm_data/base-rootfs.img.zst
var embeddedRootfs []byte

//go:embed vm_data/base-rootfs.version
var embeddedRootfsVersion string

// embeddedVersion extracts a version string from embedded binary data
// by searching for a prefix and returning the following 7 characters.
func embeddedVersion(data []byte, prefix string) string {
	p := []byte(prefix)
	if idx := bytes.Index(data, p); idx >= 0 {
		start := idx + len(p)
		end := start + 7
		if end <= len(data) {
			return string(data[start:end])
		}
	}
	return "unknown"
}

func baseRootfsVersion() string {
	return strings.TrimSpace(embeddedRootfsVersion)
}

func buildingBlocksVersion() string {
	version := baseRootfsVersion()
	if idx := strings.LastIndex(version, "-"); idx >= 0 && idx+1 < len(version) {
		return version[idx+1:]
	}
	return version
}
