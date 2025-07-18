//go:build windows

// Cross-platform file tracking functionality.
// This Windows implementation uses modification time as a fallback since Windows
// doesn't have Unix-style inodes.
package logparser

import (
	"os"
)

// Returns a file identifier for Windows systems.
// Since Windows doesn't have inodes like Unix systems, we use the file's
// modification time as a unique identifier. This works for log rotation detection
// because rotated files typically have different timestamps.
func getInode(fileInfo os.FileInfo) uint64 {
	// Windows doesn't have inodes, use modification time as unique identifier
	return uint64(fileInfo.ModTime().UnixNano())
}
