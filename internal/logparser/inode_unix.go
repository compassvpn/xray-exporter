//go:build unix

// Cross-platform file tracking functionality.
// This Unix implementation uses actual inode numbers for reliable log rotation detection.
package logparser

import (
	"os"
	"syscall"
)

// Returns the inode number of a file on Unix systems.
// Inodes are unique identifiers that help detect when log files are rotated or replaced.
// Returns 0 if the inode cannot be determined (rare on Unix systems).
func getInode(fileInfo os.FileInfo) uint64 {
	if stat, ok := fileInfo.Sys().(*syscall.Stat_t); ok {
		return stat.Ino
	}
	return 0
}
