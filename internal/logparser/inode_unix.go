//go:build unix

package logparser

import (
	"os"
	"syscall"
)

// Returns the inode number of a file, used to detect log rotation.
// Returns 0 if the inode cannot be determined (rare on Unix systems).
func getInode(_ *os.File, fileInfo os.FileInfo) uint64 {
	if stat, ok := fileInfo.Sys().(*syscall.Stat_t); ok {
		return stat.Ino
	}
	return 0
}
