//go:build unix

package logparser

import (
	"os"
	"syscall"
)

// Returns the device and inode numbers, which together identify a file even if
// two filesystems happen to use the same inode number. Returns zeroes if they
// can't be determined (rare on Unix).
func getFileID(_ *os.File, fileInfo os.FileInfo) (dev, ino uint64) {
	if stat, ok := fileInfo.Sys().(*syscall.Stat_t); ok {
		return uint64(stat.Dev), uint64(stat.Ino)
	}
	return 0, 0
}
