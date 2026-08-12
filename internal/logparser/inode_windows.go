//go:build windows

package logparser

import (
	"os"

	"golang.org/x/sys/windows"
)

// Returns a stable per-file id (the closest Windows equivalent to a Unix
// inode), used to detect log rotation. It reads the NTFS file index via
// GetFileInformationByHandle, which (unlike ModTime) does not change on
// append, so an actively-written log is not repeatedly re-read from the start.
func getInode(file *os.File, fileInfo os.FileInfo) uint64 {
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(windows.Handle(file.Fd()), &info); err == nil {
		return uint64(info.FileIndexHigh)<<32 | uint64(info.FileIndexLow)
	}
	// Fallback for filesystems without a stable file index (e.g. some FAT/network
	// shares): use ModTime. This may over-detect rotation but never under-detects.
	return uint64(fileInfo.ModTime().UnixNano())
}
