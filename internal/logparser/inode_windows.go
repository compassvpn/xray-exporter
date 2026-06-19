//go:build windows

// Cross-platform file tracking functionality.
// This Windows implementation uses the NTFS file index (a stable per-file id,
// the closest equivalent to a Unix inode) so that appending to a log file is
// NOT mistaken for a rotation. ModTime is only used as a last-resort fallback.
package logparser

import (
	"os"

	"golang.org/x/sys/windows"
)

// Returns a stable file identifier for Windows systems.
// It reads the NTFS file index via GetFileInformationByHandle, which (unlike
// ModTime) does not change when the file is appended to, so an actively-written
// log is not repeatedly re-read from the start.
func getInode(file *os.File, fileInfo os.FileInfo) uint64 {
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(windows.Handle(file.Fd()), &info); err == nil {
		return uint64(info.FileIndexHigh)<<32 | uint64(info.FileIndexLow)
	}
	// Fallback for filesystems without a stable file index (e.g. some FAT/network
	// shares): use ModTime. This may over-detect rotation but never under-detects.
	return uint64(fileInfo.ModTime().UnixNano())
}
