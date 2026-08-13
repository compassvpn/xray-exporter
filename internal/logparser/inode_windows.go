//go:build windows

package logparser

import (
	"os"

	"golang.org/x/sys/windows"
)

// Returns the volume serial number and NTFS file index, the closest Windows
// equivalents of device and inode. The file index, unlike ModTime, doesn't change
// on append, so a log being written to isn't re-read from the start every pass.
func getFileID(file *os.File, fileInfo os.FileInfo) (dev, ino uint64) {
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(windows.Handle(file.Fd()), &info); err == nil {
		return uint64(info.VolumeSerialNumber), uint64(info.FileIndexHigh)<<32 | uint64(info.FileIndexLow)
	}
	// Fallback for filesystems without a stable file index (e.g. some FAT/network
	// shares): use ModTime. This may over-detect rotation but never under-detects.
	return 0, uint64(fileInfo.ModTime().UnixNano())
}
