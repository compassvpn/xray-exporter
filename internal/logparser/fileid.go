package logparser

import (
	"hash/fnv"
	"os"
)

// Number of leading bytes hashed into a file's fingerprint.
const fingerprintSize = 256

// Identifies one log file, so we resume appends at the right offset but read a
// replaced file from the start.
//
// The inode alone isn't enough: after a rotation deletes the old log, the new
// one can get the same inode. If it has already grown past our offset by the
// next pass, the rotation goes unnoticed and we skip lines. So we also hash the
// first bytes, which never change once an append-only log is that long.
type fileIdentity struct {
	dev, ino    uint64
	fingerprint uint64
	hasPrint    bool // false while the file is too short to hash.
	known       bool // false before the first pass.
}

func identifyFile(file *os.File, fileInfo os.FileInfo) fileIdentity {
	dev, ino := getFileID(file, fileInfo)
	sum, ok := fingerprintFile(file, fileInfo.Size())

	return fileIdentity{
		dev:         dev,
		ino:         ino,
		fingerprint: sum,
		hasPrint:    ok,
		known:       true,
	}
}

// Reports whether an offset recorded against prev still applies to id.
func (id fileIdentity) sameFileAs(prev fileIdentity) bool {
	if id.dev != prev.dev || id.ino != prev.ino {
		return false
	}

	// Same inode, so only a different hash proves the file was replaced. If
	// either side is too short to hash, the offset-past-end check in
	// parseLogFile catches replacement instead.
	if id.hasPrint && prev.hasPrint {
		return id.fingerprint == prev.fingerprint
	}

	return true
}

// Hashes the first fingerprintSize bytes. Returns false while the file is
// shorter than that, since a hash of a partial prefix would keep changing as the
// file grows and every pass would think it was a new file.
func fingerprintFile(file *os.File, size int64) (uint64, bool) {
	if size < fingerprintSize {
		return 0, false
	}

	buf := make([]byte, fingerprintSize)
	if _, err := file.ReadAt(buf, 0); err != nil {
		return 0, false
	}

	h := fnv.New64a()
	_, _ = h.Write(buf)

	return h.Sum64(), true
}
