package tftp

import "io"

// BootfileProvider supplies bootfiles by filename.
// Implementations should return a readable stream and its size in bytes
// (if known; use -1 if unknown) or an error if the file cannot be provided.
type BootfileProvider interface {
	GetBootfile(filename string) (io.ReadCloser, int64, error)
}
