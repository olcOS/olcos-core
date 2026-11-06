//go:build !windows

package server

import (
	"errors"
	"fmt"

	"golang.org/x/sys/unix"
)

// fifoFile is the write end of the access FIFO: a descriptor of this package's
// own, written to with write(2) directly. A file of the os package is polled by
// the runtime and would wait for room in a full pipe; this one is told EAGAIN
// at once, and the line is dropped.
//
// ai-generated: the whole type (access_log).
type fifoFile struct{ fd int }

// Write writes line, which is at most maxAccessLine bytes: a write that size to
// a pipe is atomic, so it is made whole or not at all.
func (f *fifoFile) Write(line []byte) (int, error) {
	n, err := unix.Write(f.fd, line)
	if errors.Is(err, unix.EAGAIN) {
		return 0, errAccessFull
	}
	if err != nil {
		return 0, fmt.Errorf("write: %w", err)
	}
	return n, nil
}

func (f *fifoFile) Close() error {
	if err := unix.Close(f.fd); err != nil {
		return fmt.Errorf("close: %w", err)
	}
	return nil
}

// openAccessFIFO opens the FIFO at path for writing without waiting: only if
// it is a FIFO, which is looked at before the open and again on the descriptor
// the open gave, so that a path swapped for something else between the two is
// closed unwritten. With no process reading the FIFO the open fails at once
// (ENXIO).
//
// ai-generated: the whole function (access_log).
func openAccessFIFO(path string) (accessFile, error) {
	var info unix.Stat_t
	if err := unix.Stat(path, &info); err != nil {
		return nil, fmt.Errorf("stat: %w", err)
	}
	if info.Mode&unix.S_IFMT != unix.S_IFIFO {
		return nil, errNotFIFO
	}
	fd, err := unix.Open(path, unix.O_WRONLY|unix.O_NONBLOCK|unix.O_CLOEXEC|unix.O_NOCTTY, 0)
	if err != nil {
		return nil, fmt.Errorf("open: %w", err)
	}
	if err = unix.Fstat(fd, &info); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("fstat: %w", err)
	}
	if info.Mode&unix.S_IFMT != unix.S_IFIFO {
		_ = unix.Close(fd)
		return nil, errNotFIFO
	}
	return &fifoFile{fd: fd}, nil
}
