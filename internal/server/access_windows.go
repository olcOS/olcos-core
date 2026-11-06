//go:build windows

package server

import "errors"

// errAccessUnsupported is a system without the FIFO access_log is written for.
var errAccessUnsupported = errors.New("a FIFO access log is not supported on this system")

// openAccessFIFO is what access_log comes to on Windows, which has no FIFO to
// open this way: the log says so once and writes nothing.
//
// ai-generated: the whole function (access_log).
func openAccessFIFO(_ string) (accessFile, error) {
	return nil, errAccessUnsupported
}
