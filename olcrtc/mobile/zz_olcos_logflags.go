// zz_olcos_logflags.go is an olcOS addition, not upstream code.
//
// The core logs through the stdlib `log` package and leaves its flags at the
// default date-and-time prefix. The apps' log pipelines (cleanup and
// redaction, the wedge detector's signatures) read lines prefixed by the time
// only ("15:04:05 "), so this pins that shape once, when the package loads.
//
// It is kept in its own file so that an update of olcrtc/ never conflicts
// with it, and it is left out of server/olcrtc-core.patch: the server binary
// does not need it.
package mobile

import "log"

//nolint:gochecknoinits // must run before the first log line
func init() {
	log.SetFlags(log.Ltime)
}
