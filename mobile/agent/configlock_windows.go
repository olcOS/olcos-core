//go:build windows

package agent

// lockConfig is a no-op on Windows: the agent runs on the Linux server (see
// configlock_unix.go), and Windows only builds and tests the package, where
// every read-modify-write runs in one process.
func lockConfig(dir string) (unlock func(), err error) {
	return func() {}, nil
}
