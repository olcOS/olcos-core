//go:build !windows

package agent

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

// lockConfig takes the exclusive advisory lock on dir/config.lock that every
// read-modify-write of config.json holds, the running agent's and the CLI's
// alike (the phones run `olcos-agent invite` and `revoke-invite` while serve
// runs), so neither writes over what the other has just written. It is the
// kernel's flock: a process that dies holding it lets go of it.
func lockConfig(dir string) (unlock func(), err error) {
	f, err := os.OpenFile(filepath.Join(dir, configLockFile), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	fd := int(f.Fd())
	for {
		err = syscall.Flock(fd, syscall.LOCK_EX)
		if !errors.Is(err, syscall.EINTR) {
			break
		}
	}
	if err != nil {
		_ = f.Close()
		return nil, err
	}
	return func() {
		_ = syscall.Flock(fd, syscall.LOCK_UN)
		_ = f.Close()
	}, nil
}
