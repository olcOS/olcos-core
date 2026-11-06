//go:build !windows

package agent

import (
	"testing"
	"time"
)

// The lock serializes every read-modify-write of config.json: a second taker
// (another process, or here another open of the same file) waits until the
// first lets go.
func TestConfigLockExcludesASecondHolder(t *testing.T) {
	dir := t.TempDir()
	unlock, err := lockConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	got := make(chan struct{})
	go func() {
		if second, err := lockConfig(dir); err == nil {
			second()
		}
		close(got)
	}()
	select {
	case <-got:
		t.Fatal("a second taker got the lock while the first held it")
	case <-time.After(150 * time.Millisecond):
	}
	unlock()
	select {
	case <-got:
	case <-time.After(5 * time.Second):
		t.Fatal("the lock was not handed over")
	}
}
