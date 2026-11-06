package agent

import (
	"errors"
	"net"
	"testing"
	"time"
)

// A listener capped at one connection hands out the second only after the
// first is closed, and Close wakes an Accept that waits for a slot.
func TestLimitListenerHoldsTheCap(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	lim := newLimitListener(ln, 1)
	defer lim.Close()

	for range 2 {
		c, err := net.Dial("tcp", ln.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
	}

	first, err := lim.Accept()
	if err != nil {
		t.Fatal(err)
	}
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := lim.Accept()
		if err != nil {
			accepted <- nil
			return
		}
		accepted <- c
	}()
	select {
	case <-accepted:
		t.Fatal("a second connection was handed out while the first was open")
	case <-time.After(150 * time.Millisecond):
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	_ = first.Close() // a second Close must not give back a second slot
	select {
	case c := <-accepted:
		if c == nil {
			t.Fatal("Accept failed after the first connection was closed")
		}
		c.Close()
	case <-time.After(2 * time.Second):
		t.Fatal("the slot was not given back when the connection closed")
	}
	if n := len(lim.slots); n != 0 {
		t.Fatalf("%d slots held after both connections closed, want 0", n)
	}

	// A third Accept waits for a connection that never comes; Close ends it.
	done := make(chan error, 1)
	go func() {
		_, err := lim.Accept()
		done <- err
	}()
	time.Sleep(50 * time.Millisecond)
	lim.Close()
	select {
	case err := <-done:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("Accept after Close = %v, want net.ErrClosed", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Close did not end a waiting Accept")
	}
}
