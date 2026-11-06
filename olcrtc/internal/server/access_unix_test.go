//go:build !windows

package server

import (
	"bufio"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// ai-generated: the whole file (access_log on a real FIFO: no reader, a
// reader that does not read, a reader that leaves, and what is not a FIFO).

const accessTestFileContent = "not a FIFO, and never written to"

func makeAccessFIFO(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "access.fifo")
	if err := unix.Mkfifo(path, 0o600); err != nil {
		t.Fatalf("Mkfifo() error = %v", err)
	}
	return path
}

// holdAccessFIFO opens the FIFO for reading and writing, as the agent does, so
// that it has a reader whatever the writers do. It reads nothing.
func holdAccessFIFO(t *testing.T, path string) *os.File {
	t.Helper()
	// #nosec G304 -- the FIFO this test made.
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("open the FIFO for reading: %v", err)
	}
	t.Cleanup(func() { _ = file.Close() })
	return file
}

// accessReader holds the FIFO as the agent does and collects the lines that
// come, without their newline.
type accessReader struct {
	mu    sync.Mutex
	lines []string
}

func startAccessReader(t *testing.T, path string) *accessReader {
	t.Helper()
	file := holdAccessFIFO(t, path)
	reader := &accessReader{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			reader.mu.Lock()
			reader.lines = append(reader.lines, scanner.Text())
			reader.mu.Unlock()
		}
	}()
	t.Cleanup(func() {
		_ = file.Close()
		<-done
	})
	return reader
}

func (r *accessReader) got() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.lines...)
}

// waitFor returns the lines read once there are n of them.
func (r *accessReader) waitFor(t *testing.T, n int) []string {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if got := r.got(); len(got) >= n {
			return got
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("read %d lines in 10 s, want %d: %q", len(r.got()), n, r.got())
	return nil
}

// readAvailable reads what a FIFO holds now, and stops at the first moment
// there is nothing more.
func readAvailable(t *testing.T, file *os.File) string {
	t.Helper()
	var data []byte
	buf := make([]byte, 4096)
	for {
		_ = file.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		n, err := file.Read(buf)
		data = append(data, buf[:n]...)
		if err != nil {
			if !errors.Is(err, os.ErrDeadlineExceeded) {
				t.Fatalf("read the FIFO: %v", err)
			}
			return string(data)
		}
	}
}

func accessTestLineFor(i int) string {
	return accessTestLine(accessTestNetworkTCP, "h"+strconv.Itoa(i)+".test:443")
}

// With nothing reading the FIFO, a line is dropped at once: the write does not
// wait for a reader, and the open is not tried again before ten seconds.
func TestAccessFIFOWithNoReaderIsNotWaitedFor(t *testing.T) {
	path := makeAccessFIFO(t)
	if _, err := openAccessFIFO(path); !errors.Is(err, unix.ENXIO) {
		t.Fatalf("openAccessFIFO(a FIFO nobody reads) error = %v, want ENXIO", err)
	}

	now := time.Date(2026, time.November, 3, 15, 4, 5, 0, time.UTC)
	opens := 0
	sink := newAccessSink(path)
	sink.now = func() time.Time { return now }
	sink.open = func(p string) (accessFile, error) {
		opens++
		return openAccessFIFO(p)
	}
	t.Cleanup(sink.close)

	returned := make(chan struct{})
	go func() {
		defer close(returned)
		sink.write([]byte(accessTestLineFor(1)))
	}()
	select {
	case <-returned:
	case <-time.After(5 * time.Second):
		t.Fatal("a write with no reader on the FIFO did not return")
	}
	now = now.Add(accessReopenEvery - time.Second)
	sink.write([]byte(accessTestLineFor(2)))
	if opens != 1 {
		t.Fatalf("opens = %d, want 1: the path is tried at most every %s", opens, accessReopenEvery)
	}

	// A reader comes. Ten seconds after the try, the next line opens the FIFO
	// again and is delivered.
	reader := startAccessReader(t, path)
	now = now.Add(time.Second)
	sink.write([]byte(accessTestLineFor(3)))
	got := reader.waitFor(t, 1)
	if want := strings.TrimSuffix(accessTestLineFor(3), "\n"); len(got) != 1 || got[0] != want {
		t.Fatalf("lines read = %q, want [%q]: the two lines written with no reader are gone", got, want)
	}
}

// Several servers write one FIFO, each through a descriptor of its own, and
// the reader gets every line whole. The lines together are less than the 4096
// bytes any pipe holds, so none is dropped for want of room.
func TestAccessFIFOGivesAReaderWholeLinesFromManyServers(t *testing.T) {
	path := makeAccessFIFO(t)
	reader := startAccessReader(t, path)

	const servers, each = 8, 3
	var wg sync.WaitGroup
	for w := range servers {
		sink := newAccessSink(path)
		t.Cleanup(sink.close)
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range each {
				sink.write([]byte(accessTestLineFor(w*each + i)))
			}
		}()
	}
	wg.Wait()

	got := reader.waitFor(t, servers*each)
	want := make(map[string]bool, servers*each)
	for i := range servers * each {
		want[strings.TrimSuffix(accessTestLineFor(i), "\n")] = true
	}
	for _, line := range got {
		if !want[line] {
			t.Errorf("line %q is not one that was written whole", line)
		}
		delete(want, line)
	}
	if len(want) != 0 || len(got) != servers*each {
		t.Fatalf("%d lines read, %d lines never came, want all %d", len(got), len(want), servers*each)
	}
}

// A reader that holds the FIFO and reads nothing fills the pipe: the writes
// go on returning, the lines that do not fit are dropped, what the pipe holds
// is whole lines, and once the reader reads, the lines come again.
func TestAccessFIFOThatIsNotReadNeverBlocksAndDropsLines(t *testing.T) {
	path := makeAccessFIFO(t)
	holder := holdAccessFIFO(t, path)
	sink := newAccessSink(path)
	t.Cleanup(sink.close)

	const written = 3000 // about 370 KB, more than any pipe holds
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := range written {
			sink.write([]byte(accessTestLineFor(i)))
		}
	}()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("writes to a FIFO nobody reads did not return")
	}

	// How much a pipe holds is the system's: 64 KiB, or two pages for a user
	// that has more pipes than its share. Some lines, and not all.
	held := strings.Split(strings.TrimSuffix(readAvailable(t, holder), "\n"), "\n")
	if len(held) < 1 || len(held) >= written {
		t.Fatalf("the pipe held %d lines of the %d written, want some, and not all", len(held), written)
	}
	for i, line := range held {
		if want := strings.TrimSuffix(accessTestLineFor(i), "\n"); line != want {
			t.Fatalf("line %d the pipe held = %q, want %q: a line is whole or not there", i, line, want)
		}
	}

	sink.write([]byte(accessTestLineFor(written)))
	if got, want := readAvailable(t, holder), accessTestLineFor(written); got != want {
		t.Fatalf("after the reader read, a line came as %q, want %q", got, want)
	}
}

// A reader that leaves makes the next write fail with EPIPE, which is no more
// than the file closed and a line lost: the process is not killed by SIGPIPE.
// A reader that comes back is served from the next line on.
func TestAccessFIFOReaderThatLeavesCostsTheFileNotTheProcess(t *testing.T) {
	path := makeAccessFIFO(t)
	// #nosec G304 -- the FIFO this test made.
	first, err := os.OpenFile(path, os.O_RDONLY|unix.O_NONBLOCK, 0)
	if err != nil {
		t.Fatalf("open the FIFO for reading: %v", err)
	}
	now := time.Date(2026, time.November, 3, 15, 4, 5, 0, time.UTC)
	sink := newAccessSink(path)
	sink.now = func() time.Time { return now }
	t.Cleanup(sink.close)

	sink.write([]byte(accessTestLineFor(1)))
	if got, want := readAvailable(t, first), accessTestLineFor(1); got != want {
		t.Fatalf("the first reader read %q, want %q", got, want)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("close the first reader: %v", err)
	}

	sink.write([]byte(accessTestLineFor(2)))
	if sink.file != nil {
		t.Fatal("the file was kept after its write failed for want of a reader")
	}

	second := startAccessReader(t, path)
	now = now.Add(time.Minute)
	sink.write([]byte(accessTestLineFor(3)))
	got := second.waitFor(t, 1)
	if want := strings.TrimSuffix(accessTestLineFor(3), "\n"); len(got) != 1 || got[0] != want {
		t.Fatalf("the second reader read %q, want [%q]", got, want)
	}
}

// Only a FIFO is opened: a regular file, a directory and a link to either are
// refused, unwritten, and a link to a FIFO is a FIFO. What is opened is open
// for writing alone, without waiting, and is not kept by a child process.
func TestOpenAccessFIFOOpensOnlyAFIFO(t *testing.T) {
	dir := t.TempDir()
	regular := filepath.Join(dir, "regular")
	if err := os.WriteFile(regular, []byte(accessTestFileContent), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	fifo := makeAccessFIFO(t)
	holdAccessFIFO(t, fifo)
	linkToRegular := filepath.Join(dir, "link-to-regular")
	linkToFIFO := filepath.Join(dir, "link-to-fifo")
	for link, target := range map[string]string{linkToRegular: regular, linkToFIFO: fifo} {
		if err := os.Symlink(target, link); err != nil {
			t.Fatalf("symlink: %v", err)
		}
	}

	for name, path := range map[string]string{"a regular file": regular, "a directory": dir, "a link to a file": linkToRegular} {
		if file, err := openAccessFIFO(path); !errors.Is(err, errNotFIFO) {
			t.Errorf("openAccessFIFO(%s) = %v, %v, want %v", name, file, err, errNotFIFO)
		}
	}
	if _, err := openAccessFIFO(filepath.Join(dir, "missing")); !errors.Is(err, unix.ENOENT) {
		t.Errorf("openAccessFIFO(a path that is not there) error = %v, want ENOENT", err)
	}
	if got, err := os.ReadFile(regular); err != nil || string(got) != accessTestFileContent {
		t.Errorf("the regular file now holds %q, %v: it was written to", got, err)
	}

	for name, path := range map[string]string{"a FIFO": fifo, "a link to a FIFO": linkToFIFO} {
		file, err := openAccessFIFO(path)
		if err != nil {
			t.Fatalf("openAccessFIFO(%s) error = %v", name, err)
		}
		fifoFile, ok := file.(*fifoFile)
		if !ok {
			t.Fatalf("openAccessFIFO(%s) = %T, want *fifoFile", name, file)
		}
		flags, err := unix.FcntlInt(uintptr(fifoFile.fd), unix.F_GETFL, 0)
		if err != nil {
			t.Fatalf("F_GETFL: %v", err)
		}
		if flags&unix.O_ACCMODE != unix.O_WRONLY || flags&unix.O_NONBLOCK == 0 {
			t.Errorf("openAccessFIFO(%s) opened with flags %#x, want O_WRONLY|O_NONBLOCK", name, flags)
		}
		fdFlags, err := unix.FcntlInt(uintptr(fifoFile.fd), unix.F_GETFD, 0)
		if err != nil || fdFlags&unix.FD_CLOEXEC == 0 {
			t.Errorf("openAccessFIFO(%s) descriptor flags = %#x, %v, want FD_CLOEXEC", name, fdFlags, err)
		}
		if err := file.Close(); err != nil {
			t.Errorf("Close() error = %v", err)
		}
	}
}
