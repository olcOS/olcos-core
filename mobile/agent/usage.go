package agent

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Who used the tunnel, when, and how much. The server records it in one place
// only, the olcrtc containers' own logs, where the core writes per session:
//
//	session opened: id=<sid> device=<device> claims=map[]
//	traffic: session=<sid> in=<bytes> out=<bytes>     (one line per finished stream)
//	peer disconnected: device=<device> session=<sid> reason=<r> duration=<d>
//	session closed: id=<sid> reason=<r>
//
// and `podman logs --timestamps` puts the RFC 3339 time in front of each line.
// A device is the id its client announced: a phone that took a device invite
// announces `inv-<tag>-<its own name>`, which is how the owner's Devices screen
// tells its invites apart. `in` is what a device sent through the server,
// `out` what it received. The apps' connection checks (`olc-ping-…`) are not
// devices and are left out.
//
// The collector reads each running container's new lines every minute, and
// when the owner asks (at most every usageMinGap). Per container it remembers
// the time of the last line it read, asks podman only for the lines since
// then and skips any not strictly after it. Totals, open sessions and those
// cursors live in usage.json next to config.json, so a restart of the agent
// neither loses nor counts anything twice.

const (
	usageFile         = "usage.json"
	usageInterval     = 60 * time.Second  // the background pass
	usageMinGap       = 20 * time.Second  // an owner's request starts a pass at most this often
	usageServeWait    = 2 * time.Second   // and waits this long for it before answering
	usageFirstSince   = "720h"            // a container read for the first time: its last 30 days
	usageOnlineWindow = 180 * time.Second // online: an open session, seen this recently
	usageSessionTTL   = 24 * time.Hour    // a session not seen for this long is forgotten
	usageMaxSessions  = 4096
	usageMaxDevices   = 1024
	usageMaxCursors   = 64
	usageMaxID        = 128              // a longer id is not a client's
	usageLogTimeout   = 60 * time.Second // one container's `podman logs`
	usageProbePrefix  = "olc-ping-"
)

var usageContainerRE = regexp.MustCompile(`^olcrtc-server-[a-z0-9-]+$`)

// --- parsing ---------------------------------------------------------------

type usageKind int

const (
	usageOther   usageKind = iota // any other line: it only moves the cursor
	usageOpened                   // session opened
	usageTraffic                  // a finished stream's bytes
	usageGone                     // peer disconnected
	usageClosed                   // session closed
)

type usageEvent struct {
	kind    usageKind
	session string
	device  string
	in, out int64
}

var (
	usageOpenedRE  = regexp.MustCompile(`session opened: id=(\S+) device=(\S+)`)
	usageTrafficRE = regexp.MustCompile(`traffic: session=(\S+) in=(\d+) out=(\d+)`)
	usageGoneRE    = regexp.MustCompile(`peer disconnected: device=(\S+) session=(\S+)`)
	usageClosedRE  = regexp.MustCompile(`session closed: id=(\S+)`)
)

// parseUsageLine splits one `podman logs --timestamps` line into its time and
// the event it carries (usageOther for every line the collector does not
// read). ok is false for a line without a leading timestamp: it says nothing,
// not even how far the log was read.
func parseUsageLine(line string) (at time.Time, ev usageEvent, ok bool) {
	line = strings.TrimRight(line, "\r\n")
	sp := strings.IndexByte(line, ' ')
	if sp <= 0 {
		return time.Time{}, usageEvent{}, false
	}
	at, err := time.Parse(time.RFC3339Nano, line[:sp])
	if err != nil {
		return time.Time{}, usageEvent{}, false
	}
	return at, parseUsageEvent(line[sp+1:]), true
}

// parseUsageEvent reads the core's message, wherever the log prefix (Go's
// date and time by default) leaves it.
func parseUsageEvent(msg string) usageEvent {
	switch {
	case strings.Contains(msg, "traffic: session="):
		if m := usageTrafficRE.FindStringSubmatch(msg); m != nil {
			return usageEvent{kind: usageTraffic, session: m[1], in: parseByteCount(m[2]), out: parseByteCount(m[3])}
		}
	case strings.Contains(msg, "session opened: id="):
		if m := usageOpenedRE.FindStringSubmatch(msg); m != nil {
			return usageEvent{kind: usageOpened, session: m[1], device: m[2]}
		}
	case strings.Contains(msg, "peer disconnected: device="):
		if m := usageGoneRE.FindStringSubmatch(msg); m != nil {
			return usageEvent{kind: usageGone, device: m[1], session: m[2]}
		}
	case strings.Contains(msg, "session closed: id="):
		if m := usageClosedRE.FindStringSubmatch(msg); m != nil {
			return usageEvent{kind: usageClosed, session: m[1]}
		}
	}
	return usageEvent{}
}

func parseByteCount(s string) int64 {
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil || n > math.MaxInt64 {
		return math.MaxInt64 // only an overflow gets here: the regexp took digits
	}
	return int64(n)
}

func addBytes(a, b int64) int64 {
	if b > math.MaxInt64-a {
		return math.MaxInt64
	}
	return a + b
}

func usableID(id string) bool { return id != "" && len(id) <= usageMaxID }

// --- the totals ------------------------------------------------------------

type usageDevice struct {
	LastSeen int64 `json:"last_seen"` // unix seconds of the latest line about it
	In       int64 `json:"in"`
	Out      int64 `json:"out"`
	Sessions int64 `json:"sessions"`
}

func (d *usageDevice) seen(sec int64) { d.LastSeen = max(d.LastSeen, sec) }

// usageSession maps one session to its device: the traffic lines name only
// the session. Kept after the session closes too, because a stream still
// running then finishes, and is logged, later.
type usageSession struct {
	Device   string `json:"device"`
	Open     bool   `json:"open,omitempty"`
	LastSeen int64  `json:"last_seen"`
}

// usageData is what usage.json holds. Sessions are keyed by container and
// session id; Cursors hold, per container, the time (unix nanoseconds) of the
// last log line read.
type usageData struct {
	Devices  map[string]*usageDevice  `json:"devices"`
	Sessions map[string]*usageSession `json:"sessions"`
	Cursors  map[string]int64         `json:"cursors"`
}

func newUsageData() usageData {
	return usageData{
		Devices:  map[string]*usageDevice{},
		Sessions: map[string]*usageSession{},
		Cursors:  map[string]int64{},
	}
}

func (d *usageData) device(id string) *usageDevice {
	dev := d.Devices[id]
	if dev == nil {
		dev = &usageDevice{}
		d.Devices[id] = dev
	}
	return dev
}

// apply folds one event, logged at `at` by `container`, into the totals.
func (d *usageData) apply(container string, at time.Time, ev usageEvent) {
	if ev.kind == usageOther || !usableID(ev.session) {
		return
	}
	sec := at.Unix()
	key := container + "/" + ev.session
	switch ev.kind {
	case usageOpened:
		if !usableID(ev.device) || strings.HasPrefix(ev.device, usageProbePrefix) {
			return
		}
		d.Sessions[key] = &usageSession{Device: ev.device, Open: true, LastSeen: sec}
		dev := d.device(ev.device)
		dev.Sessions++
		dev.seen(sec)
		if len(d.Sessions) > 2*usageMaxSessions {
			d.prune(at) // a first read of a long log: keep the map bounded on the way
		}
	case usageTraffic:
		s := d.Sessions[key]
		if s == nil {
			return // a check's session, or one opened before anything was read
		}
		s.LastSeen = max(s.LastSeen, sec)
		dev := d.device(s.Device)
		dev.In = addBytes(dev.In, ev.in)
		dev.Out = addBytes(dev.Out, ev.out)
		dev.seen(sec)
	case usageGone:
		if !usableID(ev.device) || strings.HasPrefix(ev.device, usageProbePrefix) {
			return
		}
		s := d.Sessions[key]
		if s == nil {
			// Opened before anything was read: remember it anyway, so the
			// streams it still finishes count.
			s = &usageSession{Device: ev.device}
			d.Sessions[key] = s
		}
		s.Open = false
		s.LastSeen = max(s.LastSeen, sec)
		d.device(ev.device).seen(sec)
	case usageClosed:
		s := d.Sessions[key]
		if s == nil {
			return
		}
		s.Open = false
		s.LastSeen = max(s.LastSeen, sec)
		d.device(s.Device).seen(sec)
	}
}

// prune forgets sessions not seen for usageSessionTTL, then the oldest
// sessions and devices past their caps, so the file never grows without end.
func (d *usageData) prune(now time.Time) {
	cutoff := now.Add(-usageSessionTTL).Unix()
	for k, s := range d.Sessions {
		if s.LastSeen < cutoff {
			delete(d.Sessions, k)
		}
	}
	if extra := len(d.Sessions) - usageMaxSessions; extra > 0 {
		keys := make([]string, 0, len(d.Sessions))
		for k := range d.Sessions {
			keys = append(keys, k)
		}
		sort.Slice(keys, func(i, j int) bool { return d.Sessions[keys[i]].LastSeen < d.Sessions[keys[j]].LastSeen })
		for _, k := range keys[:extra] {
			delete(d.Sessions, k)
		}
	}
	if extra := len(d.Devices) - usageMaxDevices; extra > 0 {
		ids := make([]string, 0, len(d.Devices))
		for id := range d.Devices {
			ids = append(ids, id)
		}
		sort.Slice(ids, func(i, j int) bool { return d.Devices[ids[i]].LastSeen < d.Devices[ids[j]].LastSeen })
		for _, id := range ids[:extra] {
			delete(d.Devices, id)
		}
	}
}

// pruneCursors drops the cursors of containers that no longer run once there
// are many: every reinstall names its container anew.
func (d *usageData) pruneCursors(running []string) {
	if len(d.Cursors) <= usageMaxCursors {
		return
	}
	alive := map[string]bool{}
	for _, name := range running {
		alive[name] = true
	}
	for name := range d.Cursors {
		if !alive[name] {
			delete(d.Cursors, name)
		}
	}
}

// --- the answer ------------------------------------------------------------

type usageRow struct {
	ID       string `json:"id"`
	LastSeen int64  `json:"last_seen"`
	Online   bool   `json:"online"`
	In       int64  `json:"in"`
	Out      int64  `json:"out"`
	Sessions int64  `json:"sessions"`
}

type usageReport struct {
	At      int64      `json:"at"`
	Devices []usageRow `json:"devices"`
}

// report is the GET usage answer: every device, the most recently seen
// first. Online means an open session AND a line about the device within
// usageOnlineWindow: a container stopped mid-session leaves its sessions
// open, and a device that went quiet should not read as connected.
func (d *usageData) report(now time.Time) usageReport {
	open := map[string]bool{}
	for _, s := range d.Sessions {
		if s.Open {
			open[s.Device] = true
		}
	}
	window := int64(usageOnlineWindow / time.Second)
	rows := make([]usageRow, 0, len(d.Devices))
	for id, dev := range d.Devices {
		rows = append(rows, usageRow{
			ID:       id,
			LastSeen: dev.LastSeen,
			Online:   open[id] && now.Unix()-dev.LastSeen <= window,
			In:       dev.In,
			Out:      dev.Out,
			Sessions: dev.Sessions,
		})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].LastSeen != rows[j].LastSeen {
			return rows[i].LastSeen > rows[j].LastSeen
		}
		return rows[i].ID < rows[j].ID
	})
	return usageReport{At: now.Unix(), Devices: rows}
}

// --- the collector ---------------------------------------------------------

// usageCollector keeps usageData current from the containers' logs. Safe for
// concurrent use: one pass runs at a time, and a report may be taken while a
// pass runs.
type usageCollector struct {
	mu       sync.Mutex
	data     usageData
	path     string // usage.json; "" keeps the totals in memory only
	dirty    bool
	passing  chan struct{} // closed when the running pass ends; nil when none runs
	lastPass time.Time

	// running lists the containers podman runs now; readLogs streams
	// `podman logs --timestamps --since <since> <container>` into each, one
	// line at a time. Injected so tests never touch the OS; Serve sets the
	// real podman runners.
	running  func() ([]string, error)
	readLogs func(container, since string, each func(line string)) error
	// now is the collector's clock: time.Now outside tests.
	now func() time.Time
}

// newUsageCollector starts from the totals saved at path, if any. A missing
// or unreadable file starts empty: the next pass reads the last 30 days of
// each container's log again.
func newUsageCollector(path string) *usageCollector {
	u := &usageCollector{data: newUsageData(), path: path, now: time.Now}
	if path != "" {
		if data, err := loadUsageData(path); err == nil {
			u.data = data
		}
	}
	return u
}

func loadUsageData(path string) (usageData, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return usageData{}, err
	}
	var d usageData
	if err := json.Unmarshal(raw, &d); err != nil {
		return usageData{}, err
	}
	clean := newUsageData()
	for id, dev := range d.Devices {
		if dev != nil {
			clean.Devices[id] = dev
		}
	}
	for k, s := range d.Sessions {
		if s != nil {
			clean.Sessions[k] = s
		}
	}
	for name, c := range d.Cursors {
		clean.Cursors[name] = c
	}
	return clean, nil
}

// save writes usage.json atomically (a unique temporary file renamed into
// place, as config.json is), when anything changed since the last save.
func (u *usageCollector) save() {
	u.mu.Lock()
	if u.path == "" || !u.dirty {
		u.mu.Unlock()
		return
	}
	data, err := json.Marshal(u.data)
	u.dirty = false
	u.mu.Unlock()
	if err == nil {
		err = writeFileAtomic(u.path, data)
	}
	if err != nil {
		u.mu.Lock()
		u.dirty = true // try again after the next pass
		u.mu.Unlock()
	}
}

func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, filepath.Base(path)+".tmp*")
	if err != nil {
		return err
	}
	tmp := f.Name()
	_, werr := f.Write(data)
	cerr := f.Close()
	if werr != nil || cerr != nil {
		_ = os.Remove(tmp)
		return errors.Join(werr, cerr)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// start begins a pass unless one is running (it hands back that one's end)
// or one began less than minGap ago (nil: the totals are fresh enough).
func (u *usageCollector) start(minGap time.Duration) <-chan struct{} {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.passing != nil {
		return u.passing
	}
	now := u.now()
	if minGap > 0 && !u.lastPass.IsZero() && now.Sub(u.lastPass) < minGap {
		return nil
	}
	done := make(chan struct{})
	u.passing = done
	u.lastPass = now
	go func() {
		defer func() {
			u.mu.Lock()
			u.passing = nil
			u.mu.Unlock()
			close(done)
		}()
		u.collect()
	}()
	return done
}

// run keeps the totals current: a pass at once, then one every
// usageInterval, until ctx ends.
func (u *usageCollector) run(ctx context.Context) {
	ticker := time.NewTicker(usageInterval)
	defer ticker.Stop()
	for {
		if done := u.start(0); done != nil {
			select {
			case <-done:
			case <-ctx.Done():
				return
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// collect is one pass: every running olcrtc container's new lines, then the
// pruning and the save.
func (u *usageCollector) collect() {
	if u.running == nil || u.readLogs == nil {
		return
	}
	names, err := u.running()
	if err != nil {
		return
	}
	for _, name := range names {
		if usageContainerRE.MatchString(name) {
			u.collectContainer(name)
		}
	}
	u.mu.Lock()
	u.data.prune(u.now())
	u.data.pruneCursors(names)
	u.mu.Unlock()
	u.save()
}

// collectContainer reads one container's lines since its cursor. The cursor
// moves with every line read, so a read cut short (the timeout, a restart)
// resumes where it stopped instead of counting anything twice.
func (u *usageCollector) collectContainer(name string) {
	u.mu.Lock()
	start := u.data.Cursors[name]
	u.mu.Unlock()
	since := usageFirstSince
	if start > 0 {
		since = time.Unix(0, start).UTC().Format(time.RFC3339Nano)
	}
	_ = u.readLogs(name, since, func(line string) {
		at, ev, ok := parseUsageLine(line)
		// podman's --since includes the line at that very time, and was
		// already read: only lines strictly after the cursor count.
		if !ok || at.UnixNano() <= start {
			return
		}
		u.mu.Lock()
		if at.UnixNano() > u.data.Cursors[name] {
			u.data.Cursors[name] = at.UnixNano()
		}
		u.data.apply(name, at, ev)
		u.dirty = true
		u.mu.Unlock()
	})
}

// report is the GET usage answer as of now.
func (u *usageCollector) report() usageReport {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.data.report(u.now())
}

// --- real runners (used by Serve, not by unit tests) -----------------------

// podmanRunning lists the names of the running containers.
func podmanRunning() ([]string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "podman", "ps", "--format", "{{.Names}}").Output()
	if err != nil {
		return nil, err
	}
	return strings.Fields(string(out)), nil
}

// podmanLogLines streams a container's log since `since` (a duration or an
// RFC 3339 time) into each, a line at a time. podman's two streams share ONE
// pipe: the core logs to stderr, and podman replays a container's stdout and
// stderr in their order only when both land in the same file.
func podmanLogLines(container, since string, each func(string)) error {
	ctx, cancel := context.WithTimeout(context.Background(), usageLogTimeout)
	defer cancel()
	r, w, err := os.Pipe()
	if err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, "podman", "logs", "--timestamps", "--since", since, container)
	cmd.Stdout = w
	cmd.Stderr = w
	if err := cmd.Start(); err != nil {
		_ = r.Close()
		_ = w.Close()
		return err
	}
	_ = w.Close() // podman holds its own copy: the read ends when it exits
	readErr := eachLine(r, each)
	_ = r.Close()
	waitErr := cmd.Wait()
	if readErr != nil {
		return readErr
	}
	return waitErr
}

// eachLine feeds r to each a line at a time. A line too long for the buffer
// is skipped whole: nothing the collector reads is that long, and giving up
// there would stop every later pass at the same line.
func eachLine(r io.Reader, each func(string)) error {
	br := bufio.NewReaderSize(r, 64*1024)
	for {
		line, err := br.ReadSlice('\n')
		if errors.Is(err, bufio.ErrBufferFull) {
			for errors.Is(err, bufio.ErrBufferFull) {
				_, err = br.ReadSlice('\n')
			}
			if err == nil {
				continue
			}
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		if len(line) > 0 {
			each(string(line))
		}
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
	}
}
