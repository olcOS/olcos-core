package agent

import (
	"encoding/json"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// --- helpers ---------------------------------------------------------------

// podmanTime is the time podman logs --timestamps prints in front of a line.
func podmanTime(t time.Time) string {
	return t.UTC().Format("2006-01-02T15:04:05.000000000Z07:00")
}

// logLine is a container log line as podman prints it: its timestamp, then
// the core's own (Go log's date and time, then the message).
func logLine(t time.Time, msg string) string {
	return podmanTime(t) + " " + t.UTC().Format("2006/01/02 15:04:05") + " " + msg
}

// fakePodman answers like podman would, from canned logs. Like podman's
// --since, it may hand back lines that were read before: here it always
// hands back every line, so only the collector's cursor keeps them apart.
type fakePodman struct {
	mu      sync.Mutex
	running []string
	logs    map[string][]string
	asked   map[string][]string // container → the since values asked for
	passes  int
}

func newFakePodman(running ...string) *fakePodman {
	return &fakePodman{running: running, logs: map[string][]string{}, asked: map[string][]string{}}
}

func (f *fakePodman) add(container string, lines ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.logs[container] = append(f.logs[container], lines...)
}

func (f *fakePodman) list() ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.passes++
	return append([]string(nil), f.running...), nil
}

func (f *fakePodman) read(container, since string, each func(string)) error {
	f.mu.Lock()
	f.asked[container] = append(f.asked[container], since)
	lines := append([]string(nil), f.logs[container]...)
	f.mu.Unlock()
	for _, l := range lines {
		each(l + "\n")
	}
	return nil
}

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

func testCollector(path string, pm *fakePodman, clock *fakeClock) *usageCollector {
	u := newUsageCollector(path)
	u.running = pm.list
	u.readLogs = pm.read
	u.now = clock.now
	return u
}

func rowFor(t *testing.T, r usageReport, id string) usageRow {
	t.Helper()
	for _, row := range r.Devices {
		if row.ID == id {
			return row
		}
	}
	t.Fatalf("no row for %q in %+v", id, r.Devices)
	return usageRow{}
}

var usageT0 = time.Date(2026, 10, 14, 12, 0, 0, 0, time.UTC)

// --- parsing ---------------------------------------------------------------

func TestParseUsageLineReadsTheFourKinds(t *testing.T) {
	sample := "2026-10-14T12:59:02.694673000Z 2026/10/14 12:59:02 session opened: " +
		"id=61076e99-f88c-4774-990c-47925b33bf6f device=olcos-09eb2945 claims=map[]"
	at, ev, ok := parseUsageLine(sample)
	if !ok || ev.kind != usageOpened || ev.session != "61076e99-f88c-4774-990c-47925b33bf6f" || ev.device != "olcos-09eb2945" {
		t.Fatalf("opened: ok=%v %+v", ok, ev)
	}
	if want := time.Date(2026, 10, 14, 12, 59, 2, 694673000, time.UTC); !at.Equal(want) {
		t.Fatalf("time %v, want %v", at, want)
	}

	cases := []struct {
		msg  string
		want usageEvent
	}{
		{"traffic: session=s1 in=1200 out=34567",
			usageEvent{kind: usageTraffic, session: "s1", in: 1200, out: 34567}},
		{"peer disconnected: device=inv-1a2b3c4d-quiet-harbor-42 session=s1 reason=liveness duration=4m2s",
			usageEvent{kind: usageGone, session: "s1", device: "inv-1a2b3c4d-quiet-harbor-42"}},
		{"session closed: id=s1 reason=closed",
			usageEvent{kind: usageClosed, session: "s1"}},
		// Lines the collector does not read only move the cursor.
		{"peer connected: device=x session=s1", usageEvent{}},
		{"Current peers count: 1, Devices: [x]", usageEvent{}},
		{"session s1 opened (device=x)", usageEvent{}},
		{"session opened: id=s2 device= claims=map[]", usageEvent{}}, // no device
		{"traffic: session=s1 in=lots out=1", usageEvent{}},
	}
	for _, c := range cases {
		_, got, ok := parseUsageLine(logLine(usageT0, c.msg))
		if !ok || got != c.want {
			t.Errorf("%q: ok=%v got %+v, want %+v", c.msg, ok, got, c.want)
		}
	}

	// A journald-style offset parses; a line without a timestamp says nothing.
	if at, _, ok := parseUsageLine("2026-10-14T15:59:02.000001+03:00 traffic: session=s in=1 out=2"); !ok ||
		!at.Equal(time.Date(2026, 10, 14, 12, 59, 2, 1000, time.UTC)) {
		t.Fatalf("offset time: ok=%v at=%v", ok, at)
	}
	for _, bad := range []string{"", "session opened: id=s device=d", "yesterday traffic: session=s in=1 out=2"} {
		if _, _, ok := parseUsageLine(bad); ok {
			t.Errorf("%q should not parse", bad)
		}
	}
	// A count past int64 saturates instead of wrapping.
	if _, ev, _ := parseUsageLine(logLine(usageT0, "traffic: session=s in=99999999999999999999 out=1")); ev.in <= 0 {
		t.Fatalf("overflowing count wrapped: %+v", ev)
	}
}

func TestEachLineSkipsAnOverlongLine(t *testing.T) {
	long := strings.Repeat("x", 200*1024)
	var got []string
	err := eachLine(strings.NewReader("one\n"+long+"\ntwo\nthree"), func(l string) { got = append(got, l) })
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"one\n", "two\n", "three"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("lines %q, want %q", got, want)
	}
}

// --- aggregation -----------------------------------------------------------

// Two containers (a primary and a sibling carrier) log interleaved sessions
// of two devices; traffic follows the session it names, whichever container.
func TestCollectAddsUpInterleavedContainers(t *testing.T) {
	pm := newFakePodman("olcrtc-server-ab12cd34", "olcrtc-server-ab12cd34-salutejazz", "olcos-xray-x1", "olcos-share")
	phone, tablet := "inv-1a2b3c4d-quiet-harbor-42", "inv-1a2b3c4d-amber-lark-17"
	pm.add("olcrtc-server-ab12cd34",
		logLine(usageT0, "session opened: id=a1 device="+phone+" claims=map[]"),
		logLine(usageT0.Add(2*time.Second), "traffic: session=a1 in=100 out=1000"),
		logLine(usageT0.Add(4*time.Second), "session opened: id=a2 device="+tablet+" claims=map[]"),
		logLine(usageT0.Add(5*time.Second), "traffic: session=a2 in=7 out=70"),
		logLine(usageT0.Add(6*time.Second), "traffic: session=a1 in=1 out=10"),
		logLine(usageT0.Add(8*time.Second), "peer disconnected: device="+phone+" session=a1 reason=closed duration=8s"),
		logLine(usageT0.Add(8*time.Second), "session closed: id=a1 reason=closed"),
		// A stream that outlived its session still counts.
		logLine(usageT0.Add(9*time.Second), "traffic: session=a1 in=5 out=50"),
	)
	pm.add("olcrtc-server-ab12cd34-salutejazz",
		logLine(usageT0.Add(1*time.Second), "session opened: id=b1 device="+phone+" claims=map[]"),
		logLine(usageT0.Add(3*time.Second), "traffic: session=b1 in=20 out=200"),
	)
	pm.add("olcos-xray-x1", logLine(usageT0, "session opened: id=x device=nobody claims=map[]"))
	clock := &fakeClock{t: usageT0.Add(10 * time.Second)}
	u := testCollector("", pm, clock)
	u.collect()

	r := u.report()
	if r.At != clock.now().Unix() || len(r.Devices) != 2 {
		t.Fatalf("report %+v", r)
	}
	p := rowFor(t, r, phone)
	if p.In != 126 || p.Out != 1260 || p.Sessions != 2 || p.LastSeen != usageT0.Add(9*time.Second).Unix() {
		t.Fatalf("phone %+v", p)
	}
	// a1 closed, but b1 (the sibling's lane) is still open and recent.
	if !p.Online {
		t.Fatal("the phone still has an open session")
	}
	tb := rowFor(t, r, tablet)
	if tb.In != 7 || tb.Out != 70 || tb.Sessions != 1 || !tb.Online {
		t.Fatalf("tablet %+v", tb)
	}
	// Most recently seen first.
	if r.Devices[0].ID != phone {
		t.Fatalf("order %+v", r.Devices)
	}
	if len(pm.asked["olcos-xray-x1"]) != 0 || len(pm.asked["olcos-share"]) != 0 {
		t.Fatalf("only olcrtc-server-* containers are read: %+v", pm.asked)
	}
}

func TestChecksAndUnknownSessionsAreLeftOut(t *testing.T) {
	pm := newFakePodman("olcrtc-server-ab12cd34")
	pm.add("olcrtc-server-ab12cd34",
		logLine(usageT0, "session opened: id=p1 device=olc-ping-B1B91495 claims=map[]"),
		logLine(usageT0.Add(time.Second), "traffic: session=p1 in=10 out=10"),
		logLine(usageT0.Add(time.Second), "peer disconnected: device=olc-ping-B1B91495 session=p1 reason=closed duration=1s"),
		logLine(usageT0.Add(2*time.Second), "traffic: session=never-opened in=10 out=10"),
		logLine(usageT0.Add(2*time.Second), "session closed: id=never-opened reason=closed"),
		"not a log line at all",
	)
	u := testCollector("", pm, &fakeClock{t: usageT0.Add(time.Minute)})
	u.collect()
	if r := u.report(); len(r.Devices) != 0 {
		t.Fatalf("checks and unknown sessions must not appear: %+v", r.Devices)
	}
}

// A session opened before anything was read is learnt from its disconnect,
// so the streams it still finishes count; nothing reads as online.
func TestDisconnectOfAnUnseenSessionKeepsItsLateTraffic(t *testing.T) {
	pm := newFakePodman("olcrtc-server-ab12cd34")
	pm.add("olcrtc-server-ab12cd34",
		logLine(usageT0, "peer disconnected: device=quiet-harbor-42 session=old reason=liveness duration=3h"),
		logLine(usageT0.Add(time.Second), "traffic: session=old in=3 out=4"),
	)
	u := testCollector("", pm, &fakeClock{t: usageT0.Add(2 * time.Second)})
	u.collect()
	row := rowFor(t, u.report(), "quiet-harbor-42")
	if row.In != 3 || row.Out != 4 || row.Sessions != 0 || row.Online {
		t.Fatalf("row %+v", row)
	}
}

func TestOnlineNeedsAnOpenSessionSeenRecently(t *testing.T) {
	pm := newFakePodman("olcrtc-server-ab12cd34")
	pm.add("olcrtc-server-ab12cd34",
		logLine(usageT0, "session opened: id=s1 device=quiet-harbor-42 claims=map[]"),
		logLine(usageT0, "session opened: id=s2 device=amber-lark-17 claims=map[]"),
		logLine(usageT0.Add(time.Second), "session closed: id=s2 reason=closed"),
	)
	clock := &fakeClock{t: usageT0.Add(time.Minute)}
	u := testCollector("", pm, clock)
	u.collect()
	r := u.report()
	if !rowFor(t, r, "quiet-harbor-42").Online {
		t.Fatal("an open session seen a minute ago is online")
	}
	if rowFor(t, r, "amber-lark-17").Online {
		t.Fatal("a closed session is not online")
	}
	clock.advance(usageOnlineWindow) // now 4 minutes after the last line
	if rowFor(t, u.report(), "quiet-harbor-42").Online {
		t.Fatal("an open session not heard from for over 3 minutes is not online")
	}
}

// --- cursor ----------------------------------------------------------------

func TestCursorNeverCountsALineTwice(t *testing.T) {
	pm := newFakePodman("olcrtc-server-ab12cd34")
	pm.add("olcrtc-server-ab12cd34",
		logLine(usageT0, "session opened: id=s1 device=quiet-harbor-42 claims=map[]"),
		logLine(usageT0.Add(time.Second), "traffic: session=s1 in=10 out=100"),
	)
	clock := &fakeClock{t: usageT0.Add(time.Minute)}
	u := testCollector("", pm, clock)
	u.collect()
	// The next pass gets the old lines again (the fake ignores --since) plus a new one.
	pm.add("olcrtc-server-ab12cd34", logLine(usageT0.Add(2*time.Second), "traffic: session=s1 in=1 out=1"))
	u.collect()
	row := rowFor(t, u.report(), "quiet-harbor-42")
	if row.In != 11 || row.Out != 101 || row.Sessions != 1 {
		t.Fatalf("lines counted twice or lost: %+v", row)
	}
	asked := pm.asked["olcrtc-server-ab12cd34"]
	if len(asked) != 2 || asked[0] != usageFirstSince {
		t.Fatalf("since values %q", asked)
	}
	if want := usageT0.Add(time.Second).UTC().Format(time.RFC3339Nano); asked[1] != want {
		t.Fatalf("second pass asked since %q, want the last line read %q", asked[1], want)
	}
}

// Two lines logged at the same instant are both read in one pass: only the
// line the previous pass ended on is skipped.
func TestLinesSharingATimestampInOnePassAllCount(t *testing.T) {
	pm := newFakePodman("olcrtc-server-ab12cd34")
	pm.add("olcrtc-server-ab12cd34",
		logLine(usageT0, "session opened: id=s1 device=quiet-harbor-42 claims=map[]"),
		logLine(usageT0.Add(time.Second), "traffic: session=s1 in=1 out=1"),
		logLine(usageT0.Add(time.Second), "traffic: session=s1 in=1 out=1"),
	)
	u := testCollector("", pm, &fakeClock{t: usageT0.Add(time.Minute)})
	u.collect()
	if row := rowFor(t, u.report(), "quiet-harbor-42"); row.In != 2 {
		t.Fatalf("simultaneous streams lost: %+v", row)
	}
}

// --- persistence -----------------------------------------------------------

func TestUsageSurvivesARestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), usageFile)
	pm := newFakePodman("olcrtc-server-ab12cd34")
	pm.add("olcrtc-server-ab12cd34",
		logLine(usageT0, "session opened: id=s1 device=quiet-harbor-42 claims=map[]"),
		logLine(usageT0.Add(time.Second), "traffic: session=s1 in=10 out=100"),
	)
	clock := &fakeClock{t: usageT0.Add(time.Minute)}
	first := testCollector(path, pm, clock)
	first.collect()
	before := first.report()

	// A new agent process: the totals, the open session and the cursor are back.
	again := testCollector(path, pm, clock)
	if after := again.report(); !reflect.DeepEqual(before, after) {
		t.Fatalf("totals did not survive:\n before %+v\n after  %+v", before, after)
	}
	pm.add("olcrtc-server-ab12cd34", logLine(usageT0.Add(2*time.Second), "traffic: session=s1 in=5 out=5"))
	again.collect()
	row := rowFor(t, again.report(), "quiet-harbor-42")
	if row.In != 15 || row.Out != 105 || row.Sessions != 1 || !row.Online {
		t.Fatalf("after the restart: %+v", row)
	}
	if asked := pm.asked["olcrtc-server-ab12cd34"]; asked[len(asked)-1] == usageFirstSince {
		t.Fatal("the restarted agent read the whole log again")
	}

	// A damaged file starts empty rather than failing.
	if err := writeFileAtomic(path, []byte("{not json")); err != nil {
		t.Fatal(err)
	}
	if r := testCollector(path, pm, clock).report(); len(r.Devices) != 0 {
		t.Fatalf("a damaged file should start empty: %+v", r)
	}
}

func TestPruneForgetsOldSessionsButKeepsTotals(t *testing.T) {
	d := newUsageData()
	d.apply("c", usageT0, usageEvent{kind: usageOpened, session: "old", device: "quiet-harbor-42"})
	d.apply("c", usageT0.Add(time.Second), usageEvent{kind: usageTraffic, session: "old", in: 1, out: 2})
	d.apply("c", usageT0.Add(25*time.Hour), usageEvent{kind: usageOpened, session: "new", device: "quiet-harbor-42"})
	d.prune(usageT0.Add(25 * time.Hour))
	if _, ok := d.Sessions["c/old"]; ok {
		t.Fatal("a session not seen for a day must go")
	}
	if _, ok := d.Sessions["c/new"]; !ok {
		t.Fatal("a fresh session must stay")
	}
	if dev := d.Devices["quiet-harbor-42"]; dev == nil || dev.In != 1 || dev.Sessions != 2 {
		t.Fatalf("totals must stay: %+v", dev)
	}
	// The caps hold whatever the log throws at them.
	for i := 0; i < 3*usageMaxSessions; i++ {
		d.apply("c", usageT0.Add(26*time.Hour), usageEvent{kind: usageOpened,
			session: "s" + strconv.Itoa(i), device: "d" + strconv.Itoa(i%(2*usageMaxDevices))})
	}
	d.prune(usageT0.Add(26 * time.Hour))
	if len(d.Sessions) > usageMaxSessions || len(d.Devices) > usageMaxDevices {
		t.Fatalf("caps exceeded: %d sessions, %d devices", len(d.Sessions), len(d.Devices))
	}
}

// --- passes and the endpoint -----------------------------------------------

// An owner's request starts a pass at most every usageMinGap; a running pass
// is waited for, not doubled.
func TestRequestPassesAreThrottled(t *testing.T) {
	pm := newFakePodman("olcrtc-server-ab12cd34")
	clock := &fakeClock{t: usageT0}
	u := testCollector("", pm, clock)
	wait := func(ch <-chan struct{}) {
		t.Helper()
		select {
		case <-ch:
		case <-time.After(5 * time.Second):
			t.Fatal("pass did not end")
		}
	}
	first := u.start(usageMinGap)
	if first == nil {
		t.Fatal("the first request must start a pass")
	}
	wait(first)
	clock.advance(usageMinGap / 2)
	if u.start(usageMinGap) != nil {
		t.Fatal("a pass ran 10 s ago: no new one")
	}
	clock.advance(usageMinGap)
	next := u.start(usageMinGap)
	if next == nil {
		t.Fatal("past the gap a request starts a pass again")
	}
	wait(next)
	if pm.passes != 2 {
		t.Fatalf("passes = %d, want 2", pm.passes)
	}
	// The background pass ignores the gap.
	wait(u.start(0))
	if pm.passes != 3 {
		t.Fatalf("passes = %d, want 3", pm.passes)
	}
}

func usagePath(c *Config) string { return "/" + c.Prefix + "/v1/usage" }

func TestUsageEndpointAnswersTheOwnerOnly(t *testing.T) {
	owner := newTestKey(t)
	member := newTestKey(t)
	cfg := testConfig(owner.device(RoleOwner), member.device(RoleMember))
	h := newHandler(cfg, testState(nil))
	pm := newFakePodman("olcrtc-server-ab12cd34")
	now := time.Now().Truncate(time.Second)
	pm.add("olcrtc-server-ab12cd34",
		logLine(now.Add(-time.Hour), "session opened: id=s0 device=amber-lark-17 claims=map[]"),
		logLine(now.Add(-time.Hour), "session closed: id=s0 reason=closed"),
		logLine(now.Add(-10*time.Second), "session opened: id=s1 device=inv-1a2b3c4d-quiet-harbor-42 claims=map[]"),
		logLine(now.Add(-5*time.Second), "traffic: session=s1 in=85000000 out=1200000000"),
	)
	h.usage = testCollector("", pm, &fakeClock{t: now})

	// A member gets the same camouflage as a stranger.
	assert404(t, do(h, member.sign(t, "GET", usagePath(cfg), nil, time.Now(), "n-usage-member")))
	if pm.passes != 0 {
		t.Fatal("a member's request must not read the logs")
	}

	rec := do(h, owner.sign(t, "GET", usagePath(cfg), nil, time.Now(), "n-usage-owner"))
	if rec.Code != 200 {
		t.Fatalf("owner: want 200, got %d body=%s", rec.Code, rec.Body.String())
	}
	// The exact shape both phones decode.
	var raw struct {
		At      int64            `json:"at"`
		Devices []map[string]any `json:"devices"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	if raw.At != now.Unix() || len(raw.Devices) != 2 {
		t.Fatalf("body %s", rec.Body.String())
	}
	want := map[string]any{
		"id": "inv-1a2b3c4d-quiet-harbor-42", "last_seen": float64(now.Add(-5 * time.Second).Unix()),
		"online": true, "in": float64(85000000), "out": float64(1200000000), "sessions": float64(1),
	}
	if !reflect.DeepEqual(raw.Devices[0], want) {
		t.Fatalf("first device %v, want %v", raw.Devices[0], want)
	}
	if raw.Devices[1]["id"] != "amber-lark-17" || raw.Devices[1]["online"] != false {
		t.Fatalf("second device %v", raw.Devices[1])
	}

	// Without a collector (or before anything was read) the list is empty, not null.
	bare := newHandler(cfg, testState(nil))
	rec = do(bare, owner.sign(t, "GET", usagePath(cfg), nil, time.Now(), "n-usage-bare"))
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), `"devices":[]`) {
		t.Fatalf("empty answer: %d %s", rec.Code, rec.Body.String())
	}
}
