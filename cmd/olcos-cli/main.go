// Command olcos-cli is a desktop harness for the shared core: it starts an
// engine from a share link, prints the local SOCKS address and periodic
// traffic counters, and exits on SIGINT/SIGTERM or after -duration.
//
// It exists for end-to-end checks against a real server; it is not shipped
// to users.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/olcOS/olcos-core/olcos"
)

type stderrLog struct{}

func (stderrLog) Write(level int, msg string) {
	fmt.Fprintf(os.Stderr, "[%d] %s\n", level, msg)
}

func main() {
	uri := flag.String("uri", os.Getenv("OLCOS_URI"), "share link (vless:// or olcrtc://); default $OLCOS_URI")
	duration := flag.Duration("duration", 0, "stop after this long (0 = until signal)")
	every := flag.Duration("stats", 5*time.Second, "stats print interval (0 = off)")
	flag.Parse()
	if *uri == "" {
		fmt.Fprintln(os.Stderr, "usage: olcos-cli -uri vless://... [-duration 30s]")
		os.Exit(2)
	}

	rt := olcos.New()
	rt.SetLogWriter(stderrLog{})
	in, _ := json.Marshal(map[string]string{"uri": *uri})
	out := rt.Invoke("engine.start", string(in))
	var env struct {
		OK     bool            `json:"ok"`
		Error  string          `json:"error"`
		Result json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal([]byte(out), &env); err != nil || !env.OK {
		fmt.Fprintf(os.Stderr, "engine.start failed: %s\n", out)
		os.Exit(1)
	}
	fmt.Println(string(env.Result))

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	var deadline <-chan time.Time
	if *duration > 0 {
		deadline = time.After(*duration)
	}
	var tick <-chan time.Time
	if *every > 0 {
		t := time.NewTicker(*every)
		defer t.Stop()
		tick = t.C
	}
	for {
		select {
		case <-sig:
			shutdown(rt)
			return
		case <-deadline:
			shutdown(rt)
			return
		case <-tick:
			fmt.Println(rt.Invoke("engine.stats", "{}"))
		}
	}
}

func shutdown(rt *olcos.Runtime) {
	fmt.Println(rt.Invoke("engine.stats", "{}"))
	fmt.Println(rt.Invoke("engine.stop", "{}"))
}
