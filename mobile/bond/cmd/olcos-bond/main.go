// Command olcos-bond is the server side of bonding (package bond). It runs
// on the VPS next to the olcrtc server, accepts the lanes' sub-connections on
// one port and joins each stream back together before it dials the target.
package main

import (
	"flag"
	"log"

	"github.com/openlibrecommunity/olcrtc-ios/gomobile/bond"
)

func main() {
	listen := flag.String("listen", ":0", "address to accept lanes on")
	key := flag.String("key", "/root/.olcrtc_key", "the tunnel key: bare hex, or a server.yaml")
	dns := flag.String("dns", "", "DNS server (host:port) for targets; empty: the system resolver")
	flag.Parse()
	log.Fatal(bond.Serve(*listen, *key, *dns))
}
