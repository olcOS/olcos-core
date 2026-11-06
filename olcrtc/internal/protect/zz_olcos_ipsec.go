// zz_olcos_ipsec.go is an olcOS addition, not upstream code.
//
// The core's ICE interface filter (pionnet.go) excludes tunnel-style
// interfaces by name prefix - tun, utun, ppp, pptp - but not iOS's IPsec
// tunnels (ipsecN). Without this, pion may gather host candidates on an IPsec
// VPN's interface: ICE noise at best, a routing loop at worst.
// tunInterfacePrefixes is a package var read at call time, so appending in
// init() needs no change to upstream files.
//
// It is kept in its own file so that an update of olcrtc/ never conflicts
// with it, and it is left out of server/olcrtc-core.patch: the server binary
// does not need it.
package protect

//nolint:gochecknoinits // must run before any interface enumeration
func init() {
	tunInterfacePrefixes = append(tunInterfacePrefixes, "ipsec")
}
