package bond

import (
	"net"
	"net/netip"
	"strings"
)

// directRules is the bond client's reading of the direct list the olcrtc core
// takes (its internal/route package, which another module cannot import):
// `domain:<name>` for a name and everything under it, `full:<name>` for that
// name only, an address or a CIDR prefix. A bonded connection reaches the
// lanes only as a CONNECT to the bond server, so a lane's own core never sees
// the destination; the client has to decide before it bonds.
type directRules struct {
	full     map[string]struct{}
	suffix   map[string]struct{}
	prefixes []netip.Prefix
}

// parseDirect reads the list; blank lines, # comments and anything it does
// not understand are skipped (the app checked the text with the core first).
// Nil when nothing is listed.
func parseDirect(text string) *directRules {
	r := &directRules{full: map[string]struct{}{}, suffix: map[string]struct{}{}}
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		switch {
		case line == "" || strings.HasPrefix(line, "#"):
		case strings.HasPrefix(line, "domain:"):
			if name := normalizeName(line[len("domain:"):]); name != "" {
				r.suffix[name] = struct{}{}
			}
		case strings.HasPrefix(line, "full:"):
			if name := normalizeName(line[len("full:"):]); name != "" {
				r.full[name] = struct{}{}
			}
		default:
			if p, err := netip.ParsePrefix(line); err == nil {
				r.prefixes = append(r.prefixes, p.Masked())
			} else if a, err := netip.ParseAddr(line); err == nil {
				r.prefixes = append(r.prefixes, netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()))
			}
		}
	}
	if len(r.full)+len(r.suffix)+len(r.prefixes) == 0 {
		return nil
	}
	return r
}

func normalizeName(name string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(name)), ".")
}

// matchTarget reports whether a CONNECT target ("host:port") is listed.
func (r *directRules) matchTarget(target string) bool {
	if r == nil {
		return false
	}
	host, _, err := net.SplitHostPort(target)
	if err != nil {
		host = target
	}
	if a, err := netip.ParseAddr(host); err == nil {
		a = a.Unmap()
		for _, p := range r.prefixes {
			if p.Contains(a) {
				return true
			}
		}
		return false
	}
	name := normalizeName(host)
	if _, ok := r.full[name]; ok {
		return true
	}
	for {
		if _, ok := r.suffix[name]; ok {
			return true
		}
		dot := strings.IndexByte(name, '.')
		if dot < 0 {
			return false
		}
		name = name[dot+1:]
	}
}
