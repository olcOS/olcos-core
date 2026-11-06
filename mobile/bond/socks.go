package bond

import (
	"bytes"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
)

// SOCKS5 (RFC 1928, 1929): the app-facing side, and the client side towards
// a lane.

const (
	socksVersion   = 5
	cmdConnect     = 1
	atypIPv4       = 1
	atypDomain     = 3
	atypIPv6       = 4
	methodNone     = 0
	methodPassword = 2
	methodRefused  = 0xFF

	repSuccess          = 0
	repFailure          = 1
	repNetUnreachable   = 3
	repHostUnreachable  = 4
	repCmdNotSupported  = 7
	repAddrNotSupported = 8
)

var (
	errSocksAuth  = errors.New("bond: SOCKS5 authentication failed")
	errSocksProto = errors.New("bond: not a SOCKS5 request")
)

// socksRefusedError is a lane's SOCKS failure reply.
type socksRefusedError struct{ code byte }

func (e socksRefusedError) Error() string { return fmt.Sprintf("bond: lane refused (SOCKS5 reply %d)", e.code) }

type socksRequest struct {
	cmd    byte
	target string // host:port
	raw    []byte // the request as the app sent it
}

// acceptSocks runs an app's handshake up to its request. With a user set the
// app must log in with it; without one it must offer no authentication.
func acceptSocks(c net.Conn, user, pass string) (socksRequest, error) {
	var head [2]byte
	if _, err := io.ReadFull(c, head[:]); err != nil {
		return socksRequest{}, err
	}
	if head[0] != socksVersion {
		return socksRequest{}, errSocksProto
	}
	methods := make([]byte, head[1])
	if _, err := io.ReadFull(c, methods); err != nil {
		return socksRequest{}, err
	}
	want := byte(methodNone)
	if user != "" {
		want = methodPassword
	}
	if !bytes.Contains(methods, []byte{want}) {
		_, _ = c.Write([]byte{socksVersion, methodRefused})
		return socksRequest{}, errSocksAuth
	}
	if _, err := c.Write([]byte{socksVersion, want}); err != nil {
		return socksRequest{}, err
	}
	if want == methodPassword {
		if err := acceptLogin(c, user, pass); err != nil {
			return socksRequest{}, err
		}
	}
	return readRequest(c)
}

func acceptLogin(c net.Conn, user, pass string) error {
	var head [2]byte
	if _, err := io.ReadFull(c, head[:]); err != nil {
		return err
	}
	u := make([]byte, head[1])
	if _, err := io.ReadFull(c, u); err != nil {
		return err
	}
	var plen [1]byte
	if _, err := io.ReadFull(c, plen[:]); err != nil {
		return err
	}
	p := make([]byte, plen[0])
	if _, err := io.ReadFull(c, p); err != nil {
		return err
	}
	userOK := subtle.ConstantTimeCompare(u, []byte(user)) == 1
	passOK := subtle.ConstantTimeCompare(p, []byte(pass)) == 1
	if head[0] != 1 || !userOK || !passOK {
		_, _ = c.Write([]byte{1, 1})
		return errSocksAuth
	}
	_, err := c.Write([]byte{1, 0})
	return err
}

func readRequest(c net.Conn) (socksRequest, error) {
	head := make([]byte, 4, 4+1+255+2)
	if _, err := io.ReadFull(c, head); err != nil {
		return socksRequest{}, err
	}
	if head[0] != socksVersion {
		return socksRequest{}, errSocksProto
	}
	var host string
	raw := head
	switch head[3] {
	case atypIPv4, atypIPv6:
		n := net.IPv4len
		if head[3] == atypIPv6 {
			n = net.IPv6len
		}
		ip := make([]byte, n)
		if _, err := io.ReadFull(c, ip); err != nil {
			return socksRequest{}, err
		}
		raw = append(raw, ip...)
		addr, _ := netip.AddrFromSlice(ip)
		host = addr.Unmap().String()
	case atypDomain:
		var n [1]byte
		if _, err := io.ReadFull(c, n[:]); err != nil {
			return socksRequest{}, err
		}
		name := make([]byte, n[0])
		if _, err := io.ReadFull(c, name); err != nil {
			return socksRequest{}, err
		}
		raw = append(append(raw, n[0]), name...)
		host = string(name)
	default:
		_, _ = c.Write(socksReply(repAddrNotSupported))
		return socksRequest{}, errSocksProto
	}
	var port [2]byte
	if _, err := io.ReadFull(c, port[:]); err != nil {
		return socksRequest{}, err
	}
	raw = append(raw, port[:]...)
	target := net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(port[:]))))
	return socksRequest{cmd: head[1], target: target, raw: raw}, nil
}

// socksReply is a reply with an empty IPv4 bound address.
func socksReply(code byte) []byte {
	return []byte{socksVersion, code, 0, atypIPv4, 0, 0, 0, 0, 0, 0}
}

// greeting is the client's opening and login for a lane, in one piece.
func greeting(user, pass string) []byte {
	if user == "" {
		return []byte{socksVersion, 1, methodNone}
	}
	b := []byte{socksVersion, 1, methodPassword, 1, byte(len(user))}
	b = append(b, user...)
	b = append(b, byte(len(pass)))
	return append(b, pass...)
}

// readGreetingReply reads a lane's answers to greeting.
func readGreetingReply(c net.Conn, user string) error {
	var method [2]byte
	if _, err := io.ReadFull(c, method[:]); err != nil {
		return err
	}
	want := byte(methodNone)
	if user != "" {
		want = methodPassword
	}
	if method[0] != socksVersion || method[1] != want {
		return errSocksAuth
	}
	if user == "" {
		return nil
	}
	var status [2]byte
	if _, err := io.ReadFull(c, status[:]); err != nil {
		return err
	}
	if status[1] != 0 {
		return errSocksAuth
	}
	return nil
}

// connectRequest is a CONNECT for host:port.
func connectRequest(addr string) ([]byte, error) {
	host, portText, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 0 || port > 65535 {
		return nil, fmt.Errorf("bond: bad port in %q", addr)
	}
	b := []byte{socksVersion, cmdConnect, 0}
	if ip, err := netip.ParseAddr(host); err == nil {
		if ip.Is4() {
			b = append(b, atypIPv4)
		} else {
			b = append(b, atypIPv6)
		}
		b = append(b, ip.AsSlice()...)
	} else {
		if len(host) > 255 {
			return nil, fmt.Errorf("bond: host name too long")
		}
		b = append(b, atypDomain, byte(len(host)))
		b = append(b, host...)
	}
	return binary.BigEndian.AppendUint16(b, uint16(port)), nil
}

// readConnectReply reads a lane's reply to a CONNECT.
func readConnectReply(c net.Conn) error {
	var head [4]byte
	if _, err := io.ReadFull(c, head[:]); err != nil {
		return err
	}
	if head[0] != socksVersion {
		return errSocksProto
	}
	var n int
	switch head[3] {
	case atypIPv4:
		n = net.IPv4len
	case atypIPv6:
		n = net.IPv6len
	case atypDomain:
		var l [1]byte
		if _, err := io.ReadFull(c, l[:]); err != nil {
			return err
		}
		n = int(l[0])
	default:
		return errSocksProto
	}
	if _, err := io.ReadFull(c, make([]byte, n+2)); err != nil {
		return err
	}
	if head[1] != repSuccess {
		return socksRefusedError{code: head[1]}
	}
	return nil
}
