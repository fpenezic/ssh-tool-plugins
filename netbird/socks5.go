package main

// Minimal SOCKS5 server: no auth, CONNECT only, bound to loopback.
// Deliberately hand-rolled (~150 lines) instead of pulling a SOCKS
// dependency into yet another module - the consumer is always our
// own x/net/proxy client, so only the exact subset it speaks is
// implemented. Hostname (ATYP=3) requests resolve INSIDE the netbird
// network via the embedded client's dialer, which is what makes
// NetBird DNS names work from the main app.

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"time"
)

// dialer is the subset of embed.Client the proxy needs.
type dialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

func serveSocks(ln net.Listener, d dialer) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return // listener closed on shutdown
		}
		go func() {
			if err := handleConn(conn, d); err != nil {
				log.Printf("socks: %v", err)
			}
		}()
	}
}

func handleConn(conn net.Conn, d dialer) error {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))

	// Greeting: VER NMETHODS METHODS...
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return fmt.Errorf("greeting: %w", err)
	}
	if hdr[0] != 0x05 {
		return fmt.Errorf("not socks5 (ver %d)", hdr[0])
	}
	methods := make([]byte, int(hdr[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return fmt.Errorf("methods: %w", err)
	}
	// Reply: no-auth. The listener is loopback-only; auth adds nothing.
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		return err
	}

	// Request: VER CMD RSV ATYP DST.ADDR DST.PORT
	req := make([]byte, 4)
	if _, err := io.ReadFull(conn, req); err != nil {
		return fmt.Errorf("request: %w", err)
	}
	if req[1] != 0x01 { // CONNECT
		_, _ = conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // command not supported
		return fmt.Errorf("unsupported cmd %d", req[1])
	}
	var host string
	switch req[3] {
	case 0x01: // IPv4
		b := make([]byte, 4)
		if _, err := io.ReadFull(conn, b); err != nil {
			return err
		}
		host = net.IP(b).String()
	case 0x03: // domain name - resolved inside the netbird network
		l := make([]byte, 1)
		if _, err := io.ReadFull(conn, l); err != nil {
			return err
		}
		b := make([]byte, int(l[0]))
		if _, err := io.ReadFull(conn, b); err != nil {
			return err
		}
		host = string(b)
	case 0x04: // IPv6
		b := make([]byte, 16)
		if _, err := io.ReadFull(conn, b); err != nil {
			return err
		}
		host = net.IP(b).String()
	default:
		_, _ = conn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // address type not supported
		return fmt.Errorf("unsupported atyp %d", req[3])
	}
	pb := make([]byte, 2)
	if _, err := io.ReadFull(conn, pb); err != nil {
		return err
	}
	port := binary.BigEndian.Uint16(pb)

	dctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	// A name in a nameserver group whose servers sit inside the overlay:
	// asked here, through the netstack (dns.go says why), with a budget of
	// its own so a slow server leaves time for the dial; each address it
	// gives is tried in turn, and the name the client's way after them.
	var target net.Conn
	var err error
	if req[3] == 0x03 {
		rctx, rcancel := context.WithTimeout(dctx, 8*time.Second)
		addrs, ok := resolveOverlay(rctx, host, d.DialContext)
		rcancel()
		if ok {
			for _, a := range addrs {
				if target, err = d.DialContext(dctx, "tcp", net.JoinHostPort(a, fmt.Sprintf("%d", port))); err == nil {
					break
				}
			}
		}
	}
	if target == nil {
		target, err = dialName(dctx, d, net.JoinHostPort(host, fmt.Sprintf("%d", port)), req[3] == 0x03)
	}
	cancel()
	if err != nil {
		_, _ = conn.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // connection refused
		return fmt.Errorf("dial %s:%d: %w", host, port, err)
	}
	defer target.Close()

	// Success reply. BND.ADDR/PORT are not meaningful for CONNECT
	// through an overlay; zeros are what every client accepts.
	if _, err := conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0}); err != nil {
		return err
	}

	// Relay until either side closes. Clear the handshake deadline -
	// SSH sessions live for hours.
	_ = conn.SetDeadline(time.Time{})
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(target, conn); done <- struct{}{} }()
	go func() { _, _ = io.Copy(conn, target); done <- struct{}{} }()
	<-done
	return nil
}

// readyAt is when the proxy started listening (set in main).
var readyAt time.Time

// startupGrace is how long after start a name the client's DNS does not
// know yet is asked again: the client is up before its DNS service has
// the network's zone (seen with NetBird v0.82: the first dial right
// after start got "no such host" for a peer's name, the next one 2 s
// later resolved).
const startupGrace = 20 * time.Second

// dialName dials addr; a name that does not resolve during the startup
// grace is tried again every second, at most four times.
func dialName(ctx context.Context, d dialer, addr string, byName bool) (net.Conn, error) {
	for try := 0; ; try++ {
		c, err := d.DialContext(ctx, "tcp", addr)
		if err == nil || !byName || try >= 4 || time.Since(readyAt) > startupGrace || !strings.Contains(err.Error(), "no such host") {
			return c, err
		}
		select {
		case <-ctx.Done():
			return nil, err
		case <-time.After(time.Second):
		}
	}
}
