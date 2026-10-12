package ovpn

import (
	"encoding/base64"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// PushReply is what the server pushed: addressing, routes, DNS and the
// negotiated session parameters.
type PushReply struct {
	Addresses     []netip.Prefix
	Routes        []string
	RouteGateway  string
	DNS           []netip.Addr
	Domains       []string
	RedirectAll   bool
	TunMTU        int
	Cipher        string
	Auth          string
	Compress      string
	PeerID        int
	Ping          int
	PingRestart   int
	AuthToken     string
	AuthTokenUser string
	Topology      string
}

func parsePush(body string) (*PushReply, error) {
	pr := &PushReply{PeerID: -1}
	var ifconfig []string
	for _, opt := range strings.Split(body, ",") {
		f := splitArgs(strings.TrimSpace(opt))
		if len(f) == 0 {
			continue
		}
		arg := func(i int) string {
			if i < len(f) {
				return f[i]
			}
			return ""
		}
		switch f[0] {
		case "ifconfig":
			ifconfig = f[1:]
		case "ifconfig-ipv6":
			if p, err := netip.ParsePrefix(arg(1)); err == nil {
				pr.Addresses = append(pr.Addresses, p)
			}
		case "topology":
			pr.Topology = arg(1)
		case "route":
			r := arg(1)
			if m := arg(2); m != "" && m != "default" {
				if ones, ok := maskBits(m); ok {
					r += "/" + strconv.Itoa(ones)
				}
			}
			pr.Routes = append(pr.Routes, r)
		case "route-ipv6":
			pr.Routes = append(pr.Routes, arg(1))
		case "route-gateway":
			pr.RouteGateway = arg(1)
		case "redirect-gateway":
			pr.RedirectAll = true
		case "dhcp-option":
			switch strings.ToUpper(arg(1)) {
			case "DNS", "DNS6":
				if a, err := netip.ParseAddr(arg(2)); err == nil {
					pr.DNS = append(pr.DNS, a)
				}
			case "DOMAIN", "DOMAIN-SEARCH", "ADAPTER_DOMAIN_SUFFIX":
				pr.Domains = append(pr.Domains, arg(2))
			}
		case "dns":
			// dns server <n> address <a> [<a>...] | dns search-domains <d>...
			if arg(1) == "server" && arg(3) == "address" {
				for _, a := range f[4:] {
					a = strings.TrimSuffix(strings.SplitN(a, "#", 2)[0], "]")
					a = strings.TrimPrefix(a, "[")
					if ip, err := netip.ParseAddr(a); err == nil {
						pr.DNS = append(pr.DNS, ip)
					} else if ap, err := netip.ParseAddrPort(a); err == nil {
						pr.DNS = append(pr.DNS, ap.Addr())
					}
				}
			}
			if arg(1) == "search-domains" {
				pr.Domains = append(pr.Domains, f[2:]...)
			}
		case "tun-mtu":
			pr.TunMTU, _ = strconv.Atoi(arg(1))
		case "cipher":
			pr.Cipher = strings.ToUpper(arg(1))
		case "auth":
			pr.Auth = strings.ToUpper(arg(1))
		case "peer-id":
			pr.PeerID, _ = strconv.Atoi(arg(1))
		case "ping":
			pr.Ping, _ = strconv.Atoi(arg(1))
		case "ping-restart":
			pr.PingRestart, _ = strconv.Atoi(arg(1))
		case "auth-token":
			pr.AuthToken = arg(1)
		case "auth-token-user":
			if u, err := decodeB64(arg(1)); err == nil {
				pr.AuthTokenUser = u
			}
		case "comp-lzo":
			pr.Compress = "lzo"
		case "compress":
			m, err := compressMode(arg(1))
			if err != nil {
				return nil, fmt.Errorf("server pushed %w", err)
			}
			pr.Compress = m
		}
	}
	if len(ifconfig) >= 1 {
		ip, err := netip.ParseAddr(ifconfig[0])
		if err != nil {
			return nil, fmt.Errorf("pushed ifconfig %q: %w", ifconfig[0], err)
		}
		bits := 32
		// topology subnet: "ifconfig local netmask"; net30 / p2p:
		// "ifconfig local peer", where the peer is no valid mask.
		if len(ifconfig) >= 2 {
			if ones, ok := maskBits(ifconfig[1]); ok && ones > 0 {
				bits = ones
			}
		}
		pr.Addresses = append([]netip.Prefix{netip.PrefixFrom(ip, bits)}, pr.Addresses...)
	}
	if len(pr.Addresses) == 0 {
		return nil, fmt.Errorf("server pushed no tunnel address")
	}
	return pr, nil
}

// maskBits reads a dotted netmask; ok is false for a non-mask (the peer
// address of a net30 / p2p ifconfig).
func maskBits(m string) (int, bool) {
	ip := net.ParseIP(m).To4()
	if ip == nil {
		return 0, false
	}
	ones, bits := net.IPMask(ip).Size()
	if bits == 0 {
		return 0, false
	}
	return ones, true
}

func decodeB64(s string) (string, error) {
	b, err := base64.StdEncoding.DecodeString(s)
	return string(b), err
}

// tokenUpdate picks a renewed auth-token out of a later push.
func tokenUpdate(body string) (tok, user string) {
	for _, opt := range strings.Split(body, ",") {
		f := splitArgs(strings.TrimSpace(opt))
		if len(f) < 2 {
			continue
		}
		switch f[0] {
		case "auth-token":
			tok = f[1]
		case "auth-token-user":
			user, _ = decodeB64(f[1])
		}
	}
	return tok, user
}
