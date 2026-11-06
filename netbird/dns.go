package main

// DNS of the overlay, for the app.
//
// The app routes a name by the DNS domains a tunnel reports (the app
// proxy sends a name in one of them through that tunnel), so the helper
// reports them in an info event: the peer's own NetBird domain (the
// FQDN without its first label) and the match domains of the
// nameserver groups, the ones with search domains on as search domains.
//
// A name is resolved inside the overlay already (embed.Client.Dial asks
// the client's own DNS service on the netstack). That service answers
// NetBird names itself, but forwards a nameserver group's queries to its
// servers over the host network: client/internal/dns/upstream_general.go
// uses the netstack only on GOOS=js (a TODO there). A nameserver that is
// reachable only through the overlay (a DNS server behind a routing
// peer) therefore never answers in userspace mode. For a name in such a
// group's domain this helper asks the group's servers itself, through
// the netstack, and dials the address; everything else goes the
// client's way as before.

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	mgmProto "github.com/netbirdio/netbird/shared/management/proto"
	"github.com/netbirdio/netbird/shared/netiputil"
)

// nsGroup is a nameserver group with match domains. overlay: its servers
// sit inside the overlay, and servers are those; a group of public
// servers is kept too (overlay false), so a more specific public domain
// still wins the choice and is left to the client.
type nsGroup struct {
	domains []string
	servers []netip.AddrPort
	overlay bool
}

// overlayDNS is what the SOCKS proxy resolves through (set from the
// latest sync response).
var overlayDNS struct {
	sync.Mutex
	groups []nsGroup
}

func normDomain(d string) string {
	return strings.ToLower(strings.Trim(strings.TrimSpace(d), "."))
}

// tunnelInfo reads the sync response into the info event's fields and
// the nameserver groups the proxy resolves through itself.
// nm is the network map (decoded from the envelope for a peer on the
// components format, see networkMapOf); pc the peer's own config.
func tunnelInfo(pc *mgmProto.PeerConfig, nm *mgmProto.NetworkMap) (map[string]any, []nsGroup) {
	info := map[string]any{}
	var overlay []netip.Prefix
	if p := nm.GetPeerConfig(); p != nil {
		pc = p
	}
	if a := pc.GetAddress(); a != "" {
		info["addresses"] = []string{a}
		if p, err := netip.ParsePrefix(a); err == nil {
			overlay = append(overlay, p.Masked())
		}
	}
	// The account's IPv6 range too: a nameserver on another peer's IPv6
	// address is inside the overlay without any route covering it.
	if raw := pc.GetAddressV6(); len(raw) > 0 {
		if p, err := netiputil.DecodePrefix(raw); err == nil {
			overlay = append(overlay, p.Masked())
		}
	}
	var routes []string
	seenRoute := map[string]bool{}
	for _, r := range nm.GetRoutes() {
		n := r.GetNetwork()
		p, err := netip.ParsePrefix(n)
		if err != nil || p.Bits() == 0 || seenRoute[p.Masked().String()] {
			continue
		}
		seenRoute[p.Masked().String()] = true
		routes = append(routes, p.Masked().String())
		overlay = append(overlay, p.Masked())
	}
	sort.Strings(routes)
	// Always sent, an empty list included: the app reads a report with a
	// routes field as the whole tunnel, so a removed last route (and the
	// domains that went with it) is cleared there instead of kept.
	if routes == nil {
		routes = []string{}
	}
	info["routes"] = routes

	var search, split, servers []string
	seen := map[*[]string]map[string]bool{&search: {}, &split: {}}
	add := func(list *[]string, d string) {
		d = normDomain(d)
		if d == "" || seen[list][d] {
			return
		}
		seen[list][d] = true
		*list = append(*list, d)
	}
	dc := nm.GetDNSConfig()
	// The peer's own domain: its FQDN minus the host label, unless the
	// zone has search off.
	if f := normDomain(pc.GetFqdn()); strings.Contains(f, ".") {
		zone := f[strings.Index(f, ".")+1:]
		off := false
		for _, z := range dc.GetCustomZones() {
			if normDomain(z.GetDomain()) == zone && z.GetSearchDomainDisabled() {
				off = true
			}
		}
		add(&split, zone)
		if !off {
			add(&search, zone)
		}
	}
	var groups []nsGroup
	for _, g := range dc.GetNameServerGroups() {
		var doms []string
		for _, d := range g.GetDomains() {
			if d = normDomain(d); d != "" {
				doms = append(doms, d)
				add(&split, d)
				if g.GetSearchDomainsEnabled() {
					add(&search, d)
				}
			}
		}
		var reach []netip.AddrPort
		for _, ns := range g.GetNameServers() {
			ip, err := netip.ParseAddr(ns.GetIP())
			if err != nil {
				continue
			}
			// No port is 53; one outside 1-65535 is a broken entry, skipped
			// (asking 53 instead could reach another server).
			port := uint16(53)
			switch p := ns.GetPort(); {
			case p > 0 && p < 65536:
				port = uint16(p)
			case p != 0:
				log.Printf("netbird: nameserver %s has port %d, left out", ns.GetIP(), p)
				continue
			}
			servers = append(servers, netip.AddrPortFrom(ip, port).String())
			for _, p := range overlay {
				if p.Contains(ip.Unmap()) {
					reach = append(reach, netip.AddrPortFrom(ip.Unmap(), port))
					break
				}
			}
		}
		// A primary group (no domains) takes every name; leave those to
		// the client (its servers are usually public ones).
		if len(doms) > 0 {
			groups = append(groups, nsGroup{domains: doms, servers: reach, overlay: len(reach) > 0})
		}
	}
	if len(search) > 0 {
		info["search_domains"] = search
	}
	if len(split) > 0 {
		info["split_dns"] = split
	}
	if len(servers) > 0 {
		info["dns"] = servers
	}
	return info, groups
}

// groupFor is the group whose domain host is in, the longest domain first.
func groupFor(host string, groups []nsGroup) (nsGroup, bool) {
	h := normDomain(host)
	best, bestLen := nsGroup{}, 0
	for _, g := range groups {
		for _, d := range g.domains {
			if (h == d || strings.HasSuffix(h, "."+d)) && len(d) > bestLen {
				best, bestLen = g, len(d)
			}
		}
	}
	return best, bestLen > 0
}

type dialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// resolveOverlay asks the servers of host's nameserver group through the
// overlay and returns every address they gave (A first, then AAAA), for
// the caller to try in order. ok=false when the group that takes host
// (the most specific domain) is not an overlay one, none takes it, or no
// server answered with an address: the caller then dials the name the
// client's way.
func resolveOverlay(ctx context.Context, host string, dial dialFunc) ([]string, bool) {
	overlayDNS.Lock()
	groups := overlayDNS.groups
	overlayDNS.Unlock()
	g, ok := groupFor(host, groups)
	if !ok || !g.overlay {
		return nil, false
	}
	for _, s := range g.servers {
		var addrs []string
		for _, qt := range []uint16{dns.TypeA, dns.TypeAAAA} {
			got, err := queryOne(ctx, dial, s.String(), host, qt)
			if err == nil {
				addrs = append(addrs, got...)
			}
		}
		if len(addrs) > 0 {
			return addrs, true
		}
	}
	return nil, false
}

// queryOne asks one server for one record type over UDP, again over TCP
// when the answer was truncated, and returns the addresses of the name
// asked (or of the CNAME chain from it). An answer to another question
// (wrong ID or name) is refused.
func queryOne(ctx context.Context, dial dialFunc, server, host string, qt uint16) ([]string, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(host), qt)
	m.RecursionDesired = true
	ask := func(network string) (*dns.Msg, error) {
		qctx, cancel := context.WithTimeout(ctx, 3*time.Second)
		defer cancel()
		c, err := dial(qctx, network, server)
		if err != nil {
			return nil, err
		}
		defer c.Close()
		if dl, ok := qctx.Deadline(); ok {
			_ = c.SetDeadline(dl)
		}
		co := &dns.Conn{Conn: c}
		if err := co.WriteMsg(m); err != nil {
			return nil, err
		}
		return co.ReadMsg()
	}
	r, err := ask("udp")
	if err == nil && r.Truncated {
		r, err = ask("tcp")
	}
	if err != nil {
		return nil, err
	}
	if r.Id != m.Id || len(r.Question) != 1 || !strings.EqualFold(r.Question[0].Name, m.Question[0].Name) || r.Question[0].Qtype != qt || r.Question[0].Qclass != m.Question[0].Qclass {
		return nil, errors.New("the answer is to another question")
	}
	if r.Rcode != dns.RcodeSuccess {
		return nil, errors.New(dns.RcodeToString[r.Rcode])
	}
	// Names the answer may carry addresses for: the one asked, then each
	// CNAME target reached from it.
	names := map[string]bool{strings.ToLower(m.Question[0].Name): true}
	for changed := true; changed; {
		changed = false
		for _, rr := range r.Answer {
			if c, ok := rr.(*dns.CNAME); ok && names[strings.ToLower(c.Hdr.Name)] && !names[strings.ToLower(c.Target)] {
				names[strings.ToLower(c.Target)] = true
				changed = true
			}
		}
	}
	var out []string
	for _, rr := range r.Answer {
		if !names[strings.ToLower(rr.Header().Name)] {
			continue
		}
		switch v := rr.(type) {
		case *dns.A:
			out = append(out, v.A.String())
		case *dns.AAAA:
			out = append(out, v.AAAA.String())
		}
	}
	return out, nil
}

// infoJSON is an info event's body, for comparing with the last one sent.
func infoJSON(info map[string]any) string {
	b, _ := json.Marshal(info)
	return string(b)
}
