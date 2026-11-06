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
	"net"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
	mgmProto "github.com/netbirdio/netbird/shared/management/proto"
)

// nsGroup is a nameserver group with match domains and the servers of it
// the overlay reaches.
type nsGroup struct {
	domains []string
	servers []netip.AddrPort
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
func tunnelInfo(sr *mgmProto.SyncResponse) (map[string]any, []nsGroup) {
	nm := sr.GetNetworkMap()
	info := map[string]any{}
	var overlay []netip.Prefix
	pc := nm.GetPeerConfig()
	if pc == nil {
		pc = sr.GetPeerConfig()
	}
	if a := pc.GetAddress(); a != "" {
		info["addresses"] = []string{a}
		if p, err := netip.ParsePrefix(a); err == nil {
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
	if len(routes) > 0 {
		info["routes"] = routes
	}

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
			port := uint16(53)
			if ns.GetPort() > 0 && ns.GetPort() < 65536 {
				port = uint16(ns.GetPort())
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
		if len(doms) > 0 && len(reach) > 0 {
			groups = append(groups, nsGroup{domains: doms, servers: reach})
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
// overlay; ok=false when no group takes host or no server answered with
// an address (the caller then dials the name the client's way).
func resolveOverlay(ctx context.Context, host string, dial dialFunc) (string, bool) {
	overlayDNS.Lock()
	groups := overlayDNS.groups
	overlayDNS.Unlock()
	g, ok := groupFor(host, groups)
	if !ok {
		return "", false
	}
	for _, s := range g.servers {
		for _, qt := range []uint16{dns.TypeA, dns.TypeAAAA} {
			ip, err := queryOne(ctx, dial, s.String(), host, qt)
			if err == nil && ip != "" {
				return ip, true
			}
		}
	}
	return "", false
}

// queryOne asks one server for one record type over UDP, again over TCP
// when the answer was truncated, and returns the first address.
func queryOne(ctx context.Context, dial dialFunc, server, host string, qt uint16) (string, error) {
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
		return "", err
	}
	if r.Rcode != dns.RcodeSuccess {
		return "", errors.New(dns.RcodeToString[r.Rcode])
	}
	for _, rr := range r.Answer {
		switch v := rr.(type) {
		case *dns.A:
			return v.A.String(), nil
		case *dns.AAAA:
			return v.AAAA.String(), nil
		}
	}
	return "", nil
}

// infoJSON is an info event's body, for comparing with the last one sent.
func infoJSON(info map[string]any) string {
	b, _ := json.Marshal(info)
	return string(b)
}
