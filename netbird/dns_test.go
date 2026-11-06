package main

import (
	"context"
	"net"
	"reflect"
	"strings"
	"testing"

	"github.com/miekg/dns"
	mgmProto "github.com/netbirdio/netbird/shared/management/proto"
)

func syncResponse() *mgmProto.SyncResponse {
	return &mgmProto.SyncResponse{NetworkMap: &mgmProto.NetworkMap{
		PeerConfig: &mgmProto.PeerConfig{Address: "100.90.1.2/16", Fqdn: "laptop.nb.example.com"},
		Routes:     []*mgmProto.Route{{Network: "10.10.0.0/16"}, {Network: "0.0.0.0/0"}, {Network: "10.10.0.0/16"}},
		DNSConfig: &mgmProto.DNSConfig{NameServerGroups: []*mgmProto.NameServerGroup{
			// Inside the overlay (behind the routing peer's 10.10/16).
			{Domains: []string{"Corp.Example.com."}, SearchDomainsEnabled: true, NameServers: []*mgmProto.NameServer{{IP: "10.10.0.53", Port: 53}}},
			// A public server: left to the client.
			{Domains: []string{"public.example"}, NameServers: []*mgmProto.NameServer{{IP: "192.0.2.53", Port: 53}}},
			// Primary (no domains): left to the client.
			{Primary: true, NameServers: []*mgmProto.NameServer{{IP: "8.8.8.8", Port: 53}}},
		}},
	}}
}

func TestTunnelInfo(t *testing.T) {
	info, groups := tunnelInfo(syncResponse())
	want := map[string]any{
		"addresses":      []string{"100.90.1.2/16"},
		"routes":         []string{"10.10.0.0/16"},
		"search_domains": []string{"nb.example.com", "corp.example.com"},
		"split_dns":      []string{"nb.example.com", "corp.example.com", "public.example"},
		"dns":            []string{"10.10.0.53:53", "192.0.2.53:53", "8.8.8.8:53"},
	}
	if !reflect.DeepEqual(info, want) {
		t.Errorf("info:\n got %v\nwant %v", info, want)
	}
	if len(groups) != 1 || groups[0].domains[0] != "corp.example.com" || groups[0].servers[0].String() != "10.10.0.53:53" {
		t.Errorf("groups: %+v", groups)
	}
	// A zone with search off is reported for routing, not as a search domain.
	sr := syncResponse()
	sr.NetworkMap.DNSConfig.CustomZones = []*mgmProto.CustomZone{{Domain: "nb.example.com", SearchDomainDisabled: true}}
	info, _ = tunnelInfo(sr)
	if s := info["search_domains"].([]string); len(s) != 1 || s[0] != "corp.example.com" {
		t.Errorf("search with the zone's search off: %v", s)
	}
}

// A name in the overlay group's domain is asked of its server through
// the dialer the proxy uses (here a loopback server standing in for the
// netstack); a name outside it is left to the client.
func TestResolveOverlay(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := &dns.Server{PacketConn: pc, Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		// DNS names compare without case.
		if strings.EqualFold(r.Question[0].Name, "db1.corp.example.com.") && r.Question[0].Qtype == dns.TypeA {
			rr, _ := dns.NewRR("db1.corp.example.com. 60 IN A 10.10.5.7")
			m.Answer = append(m.Answer, rr)
		} else if r.Question[0].Qtype == dns.TypeA {
			m.Rcode = dns.RcodeNameError
		}
		_ = w.WriteMsg(m)
	})}
	started := make(chan struct{})
	srv.NotifyStartedFunc = func() { close(started) }
	go func() { _ = srv.ActivateAndServe() }()
	<-started
	defer srv.Shutdown()

	_, groups := tunnelInfo(syncResponse())
	overlayDNS.Lock()
	overlayDNS.groups = groups
	overlayDNS.Unlock()
	defer func() {
		overlayDNS.Lock()
		overlayDNS.groups = nil
		overlayDNS.Unlock()
	}()
	var asked []string
	dial := func(ctx context.Context, network, addr string) (net.Conn, error) {
		asked = append(asked, network+" "+addr)
		var d net.Dialer
		return d.DialContext(ctx, network, pc.LocalAddr().String())
	}
	ip, ok := resolveOverlay(context.Background(), "DB1.corp.example.com", dial)
	if !ok || ip != "10.10.5.7" {
		t.Fatalf("resolve: %q %v", ip, ok)
	}
	if asked[0] != "udp 10.10.0.53:53" {
		t.Errorf("asked %v", asked)
	}
	if _, ok := resolveOverlay(context.Background(), "nope.corp.example.com", dial); ok {
		t.Error("an unknown name resolved")
	}
	asked = nil
	if _, ok := resolveOverlay(context.Background(), "x.public.example", dial); ok || len(asked) != 0 {
		t.Errorf("a public group's name was asked here: %v", asked)
	}
}
