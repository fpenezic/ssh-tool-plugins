package snx

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// The CCC exchange: s-expression requests POSTed to https://gw/clients/,
// each answered by a CCCserverResponse. Login is
//
//	ClientHello                     -> gateway info (tunnel port, login options)
//	UserPass  (username, no password) -> "continue" + prompt + auth session id
//	MultiChallange (the password)   -> "continue" (next factor) or "done" + active_key
//
// and the active key is the cookie the SLIM tunnel's hello presents.
// ("MultiChallange" is the gateway's spelling.)

// ClientType is what the gateway knows this client as: an Endpoint
// Security VPN ("TRAC") client.
const ClientType = "TRAC"

// Gateway talks CCC to one gateway.
type Gateway struct {
	// Server is host or host:port (443 when absent).
	Server string
	// TLS verifies the gateway (pins or system roots); ServerName is filled.
	TLS  *tls.Config
	Logf func(string, ...any)

	http *http.Client
	ids  atomic.Int64
}

// Info is the part of the gateway's ClientHello answer the client uses.
type Info struct {
	ProtocolVersion int
	ServerIP        string
	TunnelPort      int // "tcpt_port": where the SLIM tunnel listens
	Protocols       []string
	ClientEnabled   bool
	LoginOptions    []LoginOption
}

// LoginOption is one realm the gateway offers ("vpn_Username_Password",
// "vpn" for a certificate, a RADIUS or SAML realm, ...).
type LoginOption struct {
	ID          string
	DisplayName string
	Factors     []string // factor types: password, certificate, identity_provider, ...
}

// AuthResult is one step of the login.
type AuthResult struct {
	// Done: logged in, ActiveKey is the tunnel cookie.
	Done      bool
	ActiveKey string
	KeyTTL    time.Duration
	// Otherwise the gateway wants more (Prompt, answered with Challenge on
	// SessionID).
	Prompt    string
	SessionID string
	Username  string
}

// AuthError is a login the gateway refused.
type AuthError struct {
	Code    int
	ID      string
	Message string
}

func (e *AuthError) Error() string {
	if e.Message == "" {
		return "authentication failed"
	}
	return e.Message
}

func (g *Gateway) client() *http.Client {
	if g.http == nil {
		cfg := g.TLS.Clone()
		if cfg.ServerName == "" {
			cfg.ServerName = hostOnly(g.Server)
		}
		g.http = &http.Client{
			Transport: &http.Transport{
				TLSClientConfig:     cfg,
				DialContext:         (&net.Dialer{Timeout: 15 * time.Second}).DialContext,
				TLSHandshakeTimeout: 15 * time.Second,
				ForceAttemptHTTP2:   false,
			},
		}
	}
	return g.http
}

func hostOnly(server string) string {
	if h, _, err := net.SplitHostPort(server); err == nil {
		return h
	}
	return server
}

func (g *Gateway) logf(format string, a ...any) {
	if g.Logf != nil {
		g.Logf(format, a...)
	}
}

// request sends one CCC request and returns its ResponseData.
func (g *Gateway) request(ctx context.Context, typ, sessionID string, protoVersion int, data *Node, timeout time.Duration) (*Node, error) {
	hdr := Obj("",
		"id", V(strconv.FormatInt(g.ids.Add(1), 10)),
		"type", V(typ),
	)
	if sessionID != "" {
		hdr.Fields = append(hdr.Fields, Field{"session_id", V(sessionID)})
	}
	if protoVersion > 0 {
		hdr.Fields = append(hdr.Fields, Field{"protocol_version", V(strconv.Itoa(protoVersion))})
	}
	body := Obj("CCCclientRequest", "RequestHeader", hdr, "RequestData", data).String()

	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+g.Server+"/clients/", strings.NewReader(body))
	if err != nil {
		return nil, err
	}
	resp, err := g.client().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: gateway answered HTTP %d", typ, resp.StatusCode)
	}
	n, err := Parse(string(raw))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", typ, err)
	}
	if n.Kind != KindObject || n.Name != "CCCserverResponse" {
		return nil, fmt.Errorf("%s: unexpected reply %q", typ, n.Name)
	}
	rd := n.Get("ResponseData")
	if rd != nil && rd.Kind == KindValue && typ == "Signout" {
		return rd, nil // nothing to say is the normal answer
	}
	if rd == nil || rd.Kind == KindValue {
		return nil, fmt.Errorf("%s: gateway returned code %s", typ, n.Str("ResponseHeader", "return_code"))
	}
	return rd, nil
}

// Hello asks the gateway what it offers.
func (g *Gateway) Hello(ctx context.Context) (*Info, error) {
	rd, err := g.request(ctx, "ClientHello", "", 0, Obj("",
		"client_info", Obj("",
			"client_type", V(ClientType),
			"client_version", V("1"),
			"client_support_saml", V("true"),
		),
	), 15*time.Second)
	if err != nil {
		return nil, err
	}
	ci := rd.Get("connectivity_info")
	if ci == nil {
		return nil, errors.New("ClientHello: no connectivity_info (not a Check Point remote access gateway?)")
	}
	in := &Info{
		ProtocolVersion: int(rd.Int("protocol_version", "protocol_version")),
		ServerIP:        ci.Str("server_ip"),
		TunnelPort:      int(ci.Int("tcpt_port")),
		ClientEnabled:   ci.Bool("client_enabled"),
	}
	for _, p := range ci.List("supported_data_tunnel_protocols") {
		in.Protocols = append(in.Protocols, p.Value)
	}
	if in.TunnelPort == 0 {
		in.TunnelPort = 443
	}
	if opts := rd.Get("login_options_data", "login_options_list"); opts != nil && opts.Kind == KindObject {
		for _, f := range opts.Fields {
			o := LoginOption{ID: f.Node.Str("id"), DisplayName: f.Node.Str("display_name")}
			if fs := f.Node.Get("factors"); fs != nil && fs.Kind == KindObject {
				for _, ff := range fs.Fields {
					o.Factors = append(o.Factors, ff.Node.Str("factor_type"))
				}
			}
			in.LoginOptions = append(in.LoginOptions, o)
		}
	}
	return in, nil
}

// clientLoggingData is what the gateway logs about the client. It wants
// one; this is the minimum Check Point's own clients send.
func clientLoggingData(deviceID string) *Node {
	return Obj("",
		"os_name", V("Windows"),
		"device_id", V(deviceID),
	)
}

// Login starts a username/password login on the given login option.
// The gateway answers with the password prompt (Challenge), or refuses.
func (g *Gateway) Login(ctx context.Context, loginOption, username, deviceID string) (*AuthResult, error) {
	data := Obj("",
		"client_type", V(ClientType),
		"username", V(Obfuscate(username)),
		"password", V(""),
		"client_logging_data", clientLoggingData(deviceID),
		"selectedLoginOption", V(loginOption),
	)
	rd, err := g.request(ctx, "UserPass", "", 0, data, 10*time.Minute)
	if err != nil {
		return nil, err
	}
	return authResult(rd)
}

// Challenge answers the pending prompt of an auth session.
func (g *Gateway) Challenge(ctx context.Context, sessionID, answer string) (*AuthResult, error) {
	data := Obj("",
		"client_type", V(ClientType),
		"auth_session_id", V(sessionID),
		"user_input", V(Obfuscate(answer)),
	)
	rd, err := g.request(ctx, "MultiChallange", sessionID, 0, data, 10*time.Minute)
	if err != nil {
		return nil, err
	}
	return authResult(rd)
}

// Routes asks the gateway which ranges the tunnel carries, for gateways
// whose hello_reply has none. The app uses them to decide which VPN a
// destination belongs to (its local proxy) and shows them in Details.
func (g *Gateway) Routes(ctx context.Context, sessionID string) ([]netip.Prefix, error) {
	rd, err := g.request(ctx, "ClientSettings", sessionID, 100, Obj("ClientSettings",
		"requested_policies_and_current_versions", Obj("", "range", Arr()),
	), 15*time.Second)
	if err != nil {
		return nil, err
	}
	return rangesToPrefixes(rd.List("updated_policies", "range", "settings")), nil
}

// Signout ends the session at the gateway.
func (g *Gateway) Signout(ctx context.Context, sessionID string) error {
	_, err := g.request(ctx, "Signout", sessionID, 100, Obj(""), 10*time.Second)
	return err
}

func authResult(rd *Node) (*AuthResult, error) {
	r := &AuthResult{SessionID: rd.Str("session_id"), Username: rd.Str("username")}
	switch status := rd.Str("authn_status"); status {
	case "continue":
		if p := rd.Str("prompt"); p != "" {
			r.Prompt, _ = Deobfuscate(p)
		}
		return r, nil
	case "done":
	default:
		return nil, authError(rd, "authentication status "+status)
	}
	key := rd.Str("active_key")
	if !rd.Bool("is_authenticated") || key == "" {
		return nil, authError(rd, "")
	}
	k, err := Deobfuscate(key)
	if err != nil {
		return nil, err
	}
	r.Done, r.ActiveKey = true, k
	r.KeyTTL = time.Duration(rd.Int("active_key_timeout")) * time.Second
	return r, nil
}

func authError(rd *Node, fallback string) error {
	e := &AuthError{Code: int(rd.Int("error_code"))}
	if s := rd.Str("error_message"); s != "" {
		e.Message, _ = Deobfuscate(s)
	}
	if s := rd.Str("error_id"); s != "" {
		e.ID, _ = Deobfuscate(s)
	}
	if e.Message == "" {
		e.Message = fallback
	}
	return e
}
