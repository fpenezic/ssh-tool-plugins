package openconnect

// ssh-tool patch (not upstream): expose the AnyConnect session cookie so
// the plugin can hand it back to the app, which resumes the session with
// ClientOptions.Cookie after an idle stop instead of logging in again.
// The only other change is the setSessionCookie call in
// anyConnectFrontend.ConnectTunnel. See ../README.md.

import "sync"

var sessionCookies sync.Map // *Client -> string

// SessionCookie returns the cookie of the tunnel that is up (AnyConnect
// only), or "" before the first successful connect.
func (c *Client) SessionCookie() string {
	v, _ := sessionCookies.Load(c)
	s, _ := v.(string)
	return s
}

func (c *Client) setSessionCookie(cookie string) {
	sessionCookies.Store(c, cookie)
}
