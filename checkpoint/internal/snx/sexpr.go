// Package snx is a Check Point remote access VPN client (the SSL Network
// Extender tunnel): the CCC login exchange over HTTPS and the SLIM packet
// tunnel over TLS.
//
// It is based on snx-rs by Dmitry Pankratov
// (https://github.com/ancwrd1/snx-rs, AGPL-3.0): written in Go from a
// study of its source, not translated, but its s-expression encoding, the
// login and auth-response handling, the tunnel hello and keepalive
// values, the ClientSettings request and the secret obfuscation follow
// it, and some test fixtures come from it (marked in snx_test.go). This
// package, like the rest of the plugin, is therefore AGPL-3.0.
package snx

import (
	"fmt"
	"strconv"
	"strings"
)

// Check Point messages are s-expressions:
//
//	(name
//		:field (value)
//		:list (
//			: (item)
//			: (:from (10.0.0.0) :to (10.255.255.255)))
//		:empty ())
//
// A node is a value, an object (optional name, ordered fields) or an
// array. "()" is the empty value.

// Kind tells which of the three shapes a Node has.
type Kind int

const (
	KindValue Kind = iota
	KindObject
	KindArray
)

// Field is one ":name (node)" entry of an object.
type Field struct {
	Name string
	Node *Node
}

// Node is one parsed (or to-be-encoded) s-expression.
type Node struct {
	Kind   Kind
	Value  string  // KindValue
	Name   string  // KindObject, may be ""
	Fields []Field // KindObject
	Items  []*Node // KindArray
}

// V is a value node.
func V(s string) *Node { return &Node{Kind: KindValue, Value: s} }

// Obj is an object node; kv alternates field names and nodes. A nil node
// drops the field (an absent optional).
func Obj(name string, kv ...any) *Node {
	n := &Node{Kind: KindObject, Name: name}
	for i := 0; i+1 < len(kv); i += 2 {
		v, _ := kv[i+1].(*Node)
		if v == nil {
			continue
		}
		n.Fields = append(n.Fields, Field{Name: kv[i].(string), Node: v})
	}
	return n
}

// Arr is an array node.
func Arr(items ...*Node) *Node { return &Node{Kind: KindArray, Items: items} }

// Get walks fields by name (and array items by index); nil when absent.
// The object's own name is not part of the path.
func (n *Node) Get(path ...string) *Node {
	cur := n
	for _, p := range path {
		if cur == nil {
			return nil
		}
		switch cur.Kind {
		case KindObject:
			var next *Node
			for _, f := range cur.Fields {
				if f.Name == p {
					next = f.Node
					break
				}
			}
			cur = next
		case KindArray:
			i, err := strconv.Atoi(p)
			if err != nil || i < 0 || i >= len(cur.Items) {
				return nil
			}
			cur = cur.Items[i]
		default:
			return nil
		}
	}
	return cur
}

// Str is the value at path, "" when absent or not a value.
func (n *Node) Str(path ...string) string {
	v := n.Get(path...)
	if v == nil || v.Kind != KindValue {
		return ""
	}
	return v.Value
}

// Int is the numeric value at path (decimal or 0x hex), 0 when absent.
func (n *Node) Int(path ...string) int64 {
	s := n.Str(path...)
	v, err := strconv.ParseInt(s, 0, 64)
	if err != nil {
		return 0
	}
	return v
}

// Bool is the value at path read as true/false.
func (n *Node) Bool(path ...string) bool { return n.Str(path...) == "true" }

// List is the items of the array at path. A single object or value where
// a one-item list was expected counts as that item; "()" is empty.
func (n *Node) List(path ...string) []*Node {
	v := n.Get(path...)
	switch {
	case v == nil:
		return nil
	case v.Kind == KindArray:
		return v.Items
	case v.Kind == KindValue && v.Value == "":
		return nil
	default:
		return []*Node{v}
	}
}

// String encodes the node the way Check Point clients do: one field per
// line, tab indented.
func (n *Node) String() string {
	var b strings.Builder
	n.encode(&b, 0)
	return b.String()
}

func (n *Node) encode(b *strings.Builder, level int) {
	switch n.Kind {
	case KindValue:
		b.WriteString("(" + quote(n.Value) + ")")
	case KindObject:
		b.WriteString("(" + quote(n.Name))
		for _, f := range n.Fields {
			b.WriteString("\n" + strings.Repeat("\t", level+1) + ":" + f.Name + " ")
			f.Node.encode(b, level+1)
		}
		b.WriteString(")")
	case KindArray:
		b.WriteString("(")
		for _, it := range n.Items {
			b.WriteString("\n" + strings.Repeat("\t", level+1) + ": ")
			it.encode(b, level+1)
		}
		b.WriteString(")")
	}
}

func quote(s string) string {
	for i := 0; i < len(s); i++ {
		if !isIdent(s[i]) {
			return `"` + strings.ReplaceAll(s, `"`, `\"`) + `"`
		}
	}
	return s
}

func isIdent(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
		c == '-' || c == '_' || c == '.'
}

// Parse reads one s-expression. Trailing NULs and whitespace are allowed.
func Parse(s string) (*Node, error) {
	p := &parser{s: s}
	p.ws()
	n, err := p.node()
	if err != nil {
		return nil, err
	}
	p.ws()
	if p.i != len(p.s) {
		return nil, p.errf("trailing data")
	}
	return n, nil
}

type parser struct {
	s string
	i int
}

func (p *parser) errf(format string, a ...any) error {
	return fmt.Errorf("s-expression at %d: %s", p.i, fmt.Sprintf(format, a...))
}

func (p *parser) ws() {
	for p.i < len(p.s) {
		switch p.s[p.i] {
		case ' ', '\t', '\r', '\n', 0:
			p.i++
		default:
			return
		}
	}
}

func (p *parser) peek() byte {
	if p.i < len(p.s) {
		return p.s[p.i]
	}
	return 0
}

// fieldAhead: ":name" (a field), as opposed to ": (" (an array item).
func (p *parser) fieldAhead() bool {
	return p.peek() == ':' && p.i+1 < len(p.s) && (isIdent(p.s[p.i+1]) || p.s[p.i+1] == '"')
}

func (p *parser) node() (*Node, error) {
	if p.peek() != '(' {
		return nil, p.errf("expected '('")
	}
	p.i++
	p.ws()
	switch {
	case p.peek() == ')':
		p.i++
		return V(""), nil
	case p.fieldAhead():
		return p.object("")
	case p.peek() == ':':
		return p.array()
	case p.i >= len(p.s):
		return nil, p.errf("unterminated expression")
	}
	start := p.i
	var head string
	if p.peek() == '"' {
		q, err := p.quoted()
		if err != nil {
			return nil, err
		}
		head = q
	} else {
		for p.i < len(p.s) && isIdent(p.s[p.i]) {
			p.i++
		}
		head = p.s[start:p.i]
	}
	p.ws()
	if p.fieldAhead() {
		return p.object(head)
	}
	if p.s[start] == '"' {
		if p.peek() != ')' {
			return nil, p.errf("expected ')' after quoted value")
		}
		p.i++
		return V(head), nil
	}
	// A plain value runs to the closing paren (it may hold spaces, '/', ...).
	end := strings.IndexByte(p.s[start:], ')')
	if end < 0 {
		return nil, p.errf("unterminated value")
	}
	if open := strings.IndexByte(p.s[start:start+end], '('); open >= 0 {
		p.i = start + open
		return nil, p.errf("unexpected '('")
	}
	v := strings.TrimSpace(p.s[start : start+end])
	p.i = start + end + 1
	return V(v), nil
}

func (p *parser) quoted() (string, error) {
	p.i++ // opening quote
	var b strings.Builder
	for p.i < len(p.s) {
		c := p.s[p.i]
		switch {
		case c == '\\' && p.i+1 < len(p.s) && p.s[p.i+1] == '"':
			b.WriteByte('"')
			p.i += 2
		case c == '"':
			p.i++
			return b.String(), nil
		default:
			b.WriteByte(c)
			p.i++
		}
	}
	return "", p.errf("unterminated string")
}

func (p *parser) object(name string) (*Node, error) {
	n := &Node{Kind: KindObject, Name: name}
	for {
		p.ws()
		if p.peek() == ')' {
			p.i++
			return n, nil
		}
		if !p.fieldAhead() {
			return nil, p.errf("expected field")
		}
		p.i++ // ':'
		var key string
		if p.peek() == '"' {
			q, err := p.quoted()
			if err != nil {
				return nil, err
			}
			key = q
		} else {
			start := p.i
			for p.i < len(p.s) && isIdent(p.s[p.i]) {
				p.i++
			}
			key = p.s[start:p.i]
		}
		p.ws()
		v, err := p.node()
		if err != nil {
			return nil, err
		}
		n.Fields = append(n.Fields, Field{Name: key, Node: v})
	}
}

func (p *parser) array() (*Node, error) {
	n := &Node{Kind: KindArray}
	for {
		p.ws()
		if p.peek() == ')' {
			p.i++
			return n, nil
		}
		if p.peek() != ':' {
			return nil, p.errf("expected array item")
		}
		p.i++
		p.ws()
		v, err := p.node()
		if err != nil {
			return nil, err
		}
		n.Items = append(n.Items, v)
	}
}
