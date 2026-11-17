package main

import (
	"errors"
	"strings"
	"testing"
	"time"
)

func TestDropLog(t *testing.T) {
	var d dropLog
	t0 := time.Unix(1000, 0)
	errDown := errors.New("data channel is not ready")

	if msg := d.note(nil, t0); msg != "" {
		t.Fatalf("success with nothing dropped logged %q", msg)
	}
	if msg := d.note(errDown, t0); !strings.Contains(msg, "dropping packets") {
		t.Fatalf("first failure: %q", msg)
	}
	for i := 0; i < 50; i++ {
		if msg := d.note(errDown, t0.Add(time.Duration(i)*time.Second)); msg != "" {
			t.Fatalf("failure %d logged %q", i, msg)
		}
	}
	if msg := d.note(errDown, t0.Add(dropRemind)); !strings.Contains(msg, "still failing") || !strings.Contains(msg, "52 packets") {
		t.Fatalf("reminder: %q", msg)
	}
	if msg := d.note(nil, t0.Add(75*time.Second)); !strings.Contains(msg, "sending again after 1m15s, 52 packets dropped") {
		t.Fatalf("recovery: %q", msg)
	}
	if msg := d.note(nil, t0.Add(76*time.Second)); msg != "" {
		t.Fatalf("second success logged %q", msg)
	}
	if msg := d.note(errDown, t0.Add(80*time.Second)); !strings.Contains(msg, "dropping packets") {
		t.Fatalf("new outage: %q", msg)
	}
}
