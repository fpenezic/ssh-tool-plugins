package main

import (
	"context"
	"fmt"
	"log"
	"os"
)

// libLogger routes the OpenConnect library's own log into stderr, which
// the app copies into its log: warnings and errors always, the protocol
// detail (retries, rejected sessions, ignored frames) with
// SSHTOOL_OC_DEBUG=1; info (tunnel established / re-established) always.
// The library never logs form values.
type libLogger struct{ debug bool }

func newLibLogger() *libLogger { return &libLogger{debug: os.Getenv("SSHTOOL_OC_DEBUG") == "1"} }

func (l *libLogger) out(level string, on bool, args []any) {
	if on {
		log.Printf("oc %s: %s", level, fmt.Sprint(args...))
	}
}

func (l *libLogger) Trace(args ...any) {}
func (l *libLogger) Debug(args ...any) { l.out("debug", l.debug, args) }
func (l *libLogger) Info(args ...any)  { l.out("info", true, args) }
func (l *libLogger) Warn(args ...any)  { l.out("warn", true, args) }
func (l *libLogger) Error(args ...any) { l.out("error", true, args) }
func (l *libLogger) Fatal(args ...any) { l.out("fatal", true, args) }
func (l *libLogger) Panic(args ...any) { l.out("panic", true, args) }

func (l *libLogger) TraceContext(_ context.Context, args ...any) {}
func (l *libLogger) DebugContext(_ context.Context, args ...any) { l.Debug(args...) }
func (l *libLogger) InfoContext(_ context.Context, args ...any)  { l.Info(args...) }
func (l *libLogger) WarnContext(_ context.Context, args ...any)  { l.Warn(args...) }
func (l *libLogger) ErrorContext(_ context.Context, args ...any) { l.Error(args...) }
func (l *libLogger) FatalContext(_ context.Context, args ...any) { l.Fatal(args...) }
func (l *libLogger) PanicContext(_ context.Context, args ...any) { l.Panic(args...) }
