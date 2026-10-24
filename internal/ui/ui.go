// Package ui is rveil's logging, on stderr, and its one question, on the
// terminal. Data goes to stdout; everything here goes to stderr.
//
// Log lines are plain, as rclone writes them:
//
//	2026/10/24 12:00:00 INFO  : tax docs 2019: sealed, verified
//
// or, with JSON, one object per line carrying fields for a program to use:
// an event (start, end, progress, or a named outcome), the step it belongs
// to, the archive, sizes, durations. Steps are logged as they start and
// end, and transfers report progress, so a front end can show what rveil
// is doing at every moment.
package ui

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"sync"
	"time"
)

// Levels, as rclone names them: NOTICE and up show by default.
const (
	LevelDebug  = slog.LevelDebug
	LevelInfo   = slog.LevelInfo
	LevelNotice = slog.LevelWarn
	LevelError  = slog.LevelError
)

// Stats is how often a transfer logs its progress.
var Stats = 5 * time.Second

var log = slog.New(newText(os.Stderr, LevelNotice))

// Setup picks the level and the format of the log on w.
func Setup(w io.Writer, level slog.Level, json bool) {
	if json {
		log = slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{Level: level, ReplaceAttr: jsonLevel}))
	} else {
		log = slog.New(newText(w, level))
	}
}

func levelName(l slog.Level) string {
	switch {
	case l >= LevelError:
		return "ERROR"
	case l >= LevelNotice:
		return "NOTICE"
	case l >= LevelInfo:
		return "INFO"
	}
	return "DEBUG"
}

func jsonLevel(_ []string, a slog.Attr) slog.Attr {
	if a.Key == slog.LevelKey {
		return slog.String(slog.LevelKey, strings.ToLower(levelName(a.Value.Any().(slog.Level))))
	}
	return a
}

// text writes the message only; the fields are for JSON.
type text struct {
	mu    *sync.Mutex
	w     io.Writer
	level slog.Level
}

func newText(w io.Writer, level slog.Level) *text { return &text{&sync.Mutex{}, w, level} }

func (h *text) Enabled(_ context.Context, l slog.Level) bool { return l >= h.level }
func (h *text) WithAttrs([]slog.Attr) slog.Handler           { return h }
func (h *text) WithGroup(string) slog.Handler                { return h }

func (h *text) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	_, err := fmt.Fprintf(h.w, "%s %-6s: %s\n", r.Time.Format("2006/01/02 15:04:05"), levelName(r.Level), r.Message)
	return err
}

// Debug, Info, Notice and Error log a message with fields: key, value pairs.
func Debug(msg string, fields ...any)  { log.Debug(msg, fields...) }
func Info(msg string, fields ...any)   { log.Info(msg, fields...) }
func Notice(msg string, fields ...any) { log.Warn(msg, fields...) }
func Error(msg string, fields ...any)  { log.Error(msg, fields...) }

// --- steps -----------------------------------------------------------------------

// Step is a stage of work, logged as it starts and ends.
type Step struct {
	name   string
	fields []any
	start  time.Time
}

// Begin logs the start of a step. name identifies it for programs
// (unlock_keys, upload…); msg is for people; fields go on each of the
// step's events.
func Begin(name, msg string, fields ...any) *Step {
	s := &Step{name: name, fields: fields, start: time.Now()}
	log.Info(msg, append([]any{"event", "start", "step", name}, fields...)...)
	return s
}

// End logs the end of the step, how long it took, and its error if any.
// More fields can come with it.
func (s *Step) End(err error, fields ...any) {
	took := time.Since(s.start)
	f := append([]any{"event", "end", "step", s.name, "seconds", took.Seconds()}, s.fields...)
	f = append(f, fields...)
	if err != nil {
		log.Debug(fmt.Sprintf("%s: failed after %s: %v", s.name, Duration(took), err), append(f, "error", err.Error())...)
		return
	}
	log.Debug(fmt.Sprintf("%s: done in %s", s.name, Duration(took)), f...)
}

// --- progress --------------------------------------------------------------------

// Progress counts the bytes of a step and logs them every Stats interval,
// and once at the end.
type Progress struct {
	mu          sync.Mutex
	step, label string
	fields      []any
	done, total int64
	start, last time.Time
}

// NewProgress starts counting; total may be 0 if unknown.
func NewProgress(step, label string, total int64, fields ...any) *Progress {
	now := time.Now()
	return &Progress{step: step, label: label, fields: fields, total: total, start: now, last: now}
}

// Write counts bytes passing through.
func (p *Progress) Write(b []byte) (int, error) {
	p.mu.Lock()
	p.done += int64(len(b))
	p.tick(false)
	p.mu.Unlock()
	return len(b), nil
}

// Set updates the counts.
func (p *Progress) Set(done, total int64) {
	p.mu.Lock()
	p.done, p.total = done, total
	p.tick(false)
	p.mu.Unlock()
}

// End logs the final count.
func (p *Progress) End() {
	p.mu.Lock()
	p.tick(true)
	p.mu.Unlock()
}

func (p *Progress) tick(final bool) {
	if !final && time.Since(p.last) < Stats {
		return
	}
	p.last = time.Now()
	secs := time.Since(p.start).Seconds()
	var rate float64
	if secs > 0 {
		rate = float64(p.done) / secs
	}
	msg := p.label + ": " + Bytes(p.done)
	f := []any{"event", "progress", "step", p.step, "bytes", p.done, "total", p.total,
		"bytes_per_second", int64(rate), "seconds", secs}
	if p.total > 0 {
		msg += fmt.Sprintf(" / %s, %d%%", Bytes(p.total), min(100, p.done*100/p.total))
	}
	msg += ", " + Bytes(int64(rate)) + "/s"
	if p.total > p.done && rate > 0 {
		eta := time.Duration(float64(p.total-p.done) / rate * float64(time.Second))
		msg += ", ETA " + Duration(eta)
		f = append(f, "eta_seconds", eta.Seconds())
	}
	log.Info(msg, append(f, p.fields...)...)
}

// --- formatting ------------------------------------------------------------------

// Bytes renders a size: 1.2 GiB.
func Bytes(n int64) string {
	f := float64(n)
	for _, u := range []string{"B", "KiB", "MiB", "GiB", "TiB"} {
		if f < 1024 || u == "TiB" {
			if u == "B" {
				return fmt.Sprintf("%d B", n)
			}
			return fmt.Sprintf("%.1f %s", f, u)
		}
		f /= 1024
	}
	return ""
}

// Duration renders a duration in milliseconds under a second, tenths of
// a second under a minute, whole seconds past it.
func Duration(d time.Duration) string {
	switch {
	case d < time.Second:
		return d.Round(time.Millisecond).String()
	case d < time.Minute:
		return d.Round(100 * time.Millisecond).String()
	}
	return d.Round(time.Second).String()
}

// --- questions -------------------------------------------------------------------

// ErrNoTerminal means a question couldn't be asked.
var ErrNoTerminal = errors.New("this needs confirmation on a terminal; pass -y to go ahead without it")

// Confirm shows what is about to happen and asks a yes/no question on the
// terminal; the default is no.
func Confirm(question string, items []string) (bool, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return false, ErrNoTerminal
	}
	defer tty.Close()
	for _, it := range items {
		fmt.Fprintln(tty, it)
	}
	fmt.Fprintf(tty, "%s [y/N] ", question)
	answer, _ := bufio.NewReader(tty).ReadString('\n')
	answer = strings.ToLower(strings.TrimSpace(answer))
	return answer == "y" || answer == "yes", nil
}
