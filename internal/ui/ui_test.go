package ui

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"regexp"
	"strings"
	"testing"
	"time"
)

func logTo(t *testing.T, level int, asJSON bool) *bytes.Buffer {
	var b bytes.Buffer
	Setup(&b, levelFrom(level), asJSON)
	t.Cleanup(func() { Setup(&bytes.Buffer{}, LevelNotice, false) })
	return &b
}

// levelFrom keeps the tests readable: -1 quiet, 0 default, 1 -v, 2 -vv.
func levelFrom(n int) slog.Level {
	return map[int]slog.Level{-1: LevelError, 0: LevelNotice, 1: LevelInfo, 2: LevelDebug}[n]
}

func work() {
	s := Begin("upload", "Uploading x", "file", "x")
	p := NewProgress("upload", "x: uploaded", 100, "file", "x")
	p.Set(50, 100)
	p.End()
	s.End(nil)
	Notice("Something to look at", "event", "odd")
	Error("It broke", "event", "fatal")
}

func TestTextLevels(t *testing.T) {
	line := regexp.MustCompile(`^\d{4}/\d\d/\d\d \d\d:\d\d:\d\d (DEBUG |INFO  |NOTICE|ERROR ): \S`)
	for level, want := range map[int]int{-1: 1, 0: 2, 1: 4, 2: 5} {
		b := logTo(t, level, false)
		work()
		lines := strings.Split(strings.TrimSpace(b.String()), "\n")
		if len(lines) != want {
			t.Fatalf("level %d: %d lines, want %d:\n%s", level, len(lines), want, b)
		}
		for _, l := range lines {
			if !line.MatchString(l) {
				t.Fatalf("level %d: not an rclone-style line: %q", level, l)
			}
		}
	}
}

func TestJSONEvents(t *testing.T) {
	Stats = time.Hour // only the final progress
	b := logTo(t, 2, true)
	work()
	var events []string
	for _, l := range strings.Split(strings.TrimSpace(b.String()), "\n") {
		var e map[string]any
		if err := json.Unmarshal([]byte(l), &e); err != nil {
			t.Fatalf("not JSON: %q", l)
		}
		events = append(events, e["level"].(string)+":"+e["event"].(string))
		if e["event"] == "progress" && (e["bytes"] != 50.0 || e["total"] != 100.0 || e["file"] != "x") {
			t.Fatalf("progress fields: %v", e)
		}
	}
	want := "info:start info:progress debug:end notice:odd error:fatal"
	if got := strings.Join(events, " "); got != want {
		t.Fatalf("events %q, want %q", got, want)
	}
}

func TestStepFailure(t *testing.T) {
	b := logTo(t, 2, true)
	Begin("move", "Moving").End(errors.New("gone"))
	if !strings.Contains(b.String(), `"error":"gone"`) || !strings.Contains(b.String(), `"step":"move"`) {
		t.Fatalf("failed step: %s", b)
	}
}
