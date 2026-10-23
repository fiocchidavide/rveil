// Package ui prints status lines and progress to stderr and asks questions
// on the terminal. Data goes to stdout; everything here goes to stderr.
package ui

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/term"
)

var (
	// Quiet silences status lines and progress (errors still show).
	Quiet bool
	// Color is on when stderr is a terminal and NO_COLOR is unset.
	Color = term.IsTerminal(int(os.Stderr.Fd())) && os.Getenv("NO_COLOR") == ""

	stderr io.Writer = os.Stderr
	mu     sync.Mutex
)

func paint(code, s string) string {
	if !Color {
		return s
	}
	return "\x1b[" + code + "m" + s + "\x1b[0m"
}

func line(icon, color, msg string) {
	mu.Lock()
	defer mu.Unlock()
	fmt.Fprintln(stderr, paint(color, icon)+" "+msg)
}

// Step announces something that takes a while.
func Step(format string, a ...any) {
	if !Quiet {
		line("▸", "1", paint("1", fmt.Sprintf(format, a...)))
	}
}

// Info adds a detail.
func Info(format string, a ...any) {
	if !Quiet {
		line(" ", "2", paint("2", fmt.Sprintf(format, a...)))
	}
}

// OK reports success.
func OK(format string, a ...any) {
	if !Quiet {
		line("✔", "32", fmt.Sprintf(format, a...))
	}
}

// Warn reports something to look at.
func Warn(format string, a ...any) { line("!", "33", fmt.Sprintf(format, a...)) }

// Err reports a failure.
func Err(format string, a ...any) { line("✘", "31", fmt.Sprintf(format, a...)) }

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

// Progress draws a progress line while bytes pass through it. It draws
// nothing when quiet or when stderr isn't a terminal.
type Progress struct {
	label string
	total int64
	done  int64
	start time.Time
	last  time.Time
	live  bool
}

// NewProgress starts a progress line; total may be 0 if unknown.
func NewProgress(label string, total int64) *Progress {
	return &Progress{label: label, total: total, start: time.Now(),
		live: !Quiet && term.IsTerminal(int(os.Stderr.Fd()))}
}

// Write counts bytes.
func (p *Progress) Write(b []byte) (int, error) {
	p.Set(p.done+int64(len(b)), p.total)
	return len(b), nil
}

// Set updates the counts.
func (p *Progress) Set(done, total int64) {
	p.done, p.total = done, total
	if p.live && time.Since(p.last) >= 200*time.Millisecond {
		p.last = time.Now()
		p.draw()
	}
}

func (p *Progress) draw() {
	s := "  " + p.label + "  " + Bytes(p.done)
	if p.total > 0 {
		s += fmt.Sprintf(" / %s  %3d%%", Bytes(p.total), min(100, p.done*100/p.total))
	}
	if secs := time.Since(p.start).Seconds(); secs > 1 {
		s += "  " + Bytes(int64(float64(p.done)/secs)) + "/s"
	}
	mu.Lock()
	fmt.Fprint(stderr, "\r\x1b[K"+paint("2", s))
	mu.Unlock()
}

// Done clears the progress line.
func (p *Progress) Done() {
	if p.live && !p.last.IsZero() {
		mu.Lock()
		fmt.Fprint(stderr, "\r\x1b[K")
		mu.Unlock()
	}
}

// ErrNoTerminal means a question couldn't be asked.
var ErrNoTerminal = errors.New("this needs confirmation on a terminal; pass -y to go ahead without it")

// Confirm asks a yes/no question on the terminal; the default is no.
func Confirm(question string) (bool, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return false, ErrNoTerminal
	}
	defer tty.Close()
	fmt.Fprintf(tty, "%s [y/N] ", question)
	answer, _ := bufio.NewReader(tty).ReadString('\n')
	answer = strings.ToLower(strings.TrimSpace(answer))
	return answer == "y" || answer == "yes", nil
}
