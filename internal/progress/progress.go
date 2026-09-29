// Package progress provides a single-line, self-overwriting status indicator
// for long-running scans. The Reporter is TTY-aware: when its writer is a
// terminal it ticks every ~200ms with the current label + counter; when its
// writer is piped / redirected / NO_COLOR is set, it's a no-op so machine-
// readable outputs stay clean.
package progress

import (
	"fmt"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// Reporter is cheap to call from hot paths. Tick() is a lock-free atomic
// increment; the actual screen update happens on a background goroutine.
// Reporter is safe for concurrent use.
type Reporter struct {
	w        io.Writer
	isTTY    bool
	interval time.Duration

	mu      sync.Mutex
	label   string
	counter atomic.Int64
	hits    atomic.Int64

	stopCh chan struct{}
	doneCh chan struct{}
	active bool
}

// New constructs a Reporter writing to w. If w isn't a TTY, every method
// becomes a no-op (so the same call sites work both interactively and in
// CI / pipe contexts).
func New(w io.Writer) *Reporter {
	return &Reporter{
		w:        w,
		isTTY:    isTerminal(w),
		interval: 200 * time.Millisecond,
	}
}

// Start begins ticking with the given label. Idempotent — calling Start
// twice without Stop in between is a no-op for the second call.
func (r *Reporter) Start(label string) {
	if !r.isTTY {
		return
	}
	r.mu.Lock()
	if r.active {
		r.mu.Unlock()
		return
	}
	r.label = label
	r.counter.Store(0)
	r.hits.Store(0)
	r.stopCh = make(chan struct{})
	r.doneCh = make(chan struct{})
	r.active = true
	r.mu.Unlock()
	go r.loop()
}

// SetLabel updates the displayed label without resetting the counter.
// Useful when moving from one phase to another mid-scan ("hunting under /"
// → "scanning project /Users/me/code/foo").
func (r *Reporter) SetLabel(label string) {
	if !r.isTTY {
		return
	}
	r.mu.Lock()
	r.label = label
	r.mu.Unlock()
}

// Tick increments the items-seen counter.
func (r *Reporter) Tick() {
	if !r.isTTY {
		return
	}
	r.counter.Add(1)
}

// Hit increments the findings-seen counter (the secondary number displayed
// next to the items counter).
func (r *Reporter) Hit() {
	if !r.isTTY {
		return
	}
	r.hits.Add(1)
}

// Stop halts the ticker and clears the progress line. If summary is non-
// empty, prints it as the final line. Idempotent.
func (r *Reporter) Stop(summary string) {
	if !r.isTTY {
		return
	}
	r.mu.Lock()
	if !r.active {
		r.mu.Unlock()
		return
	}
	r.active = false
	stopCh := r.stopCh
	doneCh := r.doneCh
	r.mu.Unlock()
	close(stopCh)
	<-doneCh
	r.mu.Lock()
	defer r.mu.Unlock()
	// Erase the last progress line, then optionally print a summary.
	fmt.Fprint(r.w, "\r\033[K")
	if summary != "" {
		fmt.Fprintln(r.w, summary)
	}
}

func (r *Reporter) loop() {
	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()
	defer close(r.doneCh)
	for {
		select {
		case <-r.stopCh:
			return
		case <-ticker.C:
			r.render()
		}
	}
}

func (r *Reporter) render() {
	r.mu.Lock()
	label := r.label
	r.mu.Unlock()
	c := r.counter.Load()
	h := r.hits.Load()
	if h > 0 {
		fmt.Fprintf(r.w, "\r\033[K[chdora] %s: %s items, %d hits", label, formatCount(c), h)
	} else {
		fmt.Fprintf(r.w, "\r\033[K[chdora] %s: %s items", label, formatCount(c))
	}
}

// formatCount prints integers with thousand separators ("1,234,567") so the
// counter is legible at a glance. Locale-independent (always uses ',').
func formatCount(n int64) string {
	if n < 1000 {
		return fmt.Sprintf("%d", n)
	}
	s := fmt.Sprintf("%d", n)
	out := make([]byte, 0, len(s)+len(s)/3)
	for i, c := range []byte(s) {
		if i > 0 && (len(s)-i)%3 == 0 {
			out = append(out, ',')
		}
		out = append(out, c)
	}
	return string(out)
}

// isTerminal mirrors the same detection rule the renderer uses: writer is
// an *os.File pointing at a char device, and NO_COLOR is unset.
// https://no-color.org/
func isTerminal(w io.Writer) bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}
