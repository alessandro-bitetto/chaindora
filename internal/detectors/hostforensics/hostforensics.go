package hostforensics

import (
	"context"
	"os"

	"github.com/alessandro-bitetto/chaindora/internal/findings"
)

// Detector inspects user home-directory state for post-compromise artifacts.
type Detector struct {
	home string
}

// New constructs a Detector rooted at home. If home is empty, falls back to
// the current user's home directory.
func New(home string) *Detector {
	if home == "" {
		home, _ = os.UserHomeDir()
	}
	return &Detector{home: home}
}

func (d *Detector) Home() string {
	return d.home
}

// Detect runs all host-state checks and aggregates their findings.
func (d *Detector) Detect(ctx context.Context) ([]findings.Finding, error) {
	_ = ctx
	var out []findings.Finding
	out = append(out, scanTokens(d.home)...)
	out = append(out, scanShellRC(d.home)...)
	return out, nil
}
