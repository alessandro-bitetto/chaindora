package gate

import (
	"context"
	"testing"
	"time"
)

func TestConfig_CooldownThreshold_FallbackOnNilOrZero(t *testing.T) {
	def := 72 * time.Hour

	// nil config → default
	var nilCfg *Config
	if got := nilCfg.CooldownThreshold(def); got != def {
		t.Errorf("nil config: got %v, want %v", got, def)
	}

	// zero hours → default
	cfg := &Config{CooldownHours: 0}
	if got := cfg.CooldownThreshold(def); got != def {
		t.Errorf("zero hours: got %v, want %v", got, def)
	}

	// negative hours → default
	cfg = &Config{CooldownHours: -5}
	if got := cfg.CooldownThreshold(def); got != def {
		t.Errorf("negative hours: got %v, want %v", got, def)
	}

	// explicit positive → that value
	cfg = &Config{CooldownHours: 24}
	if got := cfg.CooldownThreshold(def); got != 24*time.Hour {
		t.Errorf("explicit 24h: got %v, want %v", got, 24*time.Hour)
	}
}

func TestConfig_Policy_NilIsStrict(t *testing.T) {
	var nilCfg *Config
	p := nilCfg.Policy()
	if p.AllowOnWarn || p.AllowOnUnknown {
		t.Errorf("nil config must yield Strict; got %+v", p)
	}
}

func TestConfig_Policy_ReflectsFlags(t *testing.T) {
	cfg := &Config{AllowOnWarn: true, AllowOnUnknown: false}
	p := cfg.Policy()
	if !p.AllowOnWarn || p.AllowOnUnknown {
		t.Errorf("Lenient-style config: got %+v", p)
	}

	cfg = &Config{AllowOnWarn: true, AllowOnUnknown: true}
	p = cfg.Policy()
	if !p.AllowOnWarn || !p.AllowOnUnknown {
		t.Errorf("Allow-offline-style config: got %+v", p)
	}
}

func TestNewCooldown_ZeroFallsBackTo72h(t *testing.T) {
	c := NewCooldown(0)
	if c.Threshold != 72*time.Hour {
		t.Errorf("zero threshold should default to 72h, got %v", c.Threshold)
	}
	if c.Probes == nil {
		t.Error("Probes should be auto-initialized")
	}
}

func TestNewCooldown_NegativeFallsBackTo72h(t *testing.T) {
	c := NewCooldown(-1 * time.Hour)
	if c.Threshold != 72*time.Hour {
		t.Errorf("negative threshold should default to 72h, got %v", c.Threshold)
	}
}

func TestNewCooldown_ExplicitValueRespected(t *testing.T) {
	c := NewCooldown(24 * time.Hour)
	if c.Threshold != 24*time.Hour {
		t.Errorf("got %v, want %v", c.Threshold, 24*time.Hour)
	}
}

func TestNewCooldown_NameIsCooldown(t *testing.T) {
	c := NewCooldown(72 * time.Hour)
	if c.Name() != "cooldown" {
		t.Errorf("Name() = %q, want %q", c.Name(), "cooldown")
	}
}

func TestCooldown_Check_GitEcosystemPassthrough(t *testing.T) {
	// Git-URL packages have no registry publish-date concept; the
	// cooldown checker passes them through.
	c := NewCooldown(72 * time.Hour)
	r := c.Check(context.Background(), PackageRef{Ecosystem: "git", Name: "github.com/u/r", Version: "abcdef"})
	if r.Verdict != VerdictApprove {
		t.Errorf("git refs should be approved by cooldown, got %v: %q", r.Verdict, r.Reason)
	}
}
