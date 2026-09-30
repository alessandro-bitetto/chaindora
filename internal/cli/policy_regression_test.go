package cli

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/alessandro-bitetto/chaindora/internal/inventory"
	"github.com/spf13/cobra"
)

func setPolicyTestFlag(t *testing.T, cmd *cobra.Command, name, value string) {
	t.Helper()
	flag := cmd.Flags().Lookup(name)
	before, changed := flag.Value.String(), flag.Changed
	if err := cmd.Flags().Set(name, value); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = flag.Value.Set(before); flag.Changed = changed })
}

func TestCIFailOnRejectsTyposBeforeInventory(t *testing.T) {
	for _, value := range []string{"critcal", "", "high,", "none,high", "any,critical", "critical,,high"} {
		t.Run(value, func(t *testing.T) {
			setPolicyTestFlag(t, ciCmd, "fail-on", value)
			err := ciCmd.RunE(ciCmd, []string{filepath.Join(t.TempDir(), "missing-project")})
			if err == nil || !strings.Contains(err.Error(), "invalid --fail-on") {
				t.Fatalf("invalid policy was not rejected first: %v", err)
			}
		})
	}
	for _, value := range []string{"critical,high", " HIGH , low ", "any", "none", "unknown"} {
		if err := validateFailOn(value); err != nil {
			t.Fatal(err)
		}
	}
}

func TestOfflineOverridesFreshPopularAcrossScanEntryPoints(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "package-lock.json"), []byte(`{"lockfileVersion":3,"packages":{"node_modules/lodash":{"version":"4.17.21"}}}`), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", os.Getenv("HOME"))
	var requests atomic.Int64
	original := http.DefaultTransport
	http.DefaultTransport = auditRoundTrip(func(*http.Request) (*http.Response, error) {
		requests.Add(1)
		return nil, fmt.Errorf("network forbidden by test")
	})
	t.Cleanup(func() { http.DefaultTransport = original })
	for _, cmd := range []*cobra.Command{scanCmd, ciCmd} {
		t.Run(cmd.Name(), func(t *testing.T) {
			for name, value := range map[string]string{"offline": "true", "fresh-popular": "true", "skip-incidents": "true", "skip-integrity": "true", "format": "json"} {
				setPolicyTestFlag(t, cmd, name, value)
			}
			// Offline mutates these derived flags; preserve their initial values.
			for _, name := range []string{"skip-osv", "skip-registry"} {
				setPolicyTestFlag(t, cmd, name, "false")
			}
			if err := cmd.RunE(cmd, []string{root}); err != nil {
				t.Fatal(err)
			}
		})
	}
	if _, err := scanProject(context.Background(), root, projectScanOpts{SkipOSV: true, SkipRegistry: true, SkipIncidents: true, SkipIntegrity: true, FreshPopular: true}); err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 0 {
		t.Fatalf("offline mode made %d HTTP requests", requests.Load())
	}
}

func TestIncidentPackSelectionRequiresUsableRecords(t *testing.T) {
	root, home := t.TempDir(), t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	previous, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(root); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Chdir(previous); err != nil {
			t.Error(err)
		}
	})
	inv := &inventory.Inventory{}
	if _, err := scanIncidents(context.Background(), inv, root, "", nil); err == nil {
		t.Fatal("missing default pack reported successful coverage")
	}
	pack := filepath.Join(home, ".chaindora", "incidents")
	if err := os.MkdirAll(pack, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := scanIncidents(context.Background(), inv, root, "", nil); err == nil {
		t.Fatal("empty default pack reported successful coverage")
	}
	if err := os.WriteFile(filepath.Join(pack, "fixture.yaml"), []byte("schema: 1\nid: INERT-TEST\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := scanIncidents(context.Background(), inv, root, "", nil); err != nil {
		t.Fatalf("valid home pack was not discovered: %v", err)
	}
	if _, err := scanIncidents(context.Background(), inv, root, filepath.Join(root, "missing"), nil); err == nil {
		t.Fatal("explicit missing path fell back to the valid home pack")
	}
	if err := os.Mkdir(filepath.Join(root, "incidents"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := scanIncidents(context.Background(), inv, root, "", nil); err == nil {
		t.Fatal("empty local pack fell back to the valid home pack")
	}
}
