package gate

import (
	"context"
	"encoding/json"
	"errors"
	"os/exec"
	"strings"
)

// ResolveCondaTree resolves what `conda install <pkg>` would
// install. Approach:
//   1. `conda install --dry-run --json <pkg>` returns a JSON plan
//      with `actions.LINK` listing every package conda would
//      fetch+link, including transitives.
//   2. Each entry has a `sha256` field (or md5 for older builds).
//
// Conda has its own ecosystem outside OSV's coverage, so the
// OSV checker is a no-op here — gate signal for conda comes from
// cooldown, integrity-republish, and static-pattern.
//
// Conda packages CAN run post-link scripts (post-link.sh /
// post-link.bat). --dry-run skips fetching/extracting, so those
// scripts don't execute during resolution.
//
// condaPath is the absolute path to the real `conda` binary (or
// `mamba` / `micromamba` — all expose --dry-run --json).
func ResolveCondaTree(ctx context.Context, condaPath string, installArgs []string) ([]PackageRef, error) {
	if len(installArgs) == 0 {
		return nil, errors.New("no conda install args supplied")
	}
	conda := condaPath
	if conda == "" {
		conda = "conda"
	}
	// Strip a leading "install" verb token if present.
	if len(installArgs) > 0 && installArgs[0] == "install" {
		installArgs = installArgs[1:]
	}
	args := append([]string{
		"install",
		"--dry-run",
		"--json",
		"--yes",
	}, installArgs...)
	cmd := exec.CommandContext(ctx, conda, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		// `conda install --dry-run` exits non-zero on solver
		// conflicts; the JSON body is still present and useful.
		// Only surface as PMError if the body wasn't parseable.
		if refs, parseErr := parseCondaDryRun(out); parseErr == nil && len(refs) > 0 {
			return refs, nil
		}
		return nil, wrapPMError("conda", "install --dry-run --json", out, err)
	}
	return parseCondaDryRun(out)
}

// parseCondaDryRun parses conda's --dry-run --json output. Schema
// (the `actions` field is what we care about):
//
//	{
//	  "actions": {
//	    "LINK": [
//	      {
//	        "name": "numpy",
//	        "version": "1.26.4",
//	        "channel": "conda-forge",
//	        "url": "https://conda.anaconda.org/.../numpy-1.26.4-py311.conda",
//	        "sha256": "abc...",
//	        "md5": "xyz..."
//	      }
//	    ]
//	  },
//	  "success": true,
//	  "dry_run": true
//	}
//
// Older mamba versions sometimes nest LINK under a list of plans
// (transactions). We handle both shapes.
func parseCondaDryRun(data []byte) ([]PackageRef, error) {
	// conda may emit multiple JSON objects in some failure modes
	// (one per channel-priority pass). Take the first parsing one.
	dec := json.NewDecoder(strings.NewReader(string(data)))
	var first struct {
		Actions json.RawMessage `json:"actions"`
	}
	if err := dec.Decode(&first); err != nil {
		return nil, err
	}
	if len(first.Actions) == 0 {
		return nil, nil
	}
	// `actions` is either a map {"LINK": [...]} (single env) or an
	// array of such maps (multi-env plan). Try both.
	var single struct {
		LINK []condaLinkEntry `json:"LINK"`
	}
	if err := json.Unmarshal(first.Actions, &single); err == nil && len(single.LINK) > 0 {
		return condaLinkEntriesToRefs(single.LINK), nil
	}
	var multi []struct {
		LINK []condaLinkEntry `json:"LINK"`
	}
	if err := json.Unmarshal(first.Actions, &multi); err == nil {
		var all []condaLinkEntry
		for _, m := range multi {
			all = append(all, m.LINK...)
		}
		return condaLinkEntriesToRefs(all), nil
	}
	return nil, nil
}

type condaLinkEntry struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Channel string `json:"channel"`
	URL     string `json:"url"`
	Sha256  string `json:"sha256"`
	MD5     string `json:"md5"`
}

func condaLinkEntriesToRefs(entries []condaLinkEntry) []PackageRef {
	seen := map[string]struct{}{}
	var refs []PackageRef
	for _, e := range entries {
		if e.Name == "" || e.Version == "" {
			continue
		}
		key := e.Name + "@" + e.Version
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		integrity := ""
		if e.Sha256 != "" {
			integrity = "sha256:" + e.Sha256
		} else if e.MD5 != "" {
			integrity = "md5:" + e.MD5
		}
		refs = append(refs, PackageRef{
			Ecosystem: "conda",
			Name:      e.Name,
			Version:   e.Version,
			Integrity: integrity,
		})
	}
	return refs
}
