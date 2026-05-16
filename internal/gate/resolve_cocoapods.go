package gate

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// ResolveCocoaPodsTree resolves the dependency set declared by the
// user's Podfile. CocoaPods has no "add this package" CLI — devs
// edit Podfile by hand and run `pod install` / `pod update`. The
// gate intercepts those verbs.
//
// Implementation: run `pod install --no-repo-update` (or `update`)
// in a temp dir seeded with a COPY of the user's Podfile +
// Podfile.lock (so we don't touch the user's Xcode project's
// Pods/ during resolution). The resolved Podfile.lock comes back
// for parsing. SPEC CHECKSUMS gives a sha1 per pod which we use
// as PackageRef.Integrity.
//
// CocoaPods does run `prepare_command` and post_install hooks from
// Podfile + podspec files. That's a real concern — `pod install`
// could execute attacker code during resolution. We mitigate by
// running in a temp dir COPY (so the user's Pods/ is untouched).
// Full safety would require sandboxing the pod subprocess; out of
// scope for v1, document the gap.
//
// podPath is the absolute path to the real `pod` binary; cwd is
// the user's project directory containing Podfile.
func ResolveCocoaPodsTree(ctx context.Context, podPath, cwd string) ([]PackageRef, error) {
	if cwd == "" {
		return nil, errors.New("cocoapods resolver requires the user's project cwd")
	}
	pod := podPath
	if pod == "" {
		pod = "pod"
	}
	podfile, err := os.ReadFile(filepath.Join(cwd, "Podfile"))
	if err != nil {
		return nil, fmt.Errorf("read Podfile in %s: %w", cwd, err)
	}
	tmp, err := os.MkdirTemp("", "chdora-gate-pod-*")
	if err != nil {
		return nil, fmt.Errorf("create resolve temp: %w", err)
	}
	defer os.RemoveAll(tmp)

	if err := os.WriteFile(filepath.Join(tmp, "Podfile"), podfile, 0o644); err != nil {
		return nil, fmt.Errorf("seed Podfile: %w", err)
	}
	if lockBytes, err := os.ReadFile(filepath.Join(cwd, "Podfile.lock")); err == nil {
		if err := os.WriteFile(filepath.Join(tmp, "Podfile.lock"), lockBytes, 0o644); err != nil {
			return nil, fmt.Errorf("seed Podfile.lock: %w", err)
		}
	}
	// pod install requires the .xcodeproj or .xcworkspace referenced
	// by the Podfile. The resolver doesn't need integration — just
	// the resolved Podfile.lock. Use `pod install --no-integrate`
	// which still resolves but skips Xcode project mutation.
	cmd := exec.CommandContext(ctx, pod, "install", "--no-repo-update", "--no-integrate")
	cmd.Dir = tmp
	cmd.Env = append(os.Environ(), "CP_HOME_DIR="+filepath.Join(tmp, "cp-home"))
	out, err := cmd.CombinedOutput()
	if err != nil {
		return nil, wrapPMError("pod", "install --no-integrate", out, err)
	}
	data, err := os.ReadFile(filepath.Join(tmp, "Podfile.lock"))
	if err != nil {
		return nil, fmt.Errorf("read Podfile.lock: %w", err)
	}
	return parsePodfileLockTree(data), nil
}

// parsePodfileLockTree extracts (name, version) tuples from a
// Podfile.lock and uses SPEC CHECKSUMS entries for integrity.
//
// Podfile.lock format (YAML):
//
//	PODS:
//	  - Alamofire (5.6.4)
//	  - Kingfisher (7.6.0):
//	    - Kingfisher/Core (= 7.6.0)
//	SPEC CHECKSUMS:
//	  Alamofire: 4e95d97098eacb88856099c4fc79b526a299e48c
//	  Kingfisher: ...
func parsePodfileLockTree(data []byte) []PackageRef {
	lines := strings.Split(string(data), "\n")
	type pod struct{ name, version string }
	var pods []pod
	checksums := map[string]string{}
	state := ""
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		// Section headers are at column 0.
		if len(line) > 0 && line[0] != ' ' && line[0] != '-' {
			switch {
			case strings.HasPrefix(trimmed, "PODS:"):
				state = "pods"
			case strings.HasPrefix(trimmed, "SPEC CHECKSUMS:"):
				state = "checksums"
			default:
				state = ""
			}
			continue
		}
		switch state {
		case "pods":
			// "- Name (1.2.3)" or "- Name (1.2.3):"
			if !strings.HasPrefix(trimmed, "- ") {
				continue
			}
			entry := strings.TrimPrefix(trimmed, "- ")
			entry = strings.TrimSuffix(entry, ":")
			open := strings.LastIndex(entry, " (")
			closeIdx := strings.LastIndex(entry, ")")
			if open < 0 || closeIdx <= open {
				continue
			}
			name := strings.TrimSpace(entry[:open])
			version := strings.TrimSpace(entry[open+2 : closeIdx])
			// Sub-pod refs use "Parent/Sub" naming; skip — we want
			// the parent pod's checksum.
			if strings.Contains(name, "/") {
				continue
			}
			pods = append(pods, pod{name, version})
		case "checksums":
			if i := strings.Index(trimmed, ":"); i > 0 {
				name := strings.TrimSpace(trimmed[:i])
				sum := strings.Trim(strings.TrimSpace(trimmed[i+1:]), `"`)
				checksums[name] = sum
			}
		}
	}
	seen := map[string]struct{}{}
	var refs []PackageRef
	for _, p := range pods {
		key := p.name + "@" + p.version
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		integrity := ""
		if h := checksums[p.name]; h != "" {
			integrity = "sha1:" + h
		}
		refs = append(refs, PackageRef{
			Ecosystem: "cocoapods",
			Name:      p.name,
			Version:   p.version,
			Integrity: integrity,
		})
	}
	return refs
}
