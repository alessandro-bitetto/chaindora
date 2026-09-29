package hostforensics

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/alessandro-bitetto/chaindora/internal/findings"
)

// SSHBaselinePath returns the canonical baseline location under the user's
// `.chaindora` config dir.
func SSHBaselinePath(home string) string {
	return filepath.Join(home, ".chaindora", "ssh-baseline.txt")
}

// ScanSSHAuthorizedKeys reads ~/.ssh/authorized_keys, hashes each non-comment
// line, and compares against the persisted baseline at baselinePath.
//
//   - First run (no baseline): writes the current state as baseline and
//     emits one MEDIUM informational finding noting how many keys were captured.
//   - Subsequent runs: HIGH for any key added since baseline, MEDIUM for any
//     key removed (could be intentional cleanup or evidence of tampering).
//
// Returns nil if ~/.ssh/authorized_keys doesn't exist.
func ScanSSHAuthorizedKeys(home, baselinePath string) []findings.Finding {
	keysPath := filepath.Join(home, ".ssh", "authorized_keys")
	data, err := os.ReadFile(keysPath)
	if err != nil {
		return nil
	}
	current := keyFingerprints(data)
	if len(current) == 0 {
		return nil
	}

	if baselinePath == "" {
		baselinePath = SSHBaselinePath(home)
	}

	baseline, baselineErr := readSSHBaseline(baselinePath)
	if baselineErr != nil {
		_ = writeSSHBaseline(baselinePath, current)
		return []findings.Finding{{
			Detector: "hostforensics:ssh",
			VulnID:   "HOST-SSH-BASELINE-CREATED",
			Summary: fmt.Sprintf(
				"Baseline of %d authorized SSH key(s) captured at %s. Future --ssh-check runs will flag added or removed keys.",
				len(current), baselinePath,
			),
			Severity:   findings.SeverityMedium,
			SourcePath: keysPath,
		}}
	}

	baselineSet := map[string]struct{}{}
	for _, h := range baseline {
		baselineSet[h] = struct{}{}
	}
	currentSet := map[string]struct{}{}
	for _, h := range current {
		currentSet[h] = struct{}{}
	}

	var out []findings.Finding
	for _, h := range current {
		if _, ok := baselineSet[h]; ok {
			continue
		}
		out = append(out, findings.Finding{
			Detector: "hostforensics:ssh",
			VulnID:   "HOST-SSH-KEY-ADDED",
			Summary: fmt.Sprintf(
				"A new SSH public key (sha256:%s...) appeared in ~/.ssh/authorized_keys since the baseline. Verify you authorized this key — if not, remove it and audit your account.",
				shortHash(h),
			),
			Severity:   findings.SeverityHigh,
			SourcePath: keysPath,
		})
	}
	for _, h := range baseline {
		if _, ok := currentSet[h]; ok {
			continue
		}
		out = append(out, findings.Finding{
			Detector: "hostforensics:ssh",
			VulnID:   "HOST-SSH-KEY-REMOVED",
			Summary: fmt.Sprintf(
				"A baseline SSH public key (sha256:%s...) is no longer in ~/.ssh/authorized_keys. Confirm the removal was intentional.",
				shortHash(h),
			),
			Severity:   findings.SeverityMedium,
			SourcePath: keysPath,
		})
	}
	return out
}

func keyFingerprints(data []byte) []string {
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		h := sha256.Sum256([]byte(line))
		out = append(out, hex.EncodeToString(h[:]))
	}
	return out
}

func readSSHBaseline(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var hashes []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		hashes = append(hashes, line)
	}
	return hashes, nil
}

func writeSSHBaseline(path string, hashes []string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	body := "# chaindora SSH authorized_keys baseline\n# sha256 fingerprints, one per line\n" + strings.Join(hashes, "\n") + "\n"
	return os.WriteFile(path, []byte(body), 0o600)
}

func shortHash(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}
