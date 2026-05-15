package osv

import (
	"math"
	"strings"
)

// parseCVSSv3 computes the CVSS v3.x base score from a vector like
//   "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
// Returns (score, true) on success or (0, false) if any required metric is
// missing or malformed.
func parseCVSSv3(vector string) (float64, bool) {
	if !strings.HasPrefix(vector, "CVSS:3.") {
		return 0, false
	}
	metrics := map[string]string{}
	for _, part := range strings.Split(vector, "/") {
		kv := strings.SplitN(part, ":", 2)
		if len(kv) == 2 {
			metrics[kv[0]] = kv[1]
		}
	}

	scopeRaw, ok := metrics["S"]
	if !ok {
		return 0, false
	}
	scopeChanged := scopeRaw == "C"

	av, ok1 := avValue(metrics["AV"])
	ac, ok2 := acValue(metrics["AC"])
	pr, ok3 := prValue(metrics["PR"], scopeChanged)
	ui, ok4 := uiValue(metrics["UI"])
	c, ok5 := ciaValue(metrics["C"])
	i, ok6 := ciaValue(metrics["I"])
	a, ok7 := ciaValue(metrics["A"])
	if !(ok1 && ok2 && ok3 && ok4 && ok5 && ok6 && ok7) {
		return 0, false
	}

	iscBase := 1 - (1-c)*(1-i)*(1-a)
	var impact float64
	if scopeChanged {
		impact = 7.52*(iscBase-0.029) - 3.25*math.Pow(iscBase-0.02, 15)
	} else {
		impact = 6.42 * iscBase
	}
	exploitability := 8.22 * av * ac * pr * ui
	if impact <= 0 {
		return 0, true
	}
	var score float64
	if scopeChanged {
		score = math.Min(1.08*(impact+exploitability), 10)
	} else {
		score = math.Min(impact+exploitability, 10)
	}
	return roundUpCVSS(score), true
}

// roundUpCVSS returns the smallest multiple of 0.1 not less than x, per the
// CVSS v3.1 specification's "round up" function.
func roundUpCVSS(x float64) float64 {
	return math.Ceil(x*10) / 10
}

func avValue(s string) (float64, bool) {
	switch s {
	case "N":
		return 0.85, true
	case "A":
		return 0.62, true
	case "L":
		return 0.55, true
	case "P":
		return 0.2, true
	}
	return 0, false
}

func acValue(s string) (float64, bool) {
	switch s {
	case "L":
		return 0.77, true
	case "H":
		return 0.44, true
	}
	return 0, false
}

func prValue(s string, scopeChanged bool) (float64, bool) {
	switch s {
	case "N":
		return 0.85, true
	case "L":
		if scopeChanged {
			return 0.68, true
		}
		return 0.62, true
	case "H":
		if scopeChanged {
			return 0.50, true
		}
		return 0.27, true
	}
	return 0, false
}

func uiValue(s string) (float64, bool) {
	switch s {
	case "N":
		return 0.85, true
	case "R":
		return 0.62, true
	}
	return 0, false
}

func ciaValue(s string) (float64, bool) {
	switch s {
	case "H":
		return 0.56, true
	case "L":
		return 0.22, true
	case "N":
		return 0, true
	}
	return 0, false
}

// SeverityLevel returns a qualitative rating per the CVSS v3.x spec:
//   9.0–10.0 CRITICAL
//   7.0–8.9  HIGH
//   4.0–6.9  MEDIUM
//   0.1–3.9  LOW
//   0.0      NONE
func SeverityLevel(score float64) string {
	switch {
	case score >= 9.0:
		return "CRITICAL"
	case score >= 7.0:
		return "HIGH"
	case score >= 4.0:
		return "MEDIUM"
	case score > 0:
		return "LOW"
	}
	return "NONE"
}

// HighestSeverityFromVulns iterates an OSV severity[] array and returns the
// strongest qualitative rating found. Returns "" if no parseable vector is
// present.
func HighestSeverityFromVulns(sevs []Severity) string {
	best := 0.0
	any := false
	for _, s := range sevs {
		if s.Score == "" {
			continue
		}
		score, ok := parseCVSSv3(s.Score)
		if !ok {
			continue
		}
		if score > best {
			best = score
		}
		any = true
	}
	if !any {
		return ""
	}
	return SeverityLevel(best)
}
