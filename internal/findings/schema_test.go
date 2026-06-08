package findings

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"testing"
)

// TestFindingSchemaInSync is the CI guard for the public Finding JSON
// shape. The Finding struct is the wire contract surfaced via
// --format=json, --format=jsonl, the agent push payload, and the
// server-side store. Renaming or removing a field is a breaking change
// for every downstream consumer (SARIF parser, dashboard, ingest
// pipeline). This test fails loudly if the Go struct's JSON field set
// drifts from docs/schema/v1/finding.schema.json's properties.
//
// To intentionally evolve the schema:
//  1. If adding an optional field: add it to both the Go struct and
//     the schema's properties; do NOT add it to "required".
//  2. If renaming or removing a field: bump to docs/schema/v2/ and
//     update this test's schemaPath. Don't silently change v1.
func TestFindingSchemaInSync(t *testing.T) {
	schemaPath := findRepoRoot(t) + "/docs/schema/v1/finding.schema.json"
	raw, err := os.ReadFile(schemaPath)
	if err != nil {
		t.Fatalf("read schema: %v", err)
	}
	var doc struct {
		Properties map[string]json.RawMessage `json:"properties"`
		Required   []string                   `json:"required"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("parse schema: %v", err)
	}

	schemaFields := sortedKeys(doc.Properties)
	structFields := jsonFieldsOf(reflect.TypeOf(Finding{}))
	sort.Strings(structFields)

	if !equalStringSlice(schemaFields, structFields) {
		t.Errorf("Finding JSON field set drifted from schema\nschema:  %v\nstruct:  %v\n\nIf this is an intentional change:\n  - additive field: add it to docs/schema/v1/finding.schema.json properties\n  - rename/remove: bump to docs/schema/v2/ and update this test", schemaFields, structFields)
	}

	// Spot-check: required fields must exist on the struct. (We don't
	// flip the assertion the other way — the struct can have optional
	// fields the schema lists in properties but not in required.)
	for _, name := range doc.Required {
		found := false
		for _, sf := range structFields {
			if sf == name {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("schema requires field %q but Finding struct has no JSON tag for it", name)
		}
	}
}

// jsonFieldsOf returns the names emitted in JSON for every exported
// field of t. Honors `json:"name,omitempty"` and `json:"-"`.
func jsonFieldsOf(t reflect.Type) []string {
	var out []string
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		tag := f.Tag.Get("json")
		if tag == "-" {
			continue
		}
		name := f.Name
		if tag != "" {
			if comma := indexByte(tag, ','); comma >= 0 {
				tag = tag[:comma]
			}
			if tag != "" {
				name = tag
			}
		}
		out = append(out, name)
	}
	return out
}

func indexByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}

func sortedKeys(m map[string]json.RawMessage) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func equalStringSlice(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// findRepoRoot walks up from this test's source file until it finds a
// go.mod, returning that directory. Avoids hardcoding the relative
// path from internal/findings/.
func findRepoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	dir := filepath.Dir(file)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.mod found walking up from " + file)
		}
		dir = parent
	}
}
