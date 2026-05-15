package findings

import (
	"encoding/json"
	"io"
)

// EmitJSONL writes one Finding per line as compact JSON. Useful for piping
// into log aggregators (Loki, Splunk, Datadog) or jq-based filtering.
func EmitJSONL(w io.Writer, fs []Finding) error {
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	for i := range fs {
		if err := enc.Encode(fs[i]); err != nil {
			return err
		}
	}
	return nil
}
