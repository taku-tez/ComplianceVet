package report

import (
	"encoding/json"
	"io"
)

// WriteJSON writes the report as JSON to w.
func WriteJSON(w io.Writer, rep Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(rep)
}
