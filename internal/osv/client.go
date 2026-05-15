package osv

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

const (
	queryBatchURL = "https://api.osv.dev/v1/querybatch"
	vulnURL       = "https://api.osv.dev/v1/vulns/"
	batchSize     = 1000
)

type Query struct {
	Package QueryPackage `json:"package"`
	Version string       `json:"version,omitempty"`
}

type QueryPackage struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

type batchRequest struct {
	Queries []Query `json:"queries"`
}

type batchResponse struct {
	Results []QueryResult `json:"results"`
}

type QueryResult struct {
	Vulns []VulnRef `json:"vulns"`
}

type VulnRef struct {
	ID       string `json:"id"`
	Modified string `json:"modified"`
}

// Vulnerability is the response shape for GET /v1/vulns/{id}.
type Vulnerability struct {
	ID         string      `json:"id"`
	Summary    string      `json:"summary"`
	Details    string      `json:"details"`
	Aliases    []string    `json:"aliases"`
	Severity   []Severity  `json:"severity"`
	References []Reference `json:"references"`
}

type Severity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type Reference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

type Client struct {
	HTTP *http.Client
}

func NewClient() *Client {
	return &Client{HTTP: &http.Client{Timeout: 30 * time.Second}}
}

// QueryBatch sends queries to /v1/querybatch in chunks of up to 1000 and
// concatenates the per-chunk Results slices in input order.
func (c *Client) QueryBatch(ctx context.Context, queries []Query) ([]QueryResult, error) {
	results := make([]QueryResult, 0, len(queries))
	for i := 0; i < len(queries); i += batchSize {
		end := i + batchSize
		if end > len(queries) {
			end = len(queries)
		}
		body, err := json.Marshal(batchRequest{Queries: queries[i:end]})
		if err != nil {
			return nil, err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, queryBatchURL, bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := c.HTTP.Do(req)
		if err != nil {
			return nil, err
		}
		raw, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return nil, err
		}
		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("osv: status %d: %s", resp.StatusCode, string(raw))
		}
		var br batchResponse
		if err := json.Unmarshal(raw, &br); err != nil {
			return nil, fmt.Errorf("osv: decode: %w", err)
		}
		results = append(results, br.Results...)
	}
	return results, nil
}

// GetVuln fetches the full record for a vulnerability ID.
func (c *Client) GetVuln(ctx context.Context, id string) (*Vulnerability, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, vulnURL+id, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("osv: vuln %s status %d: %s", id, resp.StatusCode, string(body))
	}
	var v Vulnerability
	if err := json.NewDecoder(resp.Body).Decode(&v); err != nil {
		return nil, err
	}
	return &v, nil
}
