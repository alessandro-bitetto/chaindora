package registries

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"
)

// MavenCentral probes Maven Central's Solr-backed search API at
// search.maven.org/solrsearch/select. The format is:
//
//	?q=g:<group>+AND+a:<artifact>+AND+v:<version>&core=gav
//	?q=g:<group>+AND+a:<artifact>&core=gav&rows=200
//
// "gav" returns one row per (group, artifact, version). The
// `timestamp` field is a unix-millis timestamp of the deployment
// to Central. There's no per-version publisher equivalent in
// the API — the closest is the GPG key on the published artifact,
// which would require downloading the JAR + signature to inspect.
// For chaindora's gate purposes we keep PublisherOfVersion
// returning "" so the publisher-change check degrades to Unknown.
type MavenCentral struct {
	Client    *http.Client
	SearchURL string // default: https://search.maven.org/solrsearch/select
	Repo1URL  string // default: https://repo1.maven.org/maven2
	UserAgent string
}

func NewMavenCentral() *MavenCentral {
	return &MavenCentral{
		Client:    &http.Client{Timeout: 10 * time.Second},
		SearchURL: "https://search.maven.org/solrsearch/select",
		Repo1URL:  "https://repo1.maven.org/maven2",
		UserAgent: "chdora-registry/",
	}
}

type mavenSolrResponse struct {
	Response struct {
		NumFound int             `json:"numFound"`
		Docs     []mavenSolrDoc  `json:"docs"`
	} `json:"response"`
}

type mavenSolrDoc struct {
	ID        string `json:"id"`
	GroupID   string `json:"g"`
	Artifact  string `json:"a"`
	Version   string `json:"v"`
	Timestamp int64  `json:"timestamp"` // unix millis
}

// splitMavenName splits chaindora's "groupId:artifactId" stored
// name back into its parts.
func splitMavenName(name string) (group, artifact string, ok bool) {
	i := strings.LastIndex(name, ":")
	if i < 0 {
		return "", "", false
	}
	return name[:i], name[i+1:], true
}

func (m *MavenCentral) querySolr(ctx context.Context, query string) (*mavenSolrResponse, error) {
	u := fmt.Sprintf("%s?q=%s&core=gav&rows=200&wt=json", m.SearchURL, url.QueryEscape(query))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	if m.UserAgent != "" {
		req.Header.Set("User-Agent", m.UserAgent)
	}
	resp, err := m.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("maven solr: HTTP %d", resp.StatusCode)
	}
	var doc mavenSolrResponse
	if err := json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&doc); err != nil {
		return nil, err
	}
	return &doc, nil
}

func (m *MavenCentral) PublishedAtVersion(ctx context.Context, name, version string) (time.Time, error) {
	group, artifact, ok := splitMavenName(name)
	if !ok {
		return time.Time{}, fmt.Errorf("maven name %q must be groupId:artifactId", name)
	}
	q := fmt.Sprintf("g:%s AND a:%s AND v:%s", group, artifact, version)
	doc, err := m.querySolr(ctx, q)
	if err != nil {
		return time.Time{}, err
	}
	if doc.Response.NumFound == 0 || len(doc.Response.Docs) == 0 {
		return time.Time{}, nil
	}
	ts := doc.Response.Docs[0].Timestamp
	return time.UnixMilli(ts).UTC(), nil
}

// PublisherOfVersion: Maven Central's public search API doesn't
// surface a per-version publisher identity. Sonatype's portal
// has the deploying user but it's not in the public API. Return
// empty + nil → checker degrades to Unknown.
func (m *MavenCentral) PublisherOfVersion(context.Context, string, string) (string, error) {
	return "", nil
}

func (m *MavenCentral) AllVersions(ctx context.Context, name string) ([]VersionInfo, error) {
	group, artifact, ok := splitMavenName(name)
	if !ok {
		return nil, fmt.Errorf("maven name %q must be groupId:artifactId", name)
	}
	q := fmt.Sprintf("g:%s AND a:%s", group, artifact)
	doc, err := m.querySolr(ctx, q)
	if err != nil {
		return nil, err
	}
	out := make([]VersionInfo, 0, len(doc.Response.Docs))
	for _, d := range doc.Response.Docs {
		t := time.UnixMilli(d.Timestamp).UTC()
		out = append(out, VersionInfo{
			Name:        name,
			Version:     d.Version,
			PublishedAt: t,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].PublishedAt.Before(out[j].PublishedAt)
	})
	return out, nil
}

// TarballURL builds the JAR URL under repo1.maven.org. JARs are
// zip archives; the existing scanTarball handles gzipped tar but
// not zip — until v0.11.x adds zip-walker support, the static-
// pattern check returns Unknown for Maven artifacts (scanner
// fails gunzip, returns error). That's acceptable for v0.11.0:
// cooldown + OSV cover Maven; static-pattern lands as a follow-up.
func (m *MavenCentral) TarballURL(_ context.Context, name, version string) (string, error) {
	group, artifact, ok := splitMavenName(name)
	if !ok {
		return "", fmt.Errorf("maven name %q must be groupId:artifactId", name)
	}
	groupPath := strings.ReplaceAll(group, ".", "/")
	return fmt.Sprintf("%s/%s/%s/%s/%s-%s.jar",
		strings.TrimRight(m.Repo1URL, "/"),
		groupPath, artifact, version,
		artifact, version,
	), nil
}

func (m *MavenCentral) FetchTarball(ctx context.Context, fetchURL string, dst io.Writer) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fetchURL, nil)
	if err != nil {
		return err
	}
	if m.UserAgent != "" {
		req.Header.Set("User-Agent", m.UserAgent)
	}
	resp, err := m.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("jar %s: HTTP %d", fetchURL, resp.StatusCode)
	}
	_, err = io.Copy(dst, io.LimitReader(resp.Body, 50<<20))
	return err
}
