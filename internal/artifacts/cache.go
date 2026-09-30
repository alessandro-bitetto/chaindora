package artifacts

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

func DefaultCacheRoot() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".chaindora", "artifacts")
}

// NPMURL restricts lockfile-directed fetches to the public registry. A project
// file cannot turn scanning into requests to local services or send credentials.
func NPMURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host != "registry.npmjs.org" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("unsupported npm artifact URL: only https://registry.npmjs.org archives are supported")
	}
	return nil
}

func CachePath(root, integrity string) string {
	sum := sha256.Sum256([]byte(integrity))
	return filepath.Join(root, hex.EncodeToString(sum[:])+".tgz")
}

// LoadNPM revalidates cached bytes against the caller's lockfile on every read.
// Offline never makes a request; missing evidence is an explicit error.
func LoadNPM(ctx context.Context, client *http.Client, root, url, integrity string, offline bool) ([]byte, error) {
	if err := NPMURL(url); err != nil {
		return nil, err
	}
	if integrity == "" {
		return nil, fmt.Errorf("missing artifact integrity")
	}
	if root != "" {
		file := CachePath(root, integrity)
		if info, err := os.Lstat(file); err == nil && info.Mode().IsRegular() && info.Size() <= MaxArchiveBytes {
			if data, err := os.ReadFile(file); err == nil && VerifyIntegrity(data, integrity) == nil {
				return data, nil
			}
		}
	}
	if offline {
		return nil, fmt.Errorf("verified artifact unavailable offline")
	}
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	copyClient := *client
	copyClient.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return fmt.Errorf("too many artifact redirects")
		}
		return NPMURL(req.URL.String())
	}
	data, err := Download(ctx, &copyClient, url)
	if err != nil {
		return nil, err
	}
	if err := VerifyIntegrity(data, integrity); err != nil {
		return nil, err
	}
	if root != "" {
		if err := os.MkdirAll(root, 0o700); err != nil {
			return nil, err
		}
		f, err := os.CreateTemp(root, ".artifact-*")
		if err != nil {
			return nil, err
		}
		name := f.Name()
		defer func() { _ = os.Remove(name) }()
		_, err = f.Write(data)
		closeErr := f.Close()
		if err != nil {
			return nil, err
		}
		if closeErr != nil {
			return nil, closeErr
		}
		if err := os.Rename(name, CachePath(root, integrity)); err != nil {
			return nil, err
		}
	}
	return data, nil
}
