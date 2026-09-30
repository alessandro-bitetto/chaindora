package registries

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPyPISelectsLockedWheelInsteadOfDifferentSource(t *testing.T) {
	wheel, source := strings.Repeat("a", 64), strings.Repeat("b", 64)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, `{"releases":{"1.0":[{"packagetype":"sdist","url":"https://files.pythonhosted.org/source.tgz","digests":{"sha256":"%s"}},{"packagetype":"bdist_wheel","url":"https://files.pythonhosted.org/wheel.whl","digests":{"sha256":"%s"}}]}}`, source, wheel)
	}))
	defer srv.Close()
	p := NewPyPI()
	p.BaseURL = srv.URL
	for _, prefix := range []string{"sha256:", "sha256="} {
		got, err := p.ArtifactURL(context.Background(), "fixture", "1.0", prefix+wheel)
		if err != nil || got != "https://files.pythonhosted.org/wheel.whl" {
			t.Fatalf("wrong selected artifact: %s %v", got, err)
		}
	}
	if _, err := p.ArtifactURL(context.Background(), "fixture", "1.0", "sha256:"+strings.Repeat("c", 64)); err == nil {
		t.Fatal("missing locked artifact silently substituted")
	}
}
