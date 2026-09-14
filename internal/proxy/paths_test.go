package proxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestExplicitUpstreamPathMapping(t *testing.T) {
	seen := make(chan string, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { seen <- r.URL.RequestURI(); w.Write([]byte(`{}`)) }))
	defer upstream.Close()
	p, err := New(upstream.URL+"/router", policyProxyRedactor(t), nil, Options{UpstreamPaths: map[string]string{"/codex/responses": "/responses"}})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ path, want string }{{"/codex/responses?x=1", "/router/responses?x=1"}, {"/responses", "/router/responses"}, {"/other", "/router/other"}} {
		p.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("POST", tc.path, strings.NewReader(`{}`)))
		if got := <-seen; got != tc.want {
			t.Fatalf("got %s want %s", got, tc.want)
		}
	}
}
