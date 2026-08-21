// Package proxy implements the local HTTP proxy: it redacts sensitive data
// from outgoing requests, forwards them to the configured upstream, and
// restores placeholders in the response before returning it to the caller.
package proxy

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"llmguard/internal/redact"
)

const (
	defaultConnectTimeout        = 10 * time.Second
	defaultResponseHeaderTimeout = 120 * time.Second
)

// Options configures upstream HTTP client timeouts. Zero values use defaults.
type Options struct {
	ConnectTimeout        time.Duration
	ResponseHeaderTimeout time.Duration
	SessionHeader         string
	MediaImages           string
}

func (o Options) withDefaults() Options {
	if o.ConnectTimeout <= 0 {
		o.ConnectTimeout = defaultConnectTimeout
	}
	if o.ResponseHeaderTimeout <= 0 {
		o.ResponseHeaderTimeout = defaultResponseHeaderTimeout
	}
	return o
}

// Proxy forwards requests to a single upstream base URL, redacting request
// bodies and restoring response bodies along the way.
type Proxy struct {
	upstream    *url.URL
	client      *http.Client
	redactor    *redact.Redactor
	logger      *log.Logger
	options     Options
	nextSession atomic.Uint64
}

// New creates a Proxy that forwards to upstream (must include scheme and
// host, e.g. "https://api.anthropic.com"). logger may be nil to disable
// redaction logging. opts configures upstream timeouts; zero values use
// defaults.
func New(upstream string, redactor *redact.Redactor, logger *log.Logger, opts Options) (*Proxy, error) {
	u, err := url.Parse(upstream)
	if err != nil {
		return nil, fmt.Errorf("parsing upstream URL %q: %w", upstream, err)
	}
	if u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("upstream URL %q must include a scheme and host", upstream)
	}

	opts = opts.withDefaults()
	transport := &http.Transport{
		DialContext:           (&net.Dialer{Timeout: opts.ConnectTimeout}).DialContext,
		TLSHandshakeTimeout:   opts.ConnectTimeout,
		ResponseHeaderTimeout: opts.ResponseHeaderTimeout,
	}

	return &Proxy{
		upstream: u,
		client:   &http.Client{Transport: transport},
		redactor: redactor,
		logger:   logger,
		options:  opts,
	}, nil
}

// ServeHTTP implements http.Handler.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "failed to read request body", http.StatusBadGateway)
		return
	}
	r.Body.Close()

	session := ""
	ephemeralSession := true
	if p.options.SessionHeader != "" {
		session = r.Header.Get(p.options.SessionHeader)
		ephemeralSession = session == ""
	}
	if len(session) > 128 {
		http.Error(w, "request rejected: invalid local session identifier", http.StatusBadRequest)
		return
	}
	if ephemeralSession {
		session = fmt.Sprintf("request-%d", p.nextSession.Add(1))
		defer p.redactor.EndSession(session)
	}
	// Do not inject protocol-specific guard notes. Generic recursive rewriting
	// must preserve the upstream request schema (Responses, Chat, Anthropic, or
	// another OpenAI-compatible router dialect).
	result, err := p.redactor.Transform(body, session, false, p.options.MediaImages)
	if err != nil {
		// Transform errors are deliberately generic and never contain matched
		// values, request bodies, or mapping contents.
		p.logf("status=%d error=%v content_encoding=%s path=%s", http.StatusUnprocessableEntity, err, safeContentEncoding(r.Header.Get("Content-Encoding")), r.URL.Path)
		http.Error(w, "request rejected: body could not be safely inspected", http.StatusUnprocessableEntity)
		return
	}
	if result.Blocked {
		p.logRequest(r.URL.Path, http.StatusForbidden, result.Transformed, result.Categories)
		http.Error(w, "request blocked by local privacy policy", http.StatusForbidden)
		return
	}
	redactedBody, categories := result.Body, result.Categories

	target := *p.upstream
	target.Path = singleJoiningSlash(p.upstream.Path, r.URL.Path)
	target.RawQuery = r.URL.RawQuery

	outReq, err := http.NewRequestWithContext(r.Context(), r.Method, target.String(), bytes.NewReader(redactedBody))
	if err != nil {
		http.Error(w, "failed to build upstream request", http.StatusBadGateway)
		return
	}
	outReq.Header = r.Header.Clone()
	outReq.Header.Del("Connection")
	if p.options.SessionHeader != "" {
		outReq.Header.Del(p.options.SessionHeader)
	}
	// Let net/http negotiate and transparently decompress the response
	// itself. If we forward the client's Accept-Encoding verbatim, Go's
	// transport assumes *we* will handle decoding and leaves the body
	// gzip-compressed, which breaks placeholder restoration (it operates on
	// the raw bytes) for any compressed response.
	outReq.Header.Del("Accept-Encoding")
	outReq.Host = p.upstream.Host
	outReq.ContentLength = int64(len(redactedBody))
	outReq.Header.Set("Content-Length", strconv.Itoa(len(redactedBody)))

	resp, err := p.client.Do(outReq)
	if err != nil {
		http.Error(w, "upstream request failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	for k, vv := range resp.Header {
		if k == "Content-Length" || k == "Transfer-Encoding" {
			continue
		}
		for _, v := range vv {
			w.Header().Add(k, v)
		}
	}
	// Restoration can change the body length, so let the server choose the
	// transfer encoding rather than trusting upstream's Content-Length.
	w.Header().Del("Content-Length")
	w.WriteHeader(resp.StatusCode)

	ct := resp.Header.Get("Content-Type")
	if strings.Contains(ct, "text/event-stream") || resp.Header.Get("Transfer-Encoding") == "chunked" {
		var rw interface {
			io.Writer
			Close() error
		}
		if strings.Contains(ct, "text/event-stream") {
			rw = NewSSERestoringWriterForSession(w, p.redactor, session)
		} else {
			rw = NewRestoringWriterForSession(w, p.redactor, session)
		}
		if _, err := io.Copy(rw, resp.Body); err != nil {
			p.logf("streaming upstream response: %v", err)
		}
		if err := rw.Close(); err != nil {
			p.logf("closing streaming response: %v", err)
		}
	} else {
		respBody, err := io.ReadAll(resp.Body)
		if err != nil {
			p.logf("reading upstream response body: %v", err)
			p.logRequest(r.URL.Path, resp.StatusCode, result.Transformed, categories)
			return
		}
		if _, err := w.Write(p.redactor.RestoreResponseForSession(respBody, ct, session)); err != nil {
			p.logf("writing response body: %v", err)
		}
		// Error response bodies are generic API error messages (no user
		// secrets), so logging them helps diagnose upstream rejections.
		if resp.StatusCode >= 400 {
			p.logErrorResponse(resp.StatusCode, resp.Header)
		}
	}

	p.logRequest(r.URL.Path, resp.StatusCode, result.Transformed, categories)
}

func safeContentEncoding(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "identity":
		return "identity"
	case "gzip":
		return "gzip"
	case "zstd":
		return "zstd"
	case "br":
		return "br"
	default:
		return "other"
	}
}

func (p *Proxy) logf(format string, args ...any) {
	if p.logger != nil {
		p.logger.Printf(format, args...)
	}
}

func (p *Proxy) logErrorResponse(status int, header http.Header) {
	if p.logger == nil {
		return
	}
	var rl []string
	for k, vv := range header {
		lk := strings.ToLower(k)
		if strings.HasPrefix(lk, "anthropic-ratelimit") || lk == "retry-after" || lk == "request-id" {
			rl = append(rl, k+"="+strings.Join(vv, ","))
		}
	}
	sort.Strings(rl)
	p.logger.Printf("upstream error status=%d %s", status, strings.Join(rl, " "))
}

func (p *Proxy) logRequest(path string, status, transformed int, categories []string) {
	if p.logger == nil {
		return
	}
	if len(categories) == 0 {
		p.logger.Printf("status=%d transformed=%d path=%s", status, transformed, path)
		return
	}
	p.logger.Printf("status=%d transformed=%d categories=%s path=%s", status, transformed, strings.Join(uniqueSorted(categories), ","), path)
}

func singleJoiningSlash(a, b string) string {
	aslash := strings.HasSuffix(a, "/")
	bslash := strings.HasPrefix(b, "/")
	switch {
	case aslash && bslash:
		return a + b[1:]
	case !aslash && !bslash:
		return a + "/" + b
	}
	return a + b
}

func uniqueSorted(items []string) []string {
	seen := make(map[string]bool, len(items))
	out := make([]string, 0, len(items))
	for _, it := range items {
		if !seen[it] {
			seen[it] = true
			out = append(out, it)
		}
	}
	sort.Strings(out)
	return out
}
