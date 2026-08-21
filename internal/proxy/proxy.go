// Package proxy implements the local HTTP proxy: it redacts sensitive data
// from outgoing requests, forwards them to the configured upstream, and
// restores placeholders in the response before returning it to the caller.
package proxy

import (
	"bytes"
	"errors"
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

	"github.com/DavidCarliez/cover/internal/redact"
)

const (
	defaultConnectTimeout        = 10 * time.Second
	defaultResponseHeaderTimeout = 120 * time.Second
	defaultMaxRequestBytes       = int64(16 << 20)
	defaultMaxResponseBytes      = int64(32 << 20)
	defaultMaxSSEEventBytes      = int64(4 << 20)
)

var errBodyTooLarge = errors.New("body exceeds configured limit")

// Options configures upstream HTTP client timeouts. Zero values use defaults.
type Options struct {
	ConnectTimeout        time.Duration
	ResponseHeaderTimeout time.Duration
	SessionHeader         string
	MediaImages           string
	MaxRequestBytes       int64
	MaxResponseBytes      int64
	MaxSSEEventBytes      int64
}

func (o Options) withDefaults() Options {
	if o.ConnectTimeout <= 0 {
		o.ConnectTimeout = defaultConnectTimeout
	}
	if o.ResponseHeaderTimeout <= 0 {
		o.ResponseHeaderTimeout = defaultResponseHeaderTimeout
	}
	if o.MaxRequestBytes <= 0 {
		o.MaxRequestBytes = defaultMaxRequestBytes
	}
	if o.MaxResponseBytes <= 0 {
		o.MaxResponseBytes = defaultMaxResponseBytes
	}
	if o.MaxSSEEventBytes <= 0 {
		o.MaxSSEEventBytes = defaultMaxSSEEventBytes
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
		return nil, fmt.Errorf("parsing upstream URL: invalid URL")
	}
	if u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("upstream URL must include a scheme and host")
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
	started := time.Now()
	defer r.Body.Close()
	body, err := readAtMost(r.Body, p.options.MaxRequestBytes)
	if err != nil {
		if errors.Is(err, errBodyTooLarge) {
			p.logf("status=%d error=request_too_large", http.StatusRequestEntityTooLarge)
			http.Error(w, "request rejected: body exceeds configured limit", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "failed to read request body", http.StatusBadGateway)
		return
	}
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
		p.logf("status=%d error=%v content_encoding=%s", http.StatusUnprocessableEntity, err, safeContentEncoding(r.Header.Get("Content-Encoding")))
		http.Error(w, "request rejected: body could not be safely inspected", http.StatusUnprocessableEntity)
		return
	}
	if result.Blocked {
		p.logRequest(http.StatusForbidden, result.Transformed, result.Categories, 0, 0, time.Since(started))
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

	ct := resp.Header.Get("Content-Type")
	streaming := strings.Contains(ct, "text/event-stream") || resp.Header.Get("Transfer-Encoding") == "chunked"
	responseBytes := 0
	if streaming {
		copyResponseHeaders(w.Header(), resp.Header)
		w.WriteHeader(resp.StatusCode)
		var rw interface {
			io.Writer
			Close() error
		}
		counted := &countingWriter{w: w}
		if strings.Contains(ct, "text/event-stream") {
			rw = NewSSERestoringWriterForSessionWithLimit(counted, p.redactor, session, p.options.MaxSSEEventBytes)
		} else {
			rw = NewRestoringWriterForSession(counted, p.redactor, session)
		}
		if _, err := io.Copy(rw, &cappedReader{r: resp.Body, remaining: p.options.MaxResponseBytes}); err != nil {
			p.logf("streaming upstream response: %v", err)
		} else if err := rw.Close(); err != nil {
			p.logf("closing streaming response: %v", err)
		}
		responseBytes = counted.n
	} else {
		respBody, err := readAtMost(resp.Body, p.options.MaxResponseBytes)
		if err != nil {
			if errors.Is(err, errBodyTooLarge) {
				p.logf("status=%d error=response_too_large", http.StatusBadGateway)
				http.Error(w, "upstream response rejected: body exceeds configured limit", http.StatusBadGateway)
				return
			}
			p.logf("reading upstream response body: %v", err)
			http.Error(w, "failed to read upstream response", http.StatusBadGateway)
			return
		}
		copyResponseHeaders(w.Header(), resp.Header)
		w.WriteHeader(resp.StatusCode)
		if n, err := w.Write(p.redactor.RestoreResponseForSession(respBody, ct, session)); err != nil {
			p.logf("writing response body: %v", err)
			responseBytes = n
		} else {
			responseBytes = n
		}
	}

	p.logRequest(resp.StatusCode, result.Transformed, categories, len(redactedBody), responseBytes, time.Since(started))
}

type countingWriter struct {
	w io.Writer
	n int
}

func (w *countingWriter) Write(p []byte) (int, error) {
	n, err := w.w.Write(p)
	w.n += n
	return n, err
}

func (w *countingWriter) Flush() {
	if flusher, ok := w.w.(http.Flusher); ok {
		flusher.Flush()
	}
}

type cappedReader struct {
	r         io.Reader
	remaining int64
}

func (r *cappedReader) Read(p []byte) (int, error) {
	if r.remaining <= 0 {
		var probe [1]byte
		n, err := r.r.Read(probe[:])
		if n > 0 {
			return 0, errBodyTooLarge
		}
		return 0, err
	}
	if int64(len(p)) > r.remaining {
		p = p[:r.remaining]
	}
	n, err := r.r.Read(p)
	r.remaining -= int64(n)
	return n, err
}

func readAtMost(r io.Reader, max int64) ([]byte, error) {
	return io.ReadAll(&cappedReader{r: r, remaining: max})
}

func copyResponseHeaders(dst, src http.Header) {
	for k, vv := range src {
		if k == "Content-Length" || k == "Transfer-Encoding" {
			continue
		}
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
	dst.Del("Content-Length")
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

func (p *Proxy) logRequest(status, transformed int, categories []string, sentBytes, returnedBytes int, duration time.Duration) {
	if p.logger == nil {
		return
	}
	fields := fmt.Sprintf("status=%d transformed=%d sent_bytes=%d returned_bytes=%d duration_ms=%d", status, transformed, sentBytes, returnedBytes, duration.Milliseconds())
	if len(categories) == 0 {
		p.logger.Print(fields)
		return
	}
	p.logger.Printf("%s categories=%s", fields, strings.Join(uniqueSorted(categories), ","))
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
