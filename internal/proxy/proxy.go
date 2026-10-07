// Package proxy implements the local HTTP proxy: it redacts sensitive data
// from outgoing requests, forwards them to the configured upstream, and
// restores placeholders in the response before returning it to the caller.
package proxy

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
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

	"github.com/DavidCarliez/cover/internal/activity"
	"github.com/DavidCarliez/cover/internal/redact"
)

const (
	defaultConnectTimeout        = 10 * time.Second
	defaultResponseHeaderTimeout = 120 * time.Second
	defaultMaxRequestBytes       = int64(64 << 20)
	defaultMaxResponseBytes      = int64(32 << 20)
	defaultMaxSSEEventBytes      = int64(4 << 20)
)

var errBodyTooLarge = errors.New("body exceeds configured limit")

// hopHeader carries one random identifier per Cover process. A request that
// already carries this process's identifier has looped back through it.
const hopHeader = "X-Cover-Hop"

// ephemeralSessionPrefix cannot occur in an HTTP header value, so a client
// session header cannot name a request-scoped session.
const ephemeralSessionPrefix = "\x00request-"

// hopByHopHeaders apply to one connection and are never forwarded.
var hopByHopHeaders = []string{
	"Connection", "Proxy-Connection", "Keep-Alive", "Proxy-Authenticate",
	"Proxy-Authorization", "Te", "Trailer", "Transfer-Encoding", "Upgrade",
}

// Options configures upstream HTTP client timeouts. Zero values use defaults.
type Options struct {
	UpstreamPaths         map[string]string
	ConnectTimeout        time.Duration
	ResponseHeaderTimeout time.Duration
	ResponseIdleTimeout   time.Duration
	SessionHeader         string
	MediaImages           string
	MaxRequestBytes       int64
	MaxResponseBytes      int64
	MaxSSEEventBytes      int64
	ContentHub            *activity.Hub
	ContentToken          string
}

func (o Options) withDefaults() Options {
	if o.ResponseIdleTimeout <= 0 {
		o.ResponseIdleTimeout = 5 * time.Minute
	}
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
	upstream     *url.URL
	client       *http.Client
	redactor     *redact.Redactor
	logger       *log.Logger
	options      Options
	nextSession  atomic.Uint64
	contentHub   *activity.Hub
	contentToken string
	hopID        string
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
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: opts.ConnectTimeout}).DialContext,
		TLSHandshakeTimeout:   opts.ConnectTimeout,
		ResponseHeaderTimeout: opts.ResponseHeaderTimeout,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          64,
		MaxIdleConnsPerHost:   16,
		IdleConnTimeout:       90 * time.Second,
	}
	var hop [8]byte
	if _, err := rand.Read(hop[:]); err != nil {
		return nil, fmt.Errorf("generating proxy identifier: %w", err)
	}

	return &Proxy{
		hopID:        hex.EncodeToString(hop[:]),
		upstream:     u,
		client:       &http.Client{Transport: transport},
		redactor:     redactor,
		logger:       logger,
		options:      opts,
		contentHub:   opts.ContentHub,
		contentToken: opts.ContentToken,
	}, nil
}

// ServeHTTP implements http.Handler.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == activity.ContentEndpoint {
		p.serveContentMonitor(w, r)
		return
	}
	started := time.Now()
	defer r.Body.Close()
	for _, value := range r.Header.Values(hopHeader) {
		for _, id := range strings.Split(value, ",") {
			if strings.TrimSpace(id) == p.hopID {
				p.logf("status=%d error=proxy_loop", http.StatusLoopDetected)
				http.Error(w, "request rejected: upstream points back to Cover", http.StatusLoopDetected)
				return
			}
		}
	}
	body, err := readAtMost(r.Body, p.options.MaxRequestBytes)
	if err != nil {
		if errors.Is(err, errBodyTooLarge) {
			p.logf("status=%d error=request_too_large", http.StatusRequestEntityTooLarge)
			http.Error(w, "request rejected: body exceeds configured limit", http.StatusRequestEntityTooLarge)
			return
		}
		http.Error(w, "failed to read request body", http.StatusBadRequest)
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
		session = fmt.Sprintf("%s%d", ephemeralSessionPrefix, p.nextSession.Add(1))
		defer p.redactor.EndSession(session)
	}
	// Do not inject protocol-specific guard notes. Generic recursive rewriting
	// must preserve the upstream request schema (Responses, Chat, Anthropic, or
	// another OpenAI-compatible router dialect).
	captureContent := p.contentHub != nil && p.contentHub.HasSubscribers()
	var result redact.TransformResult
	if captureContent {
		result, err = p.redactor.TransformWithCaptures(body, session, false, p.options.MediaImages)
	} else {
		result, err = p.redactor.Transform(body, session, false, p.options.MediaImages)
	}
	if err != nil {
		// Transform errors are deliberately generic and never contain matched
		// values, request bodies, or mapping contents.
		code := "unsafe_request"
		if encoding := r.Header.Get("Content-Encoding"); encoding != "" && encoding != "identity" {
			code = "unsupported_compression"
		}
		p.logf("status=422 error=%s", code)
		http.Error(w, "request rejected: body could not be safely inspected", http.StatusUnprocessableEntity)
		return
	}
	if result.Blocked {
		p.publishContent(captureContent, started, result, nil)
		p.logf("status=403 error=policy_blocked")
		http.Error(w, "request blocked by local privacy policy", http.StatusForbidden)
		return
	}
	redactedBody, categories := result.Body, result.Categories

	target := *p.upstream
	path := r.URL.Path
	if mapped, ok := p.options.UpstreamPaths[path]; ok {
		path = mapped
	}
	target.Path = singleJoiningSlash(p.upstream.Path, path)
	target.RawQuery = r.URL.RawQuery

	outReq, err := http.NewRequestWithContext(r.Context(), r.Method, target.String(), bytes.NewReader(redactedBody))
	if err != nil {
		http.Error(w, "failed to build upstream request", http.StatusBadGateway)
		return
	}
	outReq.Header = r.Header.Clone()
	removeHopByHopHeaders(outReq.Header)
	outReq.Header.Add(hopHeader, p.hopID)
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
	// Publish only after the exact outbound request has been constructed. This
	// is the body handed to the transport; network delivery can still fail.
	p.publishContent(captureContent, started, result, redactedBody)

	resp, err := p.client.Do(outReq)
	if err != nil {
		p.logf("status=502 error=%s", upstreamErrorCode(err))
		http.Error(w, "upstream request failed", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	resp.Body = &idleReadCloser{ReadCloser: resp.Body, timeout: p.options.ResponseIdleTimeout}

	ct := resp.Header.Get("Content-Type")
	sse := strings.Contains(ct, "text/event-stream")
	var responseBody io.Reader = resp.Body
	if ct == "" {
		// Some compatible routers omit the media type on SSE responses.
		// Keep the sniff bounded and replay every byte through the selected writer.
		buffered := bufio.NewReader(resp.Body)
		prefix, _ := buffered.Peek(64)
		responseBody = buffered
		sse = looksLikeSSE(prefix)
		if sse {
			ct = "text/event-stream"
			resp.Header.Set("Content-Type", ct)
		}
	}
	// Other responses, including chunked JSON, are buffered so restored
	// values are re-encoded with the escaping of their JSON context.
	responseBytes := 0
	if sse {
		copyResponseHeaders(w.Header(), resp.Header)
		w.WriteHeader(resp.StatusCode)
		var rw interface {
			io.Writer
			Close() error
		}
		counted := &countingWriter{w: w}
		rw = NewSSERestoringWriterWithLimits(counted, p.redactor, session, p.options.MaxSSEEventBytes, p.options.MaxResponseBytes)
		if _, err := io.Copy(rw, &cappedReader{r: responseBody, remaining: p.options.MaxResponseBytes}); err != nil {
			p.logf("status=502 error=%s", streamErrorCode(err))
			// Headers may already be sent. Abort the transport so the client
			// cannot mistake a truncated stream for successful completion.
			panic(http.ErrAbortHandler)
		} else if err := rw.Close(); err != nil {
			p.logf("status=502 error=%s", streamErrorCode(err))
			panic(http.ErrAbortHandler)
		}
		responseBytes = counted.n
	} else {
		respBody, err := readAtMost(responseBody, p.options.MaxResponseBytes)
		if err != nil {
			if errors.Is(err, errBodyTooLarge) {
				p.logf("status=%d error=response_too_large", http.StatusBadGateway)
				http.Error(w, "upstream response rejected: body exceeds configured limit", http.StatusBadGateway)
				return
			}
			p.logf("status=502 error=%s", upstreamErrorCode(err))
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

func (p *Proxy) serveContentMonitor(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	ip := net.ParseIP(host)
	provided := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	authorized := err == nil && ip != nil && ip.IsLoopback() && p.contentToken != "" &&
		subtle.ConstantTimeCompare([]byte(provided), []byte(p.contentToken)) == 1
	if !authorized || p.contentHub == nil {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	events, cancel, err := p.contentHub.Subscribe()
	if err != nil {
		http.Error(w, "live content monitor unavailable", http.StatusServiceUnavailable)
		return
	}
	defer cancel()
	w.Header().Set("Content-Type", "application/x-ndjson")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusOK)
	if flusher, ok := w.(http.Flusher); ok {
		flusher.Flush()
	}
	encoder := json.NewEncoder(w)
	for {
		select {
		case <-r.Context().Done():
			return
		case event, ok := <-events:
			if !ok {
				return
			}
			if err := encoder.Encode(event); err != nil {
				return
			}
			if flusher, ok := w.(http.Flusher); ok {
				flusher.Flush()
			}
		}
	}
}

func (p *Proxy) publishContent(enabled bool, started time.Time, result redact.TransformResult, sent []byte) {
	if !enabled || p.contentHub == nil {
		return
	}
	event := activity.ContentEvent{
		Time: started.UTC(), Transformed: result.Transformed, Blocked: result.Blocked,
	}
	for _, capture := range result.Captures {
		event.Caught = append(event.Caught, activity.ContentCapture{
			Rule: capture.Rule, Category: capture.Category, Action: capture.Action,
			Original: capture.Original, Replacement: capture.Replacement,
		})
	}
	if sent != nil {
		event.Sent = append(json.RawMessage(nil), sent...)
	}
	p.contentHub.Publish(event)
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
	src = src.Clone()
	removeHopByHopHeaders(src)
	for k, vv := range src {
		if k == "Content-Length" {
			continue
		}
		for _, v := range vv {
			dst.Add(k, v)
		}
	}
	dst.Del("Content-Length")
}

// removeHopByHopHeaders deletes connection-scoped headers, including those
// that the Connection header names.
func removeHopByHopHeaders(h http.Header) {
	for _, value := range h.Values("Connection") {
		for _, name := range strings.Split(value, ",") {
			if name = strings.TrimSpace(name); name != "" {
				h.Del(name)
			}
		}
	}
	for _, name := range hopByHopHeaders {
		h.Del(name)
	}
}

// looksLikeSSE recognizes an event stream without a media type by its first
// field, after an optional byte-order mark and blank lines.
func looksLikeSSE(prefix []byte) bool {
	prefix = bytes.TrimPrefix(prefix, []byte("\xef\xbb\xbf"))
	prefix = bytes.TrimLeft(prefix, "\r\n")
	for _, field := range []string{"event:", "data:", "id:", "retry:", ":"} {
		if bytes.HasPrefix(prefix, []byte(field)) {
			return true
		}
	}
	return false
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
