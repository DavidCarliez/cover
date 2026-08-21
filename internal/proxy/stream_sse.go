package proxy

import (
	"bytes"
	"io"
	"net/http"

	"llmguard/internal/redact"
)

// SSERestoringWriter buffers complete SSE events and restores placeholder
// tokens inside JSON data lines with proper escaping.
type SSERestoringWriter struct {
	w        io.Writer
	flusher  http.Flusher
	redactor *redact.Redactor
	session  string
	buf      []byte
}

// NewSSERestoringWriter wraps w for text/event-stream responses.
func NewSSERestoringWriter(w io.Writer, redactor *redact.Redactor) *SSERestoringWriter {
	return NewSSERestoringWriterForSession(w, redactor, "")
}

func NewSSERestoringWriterForSession(w io.Writer, redactor *redact.Redactor, session string) *SSERestoringWriter {
	f, _ := w.(http.Flusher)
	return &SSERestoringWriter{w: w, flusher: f, redactor: redactor, session: session}
}

// Write implements io.Writer.
func (rw *SSERestoringWriter) Write(p []byte) (int, error) {
	rw.buf = append(rw.buf, p...)
	for {
		idx := bytes.Index(rw.buf, []byte("\n\n"))
		if idx < 0 {
			break
		}
		event := rw.buf[:idx+2]
		rw.buf = rw.buf[idx+2:]
		restored := rw.redactor.RestoreSSEEventForSession(event, rw.session)
		if _, err := rw.w.Write(restored); err != nil {
			return 0, err
		}
		if rw.flusher != nil {
			rw.flusher.Flush()
		}
	}
	return len(p), nil
}

// Close flushes any buffered partial event.
func (rw *SSERestoringWriter) Close() error {
	if len(rw.buf) > 0 {
		restored := rw.redactor.RestoreSSEEventForSession(rw.buf, rw.session)
		if _, err := rw.w.Write(restored); err != nil {
			return err
		}
		rw.buf = nil
	}
	if rw.flusher != nil {
		rw.flusher.Flush()
	}
	return nil
}
