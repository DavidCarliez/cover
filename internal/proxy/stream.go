package proxy

import (
	"io"
	"net/http"

	"llmguard/internal/redact"
)

// RestoringWriter wraps an io.Writer (typically an http.ResponseWriter),
// restoring placeholder tokens as data streams through it while buffering
// the minimum number of bytes needed to avoid splitting a token across
// successive Write calls.
type RestoringWriter struct {
	w        io.Writer
	flusher  http.Flusher
	redactor *redact.Redactor
	session  string
	buf      []byte
}

// NewRestoringWriter wraps w. If w implements http.Flusher, each restored
// chunk is flushed immediately so streaming responses remain responsive.
func NewRestoringWriter(w io.Writer, redactor *redact.Redactor) *RestoringWriter {
	return NewRestoringWriterForSession(w, redactor, "")
}

func NewRestoringWriterForSession(w io.Writer, redactor *redact.Redactor, session string) *RestoringWriter {
	f, _ := w.(http.Flusher)
	return &RestoringWriter{w: w, flusher: f, redactor: redactor, session: session}
}

// Write implements io.Writer.
func (rw *RestoringWriter) Write(p []byte) (int, error) {
	rw.buf = append(rw.buf, p...)

	cut := rw.redactor.SafeStreamCut(rw.buf, rw.session)
	if cut > 0 {
		restored := rw.redactor.RestoreForSession(rw.buf[:cut], rw.session)
		if _, err := rw.w.Write(restored); err != nil {
			return 0, err
		}
		rw.buf = rw.buf[cut:]
		if rw.flusher != nil {
			rw.flusher.Flush()
		}
	}
	return len(p), nil
}

// Close restores and flushes any remaining buffered bytes. It must be called
// once after the source is fully copied.
func (rw *RestoringWriter) Close() error {
	if len(rw.buf) > 0 {
		restored := rw.redactor.RestoreForSession(rw.buf, rw.session)
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
