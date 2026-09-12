package proxy

import (
	"errors"
	"io"
	"time"
)

var errResponseIdle = errors.New("upstream response inactivity timeout")

// Bound each network read without imposing a total deadline on an active
// stream. Closing an HTTP response body releases a blocked transport read.
type idleReadCloser struct {
	io.ReadCloser
	timeout time.Duration
}

func (r *idleReadCloser) Read(p []byte) (int, error) {
	fired := make(chan struct{})
	timer := time.AfterFunc(r.timeout, func() {
		r.ReadCloser.Close()
		close(fired)
	})
	n, err := r.ReadCloser.Read(p)
	if !timer.Stop() {
		<-fired
		return n, errResponseIdle
	}
	return n, err
}
