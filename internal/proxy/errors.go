package proxy

import (
	"context"
	"errors"
	"net"
)

func upstreamErrorCode(err error) string {
	if errors.Is(err, context.Canceled) {
		return "client_cancelled"
	}
	if errors.Is(err, errResponseIdle) {
		return "upstream_idle_timeout"
	}
	var timeout net.Error
	if errors.As(err, &timeout) && timeout.Timeout() {
		return "upstream_timeout"
	}
	return "upstream_connection_failed"
}

func streamErrorCode(err error) string {
	if errors.Is(err, ErrSSEEventTooLarge) {
		return "sse_event_too_large"
	}
	if errors.Is(err, errBodyTooLarge) {
		return "response_too_large"
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, errResponseIdle) {
		return upstreamErrorCode(err)
	}
	return "stream_interrupted"
}
