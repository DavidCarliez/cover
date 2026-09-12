package proxy

import (
	"context"
	"errors"
	"net"
	"testing"
)

func TestFailureClassificationDoesNotExposeDetails(t *testing.T) {
	for _, tc := range []struct {
		err  error
		code string
	}{
		{context.Canceled, "client_cancelled"},
		{errResponseIdle, "upstream_idle_timeout"},
		{&net.DNSError{Err: "private-host", IsTimeout: true}, "upstream_timeout"},
		{errors.New("https://private-host/token"), "upstream_connection_failed"},
	} {
		if got := upstreamErrorCode(tc.err); got != tc.code {
			t.Fatalf("got %s want %s", got, tc.code)
		}
	}
	if streamErrorCode(ErrSSEEventTooLarge) != "sse_event_too_large" || streamErrorCode(errBodyTooLarge) != "response_too_large" {
		t.Fatal("limit errors are not distinguished")
	}
}
