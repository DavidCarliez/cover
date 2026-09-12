package main

import (
	"context"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestGracefulShutdownDrainsOrExpires(t *testing.T) {
	for _, finish := range []bool{true, false} {
		t.Run(map[bool]string{true: "drains", false: "deadline"}[finish], func(t *testing.T) {
			entered := make(chan struct{})
			release := make(chan struct{})
			handlerDone := make(chan struct{})
			srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				defer close(handlerDone)
				close(entered)
				w.WriteHeader(200)
				w.(http.Flusher).Flush()
				select {
				case <-release:
					io.WriteString(w, "complete")
				case <-r.Context().Done():
				}
			})}
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			serverDone := make(chan error, 1)
			go func() { serverDone <- serveGracefully(ctx, srv, ln, 150*time.Millisecond) }()
			client := &http.Client{Timeout: 2 * time.Second}
			resp, err := client.Get("http://" + ln.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			<-entered
			cancel()
			if finish {
				time.AfterFunc(20*time.Millisecond, func() { close(release) })
			}
			body, readErr := io.ReadAll(resp.Body)
			if finish && (readErr != nil || string(body) != "complete") {
				t.Fatalf("active response interrupted: %q %v", body, readErr)
			}
			if !finish && readErr == nil {
				t.Fatal("deadline did not interrupt stalled response")
			}
			select {
			case err := <-serverDone:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(time.Second):
				t.Fatal("shutdown hung")
			}
			<-handlerDone
		})
	}
}
