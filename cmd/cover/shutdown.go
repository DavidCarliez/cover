package main

import (
	"context"
	"net"
	"net/http"
	"time"

	"github.com/DavidCarliez/cover/internal/config"
)

func shutdownDuration(cfg *config.Config) time.Duration {
	if cfg.ShutdownTimeoutMS <= 0 {
		return 30 * time.Second
	}
	return time.Duration(cfg.ShutdownTimeoutMS) * time.Millisecond
}

func shutdownWait() time.Duration {
	cfg, err := loadOrDefaultConfig()
	if err != nil {
		return 35 * time.Second
	}
	return shutdownDuration(cfg) + 5*time.Second
}

func serveGracefully(ctx context.Context, srv *http.Server, ln net.Listener, timeout time.Duration) error {
	serving := make(chan error, 1)
	go func() { serving <- srv.Serve(ln) }()
	select {
	case err := <-serving:
		if err == http.ErrServerClosed {
			return nil
		}
		return err
	case <-ctx.Done():
		drain, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		if err := srv.Shutdown(drain); err != nil {
			_ = srv.Close()
		}
		err := <-serving
		if err == http.ErrServerClosed {
			return nil
		}
		return err
	}
}
