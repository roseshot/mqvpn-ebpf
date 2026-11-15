//go:build linux

package main

import (
	"context"
	"errors"
	"flag"
	"os"
	"os/signal"
	"syscall"

	"github.com/roseshot/mqvpn-ebpf/internal/app"
	"github.com/roseshot/mqvpn-ebpf/internal/logging"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	args, opts, err := logging.Extract(os.Args[1:])
	logger := logging.NewComponent(opts, "server")
	if err != nil {
		logger.ErrorContext(ctx, "invalid logging options", "error", err)
		os.Exit(2)
	}
	err = app.RunServer(ctx, args, logger)
	if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, flag.ErrHelp) {
		logger.ErrorContext(ctx, "mqvpn terminated", "error", err)
		os.Exit(1)
	}
}
