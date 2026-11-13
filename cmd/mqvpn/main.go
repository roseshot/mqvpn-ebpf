// mqvpn is a Linux TAP to MASQUE CONNECT-ETHERNET (draft -18) gateway.
// QUIC and HTTP/3 come from mp-quic-go; no proprietary L2 or plaintext mode.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
)

const defaultPath = "/.well-known/masque/ethernet/"

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: mqvpn server|client [options]; run with --help for options")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "server":
		err = runServer(ctx, os.Args[2:], logger)
	case "client":
		err = runClient(ctx, os.Args[2:], logger)
	case "help", "-h", "--help":
		fmt.Println("usage: mqvpn server|client [options]")
		return
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil && !errors.Is(err, context.Canceled) && !errors.Is(err, flag.ErrHelp) {
		logger.Error("mqvpn terminated", "error", err)
		os.Exit(1)
	}
}
