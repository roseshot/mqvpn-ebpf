//go:build linux

package server

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"syscall"
	"time"

	"github.com/roseshot/mqvpn-ebpf/internal/logging"
)

// Run requires one YAML config with a shared UDP listener.
// The command accepts only the current multi-instance YAML contract.
func Run(ctx context.Context, args []string, logger *slog.Logger) error {
	logger = logging.Ensure(logger)
	if len(args) > 0 {
		switch args[0] {
		case "validate":
			return validateServerCLI(args[1:], logger)
		case "reload":
			return reloadServerCLI(args[1:], logger)
		case "instance":
			return runInstanceCLI(args[1:], logger)
		}
	}
	fs := flag.NewFlagSet("mqvpn-server", flag.ContinueOnError)
	config := fs.String("config", "", "YAML Server config with shared UDP listen and multiple instances")
	reload := fs.Duration("reload-interval", 2*time.Second, "YAML and certificate/peer file poll interval (0 disables)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *config == "" || fs.NArg() != 0 {
		return errors.New("usage: mqvpn-server --config server.yaml [--reload-interval 2s]")
	}
	return runManagedServer(ctx, func() (preparedServer, error) { return prepareConfigFile(*config) }, *reload, logger)
}

func validateServerCLI(args []string, logger *slog.Logger) error {
	logger = logging.Ensure(logger)
	fs := flag.NewFlagSet("validate", flag.ContinueOnError)
	path := fs.String("config", "", "YAML config to validate")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *path == "" || fs.NArg() != 0 {
		return errors.New("usage: mqvpn-server validate --config server.yaml")
	}
	prepared, err := prepareConfigFile(*path)
	if err != nil {
		return err
	}
	logger.Info("YAML configuration valid", "config", *path, "listen", prepared.listen, "instances", len(prepared.instances))
	return nil
}

func reloadServerCLI(args []string, logger *slog.Logger) error {
	logger = logging.Ensure(logger)
	fs := flag.NewFlagSet("reload", flag.ContinueOnError)
	pid := fs.Int("pid", 0, "PID of the running server")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *pid <= 1 || fs.NArg() != 0 {
		return errors.New("usage: mqvpn-server reload --pid <daemon-pid>")
	}
	if err := syscall.Kill(*pid, syscall.SIGHUP); err != nil {
		return fmt.Errorf("request config reload of PID %d: %w", *pid, err)
	}
	logger.Info("reload signal delivered (result will be logged by daemon)", "pid", *pid)
	return nil
}

// mux owns one HTTP/3 listener for multiple isolated P2MP hubs.
// SNI selects both the mTLS identity during handshake and the traffic
// forwarding domain for CONNECT-ETHERNET. It never examines inner VPN policy.
