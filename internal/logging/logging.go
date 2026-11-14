package logging

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
)

type Options struct {
	Level  slog.Level
	Format string
}

func ParseLevel(value string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "info":
		return slog.LevelInfo, nil
	case "debug":
		return slog.LevelDebug, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	default:
		return 0, fmt.Errorf("invalid log level %q; expected debug|info|warn|error", value)
	}
}

// Extract strips common --log-level and --log-format options before routing
// remaining arguments to the selected server/client CLI.
func Extract(args []string) ([]string, Options, error) {
	level := os.Getenv("MQVPN_LOG_LEVEL")
	format := os.Getenv("MQVPN_LOG_FORMAT")
	if format == "" {
		format = "text"
	}
	out := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--log-level" || a == "--log-format":
			if i+1 >= len(args) {
				return nil, Options{}, fmt.Errorf("%s requires a value", a)
			}
			i++
			if a == "--log-level" {
				level = args[i]
			} else {
				format = args[i]
			}
		case strings.HasPrefix(a, "--log-level="):
			level = strings.TrimPrefix(a, "--log-level=")
		case strings.HasPrefix(a, "--log-format="):
			format = strings.TrimPrefix(a, "--log-format=")
		default:
			out = append(out, a)
		}
	}
	l, err := ParseLevel(level)
	if err != nil {
		return nil, Options{}, err
	}
	format = strings.ToLower(strings.TrimSpace(format))
	if format != "text" && format != "json" {
		return nil, Options{}, fmt.Errorf("invalid log format %q; expected text|json", format)
	}
	return out, Options{Level: l, Format: format}, nil
}

// New sends all diagnostic records to stderr. stdout stays reserved for
// machine-readable command output (for example, "server instance list").
func New(opts Options) *slog.Logger {
	return newWithWriter(os.Stderr, opts)
}

func newWithWriter(writer io.Writer, opts Options) *slog.Logger {
	handlerOpts := &slog.HandlerOptions{Level: opts.Level}
	if opts.Format == "json" {
		return slog.New(slog.NewJSONHandler(writer, handlerOpts))
	}
	return slog.New(slog.NewTextHandler(writer, handlerOpts))
}

// NewComponent creates an application root logger with a stable component
// attribute. Child loggers inherit its handler, format and level.
func NewComponent(opts Options, component string) *slog.Logger {
	return newComponentWithWriter(os.Stderr, opts, component)
}

func newComponentWithWriter(writer io.Writer, opts Options, component string) *slog.Logger {
	return newWithWriter(writer, opts).With("component", component)
}

// Ensure preserves the explicit logger provided by the caller, or creates a
// deterministic stderr/info fallback for library entry points and tests.
// It never depends on the process-global slog.Default() configuration.
func Ensure(logger *slog.Logger) *slog.Logger {
	if logger != nil {
		return logger
	}
	return New(Options{Level: slog.LevelInfo, Format: "text"})
}
