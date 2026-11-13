package app

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"sync/atomic"
	"time"

	quic "github.com/qoke/mp-quic-go"
	"github.com/qoke/mp-quic-go/http3"
	"github.com/roseshot/mqvpn-ebpf/internal/forward"
	"github.com/roseshot/mqvpn-ebpf/internal/tap"
)

func RunServer(ctx context.Context, args []string, logger *slog.Logger) error {
	fs := flag.NewFlagSet("server", flag.ContinueOnError)
	listen := fs.String("listen", ":4433", "UDP listen address")
	tapName := fs.String("tap", "mq0", "name of standalone TAP tunnel interface")
	tunnelIP := fs.String("tunnel-ip", "", "TAP interface CIDR, e.g. 10.77.0.1/30 (required)")
	tunnelMTU := fs.Int("tunnel-mtu", 1100, "TAP L3 MTU (IPv4 test default)")
	path := fs.String("path", defaultPath, "exact CONNECT-ETHERNET URI path")
	certFile := fs.String("cert", "", "server TLS certificate PEM")
	keyFile := fs.String("key", "", "server TLS key PEM")
	clientCA := fs.String("client-ca", "", "CA verifying client TLS certificates (mTLS required)")
	maxFrame := fs.Int("max-frame", 1160, "maximum Ethernet frame bytes, excluding FCS (larger frames dropped)")
	if err := fs.Parse(args); err != nil { return err }
	if *maxFrame < 14 || *maxFrame > 65535 { return fmt.Errorf("invalid --max-frame %d", *maxFrame) }
	if len(*path) == 0 || (*path)[0] != '/' { return errors.New("--path must begin with /") }
	cert, err := keyPair(*certFile, *keyFile)
	if err != nil { return err }
	pool, err := certPool(*clientCA)
	if err != nil { return err }
	if err := tap.Configure(*tapName, *tunnelIP, *tunnelMTU, *maxFrame); err != nil { return fmt.Errorf("configure tunnel interface: %w", err) }
	logger.Info("routed TAP tunnel ready", "interface", *tapName, "cidr", *tunnelIP, "mtu", *tunnelMTU)

	var active atomic.Bool
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect || r.Proto != "connect-ethernet" || r.URL.Path != *path {
			http.Error(w, "expected CONNECT :protocol=connect-ethernet", http.StatusBadRequest)
			return
		}
		if r.Header.Get("Capsule-Protocol") != "?1" {
			http.Error(w, "Capsule-Protocol: ?1 required", http.StatusBadRequest)
			return
		}
		setter, ok := w.(interface {
			ReceivedSettings() <-chan struct{}
			Settings() *http3.Settings
		})
		if !ok {
			http.Error(w, "HTTP/3 required", http.StatusHTTPVersionNotSupported)
			return
		}
		select {
		case <-r.Context().Done(): return
		case <-setter.ReceivedSettings():
		}
		if !setter.Settings().EnableDatagrams {
			http.Error(w, "HTTP/3 DATAGRAM required", http.StatusBadRequest)
			return
		}
		if !active.CompareAndSwap(false, true) {
			http.Error(w, "a tunnel is already active", http.StatusServiceUnavailable)
			return
		}
		defer active.Store(false)
		dev, err := tap.Open(*tapName)
		if err != nil {
			logger.Error("open TAP", "error", err)
			http.Error(w, "TAP unavailable", http.StatusServiceUnavailable)
			return
		}
		streamer, ok := w.(http3.HTTPStreamer)
		if !ok {
			_ = dev.Close()
			http.Error(w, "HTTP/3 stream unavailable", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Capsule-Protocol", "?1")
		w.WriteHeader(http.StatusOK)
		stream := streamer.HTTPStream()
		var counters forward.Counters
		stopMetrics := make(chan struct{})
		go printCounters(stopMetrics, &counters, logger)
		logger.Info("CONNECT-ETHERNET established", "remote", r.RemoteAddr, "tap", *tapName)
		err = forward.Run(r.Context(), dev, stream, *maxFrame, &counters, logger)
		close(stopMetrics)
		logger.Info("CONNECT-ETHERNET ended", "error", err, "stats", counters.Snapshot())
	})
	srv := &http3.Server{
		Addr: *listen,
		Handler: handler,
		TLSConfig: &tls.Config{
			MinVersion: tls.VersionTLS13,
			Certificates: []tls.Certificate{cert},
			ClientCAs: pool,
			ClientAuth: tls.RequireAndVerifyClientCert,
		},
		EnableDatagrams: true,
		QUICConfig: &quic.Config{
			EnableDatagrams: true,
			MaxPaths: 2,
			MultipathControllerFactory: func() quic.MultipathController {
				return quic.NewDefaultMultipathController(quic.NewRoundRobinScheduler())
			},
			KeepAlivePeriod: 10 * time.Second,
			MaxIdleTimeout: 30 * time.Second,
		},
	}
	go func() { <-ctx.Done(); _ = srv.Close() }()
	logger.Info("starting CONNECT-ETHERNET server", "listen", *listen, "path", *path)
	err = srv.ListenAndServe()
	if ctx.Err() != nil || errors.Is(err, http.ErrServerClosed) { return nil }
	return err
}

func printCounters(done <-chan struct{}, c *forward.Counters, logger *slog.Logger) {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-done: return
		case <-ticker.C:
			logger.Info("Ethernet tunnel counters", "stats", c.Snapshot())
		}
	}
}
