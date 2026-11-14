package app

import (
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSNIMuxTLSSelectionAndRemoval(t *testing.T) {
	cfg, _ := testServerFiles(t)
	a := cfg.Instances[0]
	b := a
	b.Name = "edge-b"
	b.ServerName = "edge-b.example.test"
	b.TUN = "mq1"
	cfg.Instances = []ServerInstance{a, b}
	prepared, err := prepareServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	mux := newServerMux()
	liveA := &liveInstance{prepared: prepared.instances["edge-a"]}
	liveB := &liveInstance{prepared: prepared.instances["edge-b"]}
	mux.Publish(map[string]*liveInstance{"a": liveA, "b": liveB})
	for _, testcase := range []struct {
		name     string
		selected *liveInstance
	}{
		{"edge-a.example.test", liveA},
		{"edge-b.example.test", liveB},
	} {
		selection, err := mux.TLSConfigFor(&tls.ClientHelloInfo{ServerName: testcase.name})
		if err != nil || selection != testcase.selected.prepared.tlsConfig {
			t.Fatalf("SNI %s selected wrong TLS config: %v", testcase.name, err)
		}
	}
	if _, err := mux.TLSConfigFor(&tls.ClientHelloInfo{}); err == nil {
		t.Fatal("missing SNI must fail rather than fall back to a tenant")
	}
	if _, err := mux.TLSConfigFor(&tls.ClientHelloInfo{ServerName: "other.example.test"}); err == nil {
		t.Fatal("unknown SNI accepted")
	}
	mux.Publish(map[string]*liveInstance{"a": liveA})
	if mux.Lookup("edge-b.example.test") != nil {
		t.Fatal("deleted tenant still addressable")
	}
	if mux.Lookup("edge-a.example.test") != liveA {
		t.Fatal("remaining SNI was lost")
	}
}

func TestAuthorityMustMatchSNI(t *testing.T) {
	for _, host := range []string{"edge-a.example.test", "edge-a.example.test:4433", "EDGE-A.EXAMPLE.TEST:4433"} {
		if !requestAuthorityMatchesSNI(host, "edge-a.example.test") {
			t.Fatalf("valid host rejected %q", host)
		}
	}
	if requestAuthorityMatchesSNI("edge-b.example.test:4433", "edge-a.example.test") {
		t.Fatal("cross-tenant authority accepted")
	}
	mux := newServerMux()
	req := httptest.NewRequest(http.MethodConnect, "https://edge-a.example.test/.well-known/masque/ethernet/", nil)
	req.TLS = &tls.ConnectionState{ServerName: "unknown.example.test"}
	out := httptest.NewRecorder()
	mux.ServeHTTP(out, req)
	if out.Code != http.StatusMisdirectedRequest {
		t.Fatalf("expected 421, got %d", out.Code)
	}
}

func TestSharedPortChangeRequiresRestart(t *testing.T) {
	cfg, _ := testServerFiles(t)
	next, err := prepareServer(cfg)
	if err != nil {
		t.Fatal(err)
	}
	mgr := newServerManager(t.Context(), nil)
	mgr.listen = ":4433"
	defer mgr.xdp.Close()
	cfg.Listen = ":4434"
	if err := mgr.apply(next); err == nil {
		// Initial next uses different literal listen than :4433, so error.
		t.Fatal("shared listener bind change unexpectedly accepted")
	}
}

func TestSingleInstanceIPCertificateWithoutSNI(t *testing.T) {
	for _, ip := range []string{"198.51.100.7", "2001:db8::7"} {
		mux := newServerMux()
		live := &liveInstance{prepared: preparedInstance{spec: ServerInstance{ServerName: ip}, tlsConfig: &tls.Config{}}}
		mux.Publish(map[string]*liveInstance{"only": live})
		selected, err := mux.TLSConfigFor(&tls.ClientHelloInfo{})
		if err != nil || selected != live.prepared.tlsConfig {
			t.Fatalf("IP %s missing-SNI TLS: %v", ip, err)
		}
		host := ip
		if strings.Contains(ip, ":") {
			host = "[" + ip + "]"
		}
		if !requestAuthorityMatchesSNI(host+":443", ip) {
			t.Fatalf("IP authority rejected: %s", ip)
		}
		// httptest's CONNECT constructor interprets an absolute URL as
		// authority-form and sets Host="https:". Use GET to check
		// tenant selection/Host matching; method validation follows.
		req := httptest.NewRequest(http.MethodGet, "https://"+net.JoinHostPort(ip, "443")+defaultPath, nil)
		req.TLS = &tls.ConnectionState{}
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, req)
		if w.Code == http.StatusMisdirectedRequest {
			t.Fatalf("single IP SAN request denied before mTLS authentication: %s", ip)
		}
		mux.Publish(map[string]*liveInstance{"only": live, "other": {prepared: preparedInstance{spec: ServerInstance{ServerName: "two.example.test"}, tlsConfig: &tls.Config{}}}})
		if _, err := mux.TLSConfigFor(&tls.ClientHelloInfo{}); err == nil {
			t.Fatalf("multi-instance missing-SNI accepted")
		}
	}
}
