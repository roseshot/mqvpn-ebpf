package app

import (
	"crypto/tls"
	"sync"
	"testing"
)

func TestConcurrentSNISelectionAndHotPublish(t *testing.T) {
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
	liveA := &liveInstance{prepared: prepared.instances[a.Name]}
	liveB := &liveInstance{prepared: prepared.instances[b.Name]}
	mux := newServerMux()
	onlyA := map[string]*liveInstance{a.Name: liveA}
	both := map[string]*liveInstance{a.Name: liveA, b.Name: liveB}
	mux.Publish(both)
	var wg sync.WaitGroup
	wg.Add(3)
	for worker := 0; worker < 2; worker++ {
		go func() {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				_, _ = mux.TLSConfigFor(&tls.ClientHelloInfo{ServerName: "edge-a.example.test"})
				_, _ = mux.TLSConfigFor(&tls.ClientHelloInfo{ServerName: "edge-b.example.test"})
			}
		}()
	}
	go func() {
		defer wg.Done()
		for i := 0; i < 500; i++ {
			if i%2 == 0 {
				mux.Publish(onlyA)
			} else {
				mux.Publish(both)
			}
		}
	}()
	wg.Wait()
	if mux.Lookup("edge-a.example.test") != liveA {
		t.Fatal("stable tenant was lost")
	}
}
