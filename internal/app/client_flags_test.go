package app

import (
	"context"
	"io"
	"log/slog"
	"testing"
)

func TestRejectUnknownClientWANFlags(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	for _, flag := range []string{"--wan1", "--wan2", "--wan1-ip", "--wan1-interface", "--wan2-iface"} {
		if err := RunClient(context.Background(), []string{flag, "192.0.2.10"}, logger); err == nil {
			t.Fatalf("unknown client flag %s accepted", flag)
		}
	}
}

func TestRejectRemovedCompatibilityClientFlags(t *testing.T){
	logger:=slog.New(slog.NewTextHandler(io.Discard,nil))
	for _,flag:=range []string{"--url","--server-name"}{
		if err:=RunClient(context.Background(),[]string{flag,"unused"},logger);err==nil{t.Fatalf("removed option %s accepted",flag)}
	}
}
