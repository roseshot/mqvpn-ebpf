package app

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"
)

func TestClientRequiresExplicitTUNAddressBeforeNetworking(t *testing.T){
	logger:=slog.New(slog.NewTextHandler(io.Discard,nil))
	for _,tc:=range []struct{args []string;match string}{
		{[]string{"--tun","mq0","--source-ip","192.0.2.1"},"TUN address"},
		{[]string{"--tun","mq0","--tun-address","0.0.0.0/24","--source-ip","192.0.2.1"},"unicast"},
		{[]string{"--tun","mq0","--tun-address","fd77::2/64","--tun-mtu","1100","--source-ip","192.0.2.1"},"MTU"},
		{[]string{"--tun","mq0","--tun-address","10.77.0.2/24","--tun-mtu","1200","--max-frame","1160","--source-ip","192.0.2.1"},"max-frame"},
	}{
		err:=RunClient(context.Background(),tc.args,logger)
		if err==nil||!strings.Contains(err.Error(),tc.match){
			t.Fatalf("args %v: got %v; expected %q",tc.args,err,tc.match)
		}
	}
}
