package client

import (
	"errors"
	"net/http"
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"github.com/roseshot/mqvpn-ebpf/internal/dnspush"
	"github.com/roseshot/mqvpn-ebpf/internal/routepush"
)

func TestGo127GenericAuthenticatedHeaderDecoding(t *testing.T) {
	for _, transport := range []string{"CONNECT-ETHERNET", "TCP"} {
		// "transport" is promoted from responseContext; Go 1.27 allows
		// it directly in a keyed composite literal.
		headers := authenticatedHeaders{
			Header: http.Header{
				http.CanonicalHeaderKey(routepush.Header): []string{"10.90.0.0/16,0.0.0.0/0"},
				http.CanonicalHeaderKey(dnspush.Header):   []string{"10.77.0.1,fd77::53"},
			},
			transport: transport,
		}
		// Decode[T] infers []netip.Prefix / []netip.Addr from the
		// supplied parser without explicit type arguments.
		routes, err := headers.Decode("routes", routepush.Header, routepush.Decode)
		if err != nil || !reflect.DeepEqual(routes, []netip.Prefix{
			netip.MustParsePrefix("10.90.0.0/16"),
			netip.MustParsePrefix("0.0.0.0/0"),
		}) {
			t.Fatalf("%s routes: %v, %v", transport, routes, err)
		}
		dns, err := headers.Decode("DNS", dnspush.Header, dnspush.Decode)
		if err != nil || !reflect.DeepEqual(dns, []netip.Addr{
			netip.MustParseAddr("10.77.0.1"),
			netip.MustParseAddr("fd77::53"),
		}) {
			t.Fatalf("%s DNS: %v, %v", transport, dns, err)
		}
	}
}

func TestGo127GenericAuthenticatedHeadersFailClosed(t *testing.T) {
	for _, transport := range []string{"CONNECT-ETHERNET", "TCP"} {
		headers := authenticatedHeaders{Header: make(http.Header), transport: transport}
		if routes, err := headers.Decode("routes", routepush.Header, routepush.Decode); err != nil || len(routes) != 0 {
			t.Fatalf("%s missing routes must be empty: %v, %v", transport, routes, err)
		}
		if dns, err := headers.Decode("DNS", dnspush.Header, dnspush.Decode); err != nil || len(dns) != 0 {
			t.Fatalf("%s missing DNS must be empty: %v, %v", transport, dns, err)
		}
		for _, tc := range []struct {
			key, kind, invalid string
			decode             func(authenticatedHeaders) error
		}{
			{
				key:     routepush.Header,
				kind:    "routes",
				invalid: "not-a-prefix",
				decode: func(h authenticatedHeaders) error {
					_, err := h.Decode("routes", routepush.Header, routepush.Decode)
					return err
				},
			},
			{
				key:     dnspush.Header,
				kind:    "DNS",
				invalid: "not-an-ip",
				decode: func(h authenticatedHeaders) error {
					_, err := h.Decode("DNS", dnspush.Header, dnspush.Decode)
					return err
				},
			},
		} {
			headers.Set(tc.key, tc.invalid)
			err := tc.decode(headers)
			if err == nil || !strings.Contains(err.Error(), transport+" pushed "+tc.kind+":") {
				t.Fatalf("%s invalid %s accepted or lost context: %v", transport, tc.kind, err)
			}
			headers.Del(tc.key)
		}
	}
}

func TestGenericDecoderWrapsUnderlyingValidationError(t *testing.T) {
	sentinel := errors.New("failed validation")
	h := authenticatedHeaders{Header: http.Header{}, transport: "TCP"}
	got, err := h.Decode("custom", "X-Custom", func(string) (int, error) {
		return 0, sentinel
	})
	if got != 0 || !errors.Is(err, sentinel) {
		t.Fatalf("generic decoder must preserve underlying error: %v, %v", got, err)
	}
}
