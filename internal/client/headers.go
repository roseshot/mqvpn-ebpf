package client

import (
	"fmt"
	"net/http"
)

// responseContext is embedded rather than repeated in every parser call.
// Go 1.27 allows constructing authenticatedHeaders with the promoted
// "transport" field directly in the composite literal.
type responseContext struct {
	transport string
}

type authenticatedHeaders struct {
	http.Header
	responseContext
}

// Decode is a Go 1.27 generic method. Both route CIDRs and DNS IPs are
// decoded through the same authenticated HTTP response boundary. The
// decoder is inferred from the concrete parser function; callers need
// neither explicit type arguments nor a package-level generic helper.
//
// The empty header is delegated to each protocol-specific decoder,
// preserving the distinction between no push and an invalid push.
func (h authenticatedHeaders) Decode[T any](kind, name string, parse func(string) (T, error)) (T, error) {
	value, err := parse(h.Header.Get(name))
	if err != nil {
		var zero T
		return zero, fmt.Errorf("%s pushed %s: %w", h.transport, kind, err)
	}
	return value, nil
}
