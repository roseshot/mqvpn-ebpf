package app

import (
	"context"
	"errors"
)

// eligibleTCPFallback is intentionally conservative. Authentication,
// authorization, SNI/CA errors, HTTP rejection and an established QUIC
// session must never trigger a silent transport downgrade. Only a QUIC
// connection attempt that exhausted its own UDP handshake deadline can
// automatically try the TLS 1.3 TCP transport.
func eligibleTCPFallback(parent,dial context.Context,err error)bool{
	return err!=nil && parent.Err()==nil && errors.Is(dial.Err(),context.DeadlineExceeded)
}
