package websteps

import (
	"context"
	"net"

	"github.com/ooni/probe-cli/v3/internal/model"
	"github.com/ooni/probe-cli/v3/internal/netxlite"
)

type TCPConfig struct {
	Dialer   model.Dialer
	Endpoint string
	Resolver model.Resolver
}

// TCPDo performs the TCP check.
func TCPDo(ctx context.Context, config TCPConfig) (net.Conn, error) {
	if config.Dialer != nil {
		return config.Dialer.DialContext(ctx, "tcp", config.Endpoint)
	}
	resolver := config.Resolver
	if resolver == nil {
		resolver = &netxlite.ResolverSystem{}
	}
	dialer := NewDialerResolver(resolver)
	return dialer.DialContext(ctx, "tcp", config.Endpoint)
}
