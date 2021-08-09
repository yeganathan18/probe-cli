package nwebconnectivity

import (
	"context"
	"crypto/tls"
	"net"
	"time"

	"github.com/ooni/probe-cli/v3/internal/engine/model"
	"github.com/ooni/probe-cli/v3/internal/engine/netx/archival"
)

type TLSHandshakeConfig struct {
	Conn    net.Conn
	TLSConf *tls.Config
}

// tlsHandshake performs the TLS handshake
// func (m *Measurer) tlsHandshake(measurement *model.Measurement, ctx context.Context, conn net.Conn, config *tls.Config, snitest bool) (http.RoundTripper, error) {
func tlsHandshake(ctx context.Context, measurement *model.Measurement, conn net.Conn, tlscfg *tls.Config) (net.Conn, error, *archival.TLSHandshake) {
	handshaker := newHandshaker(nil)
	tlsconn, state, err := handshaker.Handshake(ctx, conn, tlscfg)
	stop := time.Now()

	entry := makeTLSHandshakeEntry(measurement.MeasurementStartTimeSaved, stop, TCPTLSExperimentTag)
	entry.setHandshakeResult(tlscfg, state, err)
	return tlsconn, err, &entry.TLSHandshake
}
