package nwebconnectivity

import (
	"context"
	"crypto/tls"
	"time"

	"github.com/apex/log"
	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/http3"
	"github.com/ooni/probe-cli/v3/internal/engine/model"
	"github.com/ooni/probe-cli/v3/internal/engine/netx/archival"
)

// quicHandshake performs the QUIC handshake
func quicHandshake(ctx context.Context, measurement *model.Measurement, loc *nextLocationInfo, tlscfg *tls.Config, qcfg *quic.Config, endpoint string) (quic.EarlySession, *archival.TLSHandshake) {
	dialer := newQUICDialer(log.Log)
	qsess, err := dialer.DialContext(ctx, "udp", endpoint, tlscfg, qcfg)
	stop := time.Now()
	entry := makeTLSHandshakeEntry(measurement.MeasurementStartTimeSaved, stop, TCPTLSExperimentTag)
	entry.setQUICHandshakeResult(tlscfg, qsess, err)
	return qsess, &entry.TLSHandshake
}

// getHTTP3Transport creates am http3.RoundTripper
func GetSingleH3Transport(qsess quic.EarlySession, tlscfg *tls.Config, qcfg *quic.Config) *http3.RoundTripper {
	transport := &http3.RoundTripper{
		DisableCompression: true,
		TLSClientConfig:    tlscfg,
		QuicConfig:         qcfg,
		Dial:               (&SingleDialerH3{qsess: &qsess}).Dial,
	}
	return transport
}
