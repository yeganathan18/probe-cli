package nwebconnectivity

import (
	"context"
	"crypto/tls"
	"net/http"
	"net/url"
	"time"

	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/http3"
	"github.com/ooni/probe-cli/v3/internal/engine/model"
	"github.com/ooni/probe-cli/v3/internal/engine/netx"
)

// QUICConfig configures the QUIC handshake check.
type QUICConfig struct {
	Addr        string
	Dialer      netx.QUICDialer
	Measurement *model.Measurement
	SNIExample  bool
	URL         *url.URL
}

// quicHandshake performs the QUIC handshake
func quicHandshake(ctx context.Context, config *QUICConfig) (http.RoundTripper, error) {
	tlscfg := &tls.Config{
		ServerName: config.URL.Hostname(),
		NextProtos: []string{"h3"},
	}
	qcfg := &quic.Config{}
	qsess, err := config.Dialer.DialContext(ctx, "udp", config.Addr, tlscfg, qcfg)
	stop := time.Now()
	entry := makeTLSHandshakeEntry(config.Measurement.MeasurementStartTimeSaved, stop, TCPTLSExperimentTag, config.SNIExample)
	entry.setQUICHandshakeResult(tlscfg, qsess, err)
	tk := config.Measurement.TestKeys.(*TestKeys)
	tk.Lock()
	tk.TLSHandshakes = append(tk.TLSHandshakes, entry.TLSHandshake)
	tk.Unlock()
	if err != nil {
		return nil, err
	}
	return GetSingleH3Transport(qsess, tlscfg, qcfg), nil
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
