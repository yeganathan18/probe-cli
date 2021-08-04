package nwebconnectivity

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"time"

	"github.com/apex/log"
	"github.com/ooni/probe-cli/v3/internal/engine/model"
	"github.com/ooni/probe-cli/v3/internal/netxlite"
	"golang.org/x/net/http2"
)

type TLSHandshakeConfig struct {
	Conn        net.Conn
	Client      string
	Handshaker  netxlite.TLSHandshaker
	Measurement *model.Measurement
	SNIExample  bool
	TLSConf     *tls.Config
}

// tlsHandshake performs the TLS handshake
// func (m *Measurer) tlsHandshake(measurement *model.Measurement, ctx context.Context, conn net.Conn, config *tls.Config, snitest bool) (http.RoundTripper, error) {
func tlsHandshake(ctx context.Context, config *TLSHandshakeConfig) (http.RoundTripper, error) {
	tlsconn, state, err := config.Handshaker.Handshake(ctx, config.Conn, config.TLSConf)
	stop := time.Now()

	entry := makeTLSHandshakeEntry(config.Measurement.MeasurementStartTimeSaved, stop, TCPTLSExperimentTag, config.SNIExample)
	entry.setHandshakeResult(config.TLSConf, state, err)
	entry.Fingerprint = config.Client
	tk := config.Measurement.TestKeys.(*TestKeys)
	tk.Lock()
	tk.TLSHandshakes = append(tk.TLSHandshakes, entry.TLSHandshake)
	tk.Unlock()
	if err != nil {
		return nil, err
	}
	return GetSingleTransport(&state, tlsconn, config.TLSConf), nil
}

// getTransport determines the appropriate HTTP Transport from the ALPN
func GetSingleTransport(state *tls.ConnectionState, conn net.Conn, config *tls.Config) http.RoundTripper {
	if state == nil {
		return netxlite.NewHTTPTransport(&SingleDialerHTTP1{conn: &conn}, nil, nil)
	}
	// ALPN ?
	switch state.NegotiatedProtocol {
	case "h2":
		// HTTP 2 + TLS.
		return getHTTP2Transport(conn, config)
	default:
		// assume HTTP 1.x + TLS.
		return getHTTPTransport(conn, config)
	}
}

// getHTTPTransport creates an http.Transport
func getHTTPTransport(conn net.Conn, config *tls.Config) (transport http.RoundTripper) {
	transport = &http.Transport{
		DialContext:        (&SingleDialerHTTP1{conn: &conn}).DialContext,
		DialTLSContext:     (&SingleDialerHTTP1{conn: &conn}).DialContext,
		TLSClientConfig:    config,
		DisableCompression: true,
	}
	transport = &netxlite.HTTPTransportLogger{Logger: log.Log, HTTPTransport: transport.(*http.Transport)}
	return transport
}

// getHTTP2Transport creates an http2.Transport
func getHTTP2Transport(conn net.Conn, config *tls.Config) (transport http.RoundTripper) {
	transport = &http2.Transport{
		DialTLS:            (&SingleDialerH2{conn: &conn}).DialTLS,
		TLSClientConfig:    config,
		DisableCompression: true,
	}
	transport = &netxlite.HTTPTransportLogger{Logger: log.Log, HTTPTransport: transport.(*http2.Transport)}
	return transport
}
