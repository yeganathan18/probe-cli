package internal

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/url"
	"sync"

	"github.com/lucas-clemente/quic-go"
	"github.com/ooni/probe-cli/v3/internal/engine/experiment/nwebconnectivity"
	"github.com/ooni/probe-cli/v3/internal/engine/netx"
)

type (
	// CtrlRequest is the request sent to the test helper
	CtrlRequest = nwebconnectivity.ControlRequest

	// CtrlResponse is the response from the test helper
	CtrlResponse = nwebconnectivity.ControlResponse
)

// MeasureConfig contains configuration for Measure.
type MeasureConfig struct {
	Client            *http.Client
	Dialer            netx.Dialer
	H3Client          *http.Client
	MaxAcceptableBody int64
	QuicDialer        netx.QUICDialer
	Resolver          netx.Resolver
}

// Measure performs the measurement described by the request and
// returns the corresponding response or an error.
func Measure(ctx context.Context, config MeasureConfig, creq *CtrlRequest) (*CtrlResponse, error) {
	// parse input for correctness
	URL, err := url.Parse(creq.HTTPRequest)
	if err != nil {
		return nil, err
	}
	// dns: start
	wg := new(sync.WaitGroup)
	dnsch := make(chan CtrlDNSResult, 1)
	if net.ParseIP(URL.Hostname()) == nil {
		wg.Add(1)
		go DNSDo(ctx, &DNSConfig{
			Domain:   URL.Hostname(),
			Out:      dnsch,
			Resolver: config.Resolver,
			Wg:       wg,
		})
	}
	// tcpconnect: start
	tcpconnch := make(chan TCPResultPair, len(creq.TCPConnect))
	for _, endpoint := range creq.TCPConnect {
		wg.Add(1)
		go TCPDo(ctx, &TCPConfig{
			Dialer:   config.Dialer,
			Endpoint: endpoint,
			Out:      tcpconnch,
			Wg:       wg,
		})
	}
	// http: start
	httpch := make(chan CtrlHTTPResponse, 1)
	wg.Add(1)
	go HTTPDo(ctx, &HTTPConfig{
		Client:            config.Client,
		Headers:           creq.HTTPRequestHeaders,
		MaxAcceptableBody: config.MaxAcceptableBody,
		Out:               httpch,
		URL:               creq.HTTPRequest,
		Wg:                wg,
	})
	// wait for measurement steps to complete
	wg.Wait()
	// assemble response
	cresp := new(CtrlResponse)
	select {
	case cresp.DNS = <-dnsch:
	default:
		// we land here when there's no domain name
	}
	cresp.HTTPRequest = <-httpch
	cresp.TCPConnect = make(map[string]CtrlTCPResult)
	for len(cresp.TCPConnect) < len(creq.TCPConnect) {
		tcpconn := <-tcpconnch
		cresp.TCPConnect[tcpconn.Endpoint] = tcpconn.Result
	}
	if !discoverH3Server(cresp.HTTPRequest, URL) {
		return cresp, nil
	}
	// quichandshake: start
	quicch := make(chan QUICResultPair, len(creq.QUICHandshake))
	for _, endpoint := range creq.QUICHandshake {
		wg.Add(1)
		go QUICDo(ctx, &QUICConfig{
			Dialer:    config.QuicDialer,
			Endpoint:  endpoint,
			Out:       quicch,
			Wg:        wg,
			QConfig:   &quic.Config{},
			TLSConfig: &tls.Config{},
		})
	}
	// http3: start
	http3ch := make(chan CtrlHTTPResponse, 1)
	wg.Add(1)
	go HTTPDo(ctx, &HTTPConfig{
		Client:            config.H3Client,
		Headers:           creq.HTTPRequestHeaders,
		MaxAcceptableBody: config.MaxAcceptableBody,
		Out:               http3ch,
		URL:               creq.HTTPRequest,
		Wg:                wg,
	})
	cresp.HTTP3Request = <-http3ch
	cresp.QUICHandshake = make(map[string]CtrlQUICResult)
	for len(cresp.QUICHandshake) < len(creq.QUICHandshake) {
		quichandshake := <-quicch
		cresp.QUICHandshake[quichandshake.Endpoint] = quichandshake.Result
	}
	return cresp, nil
}
