package internal

import (
	"context"
	"crypto/tls"
	"errors"
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

	CtrlURLMeasurement = nwebconnectivity.ControlURL

	CtrlEndpointMeasurement = nwebconnectivity.ControlEndpoint

	CtrlHTTPMeasurement = nwebconnectivity.ControlHTTP

	CtrlH3Measurement = nwebconnectivity.ControlH3

	CtrlTLSMeasurement = nwebconnectivity.ControlTLSHandshake

	CtrlHTTPRequest = nwebconnectivity.ControlHTTPRequest
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

func Measure(ctx context.Context, config MeasureConfig, creq *CtrlRequest) (*CtrlResponse, error) {
	var cresp = CtrlResponse{URLMeasurements: []*CtrlURLMeasurement{}}
	redirectch := make(chan *RedirectInfo, 20)
	nRedirects := 0

	urlM, _ := MeasureURL(ctx, config, creq, redirectch)
	cresp.URLMeasurements = append(cresp.URLMeasurements, urlM)

	redirected := make(map[string]bool, 21)
	rdrctreqs := reduceRedirects(redirectch, redirected)

	for len(rdrctreqs) > nRedirects {
		req := rdrctreqs[nRedirects]
		if nRedirects == 20 {
			// we stop after 20 redirects, as do Chrome and Firefox, TODO(kelmenhorst): how do we test this?
			// TODO(kelmenhorst): do we need another entry indicating the redirect failure here?
			break
		}
		nRedirects += 1
		redirectch = make(chan *RedirectInfo, 20)
		urlM, _ = MeasureURL(ctx, config, req, redirectch)
		cresp.URLMeasurements = append(cresp.URLMeasurements, urlM)
		rdrctreqs = append(rdrctreqs, reduceRedirects(redirectch, redirected)...)
	}
	return &cresp, nil
}

func reduceRedirects(redirectch chan *RedirectInfo, redirected map[string]bool) []*CtrlRequest {
	out := []*CtrlRequest{}
	for rdrct := range redirectch {
		if _, ok := redirected[rdrct.Location.String()]; ok {
			continue
		}
		redirected[rdrct.Location.String()] = true
		req := &CtrlRequest{HTTPRequest: rdrct.Location.String(), TCPConnect: []string{}, HTTPRequestHeaders: rdrct.Req.Header}
		out = append(out, req)
	}
	return out
}

// Measure performs the measurement described by the request and
// returns the corresponding response or an error.
func MeasureURL(ctx context.Context, config MeasureConfig, creq *CtrlRequest, redirectch chan *RedirectInfo) (*CtrlURLMeasurement, error) {
	defer close(redirectch)
	// parse input for correctness
	URL, err := url.Parse(creq.HTTPRequest)
	if err != nil {
		return nil, err
	}

	// create URLMeasurement struct
	urlMeasurement := &CtrlURLMeasurement{
		URL:       URL.String(),
		DNS:       nil,
		Endpoints: []CtrlEndpointMeasurement{},
	}

	// dns: start
	dns := DNSDo(ctx, &DNSConfig{
		Domain:   URL.Hostname(),
		Resolver: config.Resolver,
	})

	urlMeasurement.DNS = &dns

	enpnts := getEndpoints(dns.Addrs, URL)
	addrs := mergeEndpoints(enpnts, creq.TCPConnect)

	if len(addrs) == 0 {
		return urlMeasurement, errors.New("no valid IP address to measure")
	}

	wg := new(sync.WaitGroup)
	for _, endpoint := range enpnts {
		var endpointMeasurement CtrlEndpointMeasurement = &nwebconnectivity.ControlHTTP{Endpoint: endpoint, Protocol: URL.Scheme}
		wg.Add(1)
		go measureHTTP(ctx, config, creq, endpoint, endpointMeasurement.(*CtrlHTTPMeasurement), wg, redirectch)
		urlMeasurement.Endpoints = append(urlMeasurement.Endpoints, endpointMeasurement)
	}
	wg.Wait()
	return urlMeasurement, nil
}

func measureHTTP(
	ctx context.Context,
	config MeasureConfig,
	creq *CtrlRequest,
	endpoint string,
	httpMeasurement *CtrlHTTPMeasurement,
	wg *sync.WaitGroup,
	redirectch chan *RedirectInfo,
) {
	defer wg.Done()
	var conn net.Conn
	conn, httpMeasurement.TCPConnect = TCPDo(ctx, &TCPConfig{
		Dialer:   config.Dialer,
		Endpoint: endpoint,
	})
	if conn == nil {
		return
	}

	URL, _ := url.Parse(creq.HTTPRequest)
	switch URL.Scheme {
	case "http":
		config.Client.Transport = nwebconnectivity.GetSingleTransport(nil, conn, nil)
	case "https":
		var tlsconn *tls.Conn
		cfg := &tls.Config{ServerName: URL.Hostname()}
		tlsconn, httpMeasurement.TLSHandshake = TLSDo(ctx, &TLSConfig{
			Conn:     conn,
			Endpoint: endpoint,
			Cfg:      cfg,
		})
		if tlsconn == nil {
			return
		}
		state := tlsconn.ConnectionState()
		config.Client.Transport = nwebconnectivity.GetSingleTransport(&state, tlsconn, cfg)
	}
	httpMeasurement.HTTPRequest = HTTPDo(ctx, &HTTPConfig{
		Client:            config.Client,
		Headers:           creq.HTTPRequestHeaders,
		MaxAcceptableBody: config.MaxAcceptableBody,
		URL:               creq.HTTPRequest,
	}, redirectch)
	conn.Close()
}

func measureH3(
	ctx context.Context,
	config MeasureConfig,
	creq *CtrlRequest,
	endpoint string,
	h3Measurement *CtrlH3Measurement,
	wg *sync.WaitGroup,
	redirectch chan *RedirectInfo,
) {
	defer wg.Done()
	var sess quic.EarlySession
	tlscfg := &tls.Config{}
	qcfg := &quic.Config{}
	sess, h3Measurement.QUICHandshake = QUICDo(ctx, &QUICConfig{
		Dialer:    config.QuicDialer,
		Endpoint:  endpoint,
		QConfig:   qcfg,
		TLSConfig: tlscfg,
	})
	transport := nwebconnectivity.GetSingleH3Transport(sess, tlscfg, qcfg)
	config.Client.Transport = transport
	h3Measurement.HTTPRequest = HTTPDo(ctx, &HTTPConfig{
		Client:            config.Client,
		Headers:           creq.HTTPRequestHeaders,
		MaxAcceptableBody: config.MaxAcceptableBody,
		URL:               creq.HTTPRequest,
	}, redirectch)

}

func mergeEndpoints(addrs []string, clientAddrs []string) []string {
	appendIfUnique := func(slice []string, item string) []string {
		for _, i := range slice {
			if i == item {
				return slice
			}
		}
		return append(slice, item)
	}
	for _, c := range clientAddrs {
		addrs = appendIfUnique(addrs, c)
	}
	return addrs
}

// getEndpoints connects IP addresses with the port associated with the URL scheme
func getEndpoints(addrs []string, URL *url.URL) []string {
	out := []string{}
	if URL.Scheme != "http" && URL.Scheme != "https" {
		panic("passed an unexpected scheme")
	}
	p := URL.Port()
	for _, a := range addrs {
		var port string
		switch true {
		case p != "":
			// explicit port
			port = p
		case URL.Scheme == "http":
			port = "80"
		case URL.Scheme == "https":
			port = "443"
		}
		endpoint := net.JoinHostPort(a, port)
		out = append(out, endpoint)
	}
	return out
}
