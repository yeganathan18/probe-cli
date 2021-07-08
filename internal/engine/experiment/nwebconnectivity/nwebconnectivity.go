package nwebconnectivity

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"sync"
	"time"

	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/http3"
	"github.com/ooni/probe-cli/v3/internal/engine/httpheader"
	"github.com/ooni/probe-cli/v3/internal/engine/model"
	"github.com/ooni/probe-cli/v3/internal/engine/netx"
	"github.com/ooni/probe-cli/v3/internal/engine/netx/archival"
	"github.com/ooni/probe-cli/v3/internal/errorsx"
	"github.com/ooni/probe-cli/v3/internal/netxlite"
	"github.com/ooni/probe-cli/v3/internal/runtimex"
	"golang.org/x/net/http2"
)

// Config contains the experiment config.
type Config struct{}

// Measurer performs the measurement.
type Measurer struct {
	Config     Config
	dialer     netx.Dialer
	tlsDialer  netx.TLSDialer
	quicDialer netx.QUICDialer
}

// TestKeys contains webconnectivity test keys.
type TestKeys struct {
	Agent          string  `json:"agent"`
	ClientResolver string  `json:"client_resolver"`
	Retries        *int64  `json:"retries"`    // unused
	SOCKSProxy     *string `json:"socksproxy"` // unused

	// For now mostly TCP/TLS "connect" experiment but we are
	// considering adding more events. An open question is
	// currently how to properly tag these events so that it
	// is rather obvious where they come from.
	//
	// See https://github.com/ooni/probe/issues/1413.
	NetworkEvents []archival.NetworkEvent `json:"network_events"`
	TLSHandshakes []archival.TLSHandshake `json:"tls_handshakes"`

	// DNS experiment
	Queries              []archival.DNSQueryEntry `json:"queries"`
	DNSExperimentFailure *string                  `json:"dns_experiment_failure"`

	// Control experiment
	ControlFailure *string `json:"control_failure"`

	// TCP/TLS "connect" experiment
	TCPConnect          []archival.TCPConnectEntry `json:"tcp_connect"`
	TCPConnectSuccesses int                        `json:"-"`
	TCPConnectAttempts  int                        `json:"-"`

	// HTTP experiment
	Requests              []archival.RequestEntry `json:"requests"`
	HTTPExperimentFailure *string                 `json:"http_experiment_failure"`
}

// NewExperimentMeasurer creates a new ExperimentMeasurer.
func NewExperimentMeasurer(config Config) model.ExperimentMeasurer {
	nConf := netx.Config{}
	return &Measurer{
		Config:     config,
		dialer:     netx.NewDialer(nConf),
		tlsDialer:  netx.NewTLSDialer(nConf),
		quicDialer: netx.NewQUICDialer(nConf),
	}
}

// ExperimentName implements ExperimentMeasurer.ExperExperimentName.
func (m *Measurer) ExperimentName() string {
	return "new_webconnectivity"
}

// ExperimentVersion implements ExperimentMeasurer.ExperExperimentVersion.
func (m *Measurer) ExperimentVersion() string {
	return "0.1.0"
}

var (
	// ErrNoAvailableTestHelpers is emitted when there are no available test helpers.
	ErrNoAvailableTestHelpers = errors.New("no available helpers")

	// ErrNoInput indicates that no input was provided
	ErrNoInput = errors.New("no input provided")

	// ErrInputIsNotAnURL indicates that the input is not an URL.
	ErrInputIsNotAnURL = errors.New("input is not an URL")

	// ErrUnsupportedInput indicates that the input URL scheme is unsupported.
	ErrUnsupportedInput = errors.New("unsupported input scheme")
)

// Run implements ExperimentMeasurer.Run.
func (m *Measurer) Run(
	ctx context.Context,
	sess model.ExperimentSession,
	measurement *model.Measurement,
	callbacks model.ExperimentCallbacks,
) error {
	return m.runWithRedirect(ctx, sess, measurement, callbacks, 0)
}

func (m *Measurer) runWithRedirect(
	ctx context.Context,
	sess model.ExperimentSession,
	measurement *model.Measurement,
	callbacks model.ExperimentCallbacks,
	nRedirects int,
) error {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	URL, err := url.Parse(string(measurement.Input))
	if err != nil {
		return ErrInputIsNotAnURL
	}
	if URL.Scheme != "http" && URL.Scheme != "https" {
		return ErrUnsupportedInput
	}
	// 1. perform DNS lookup
	addresses, err := m.dnsLookup(ctx, URL.Hostname())
	if err != nil {
		return err
	}
	epnts := m.getEndpoints(addresses, URL.Scheme)

	var wg sync.WaitGroup
	fmt.Println(URL, len(epnts))
	redirects := make(chan *http.Response, len(epnts)+1)

	// 2. each IP address
	for _, ip := range epnts {
		// TODO discard ipv6?
		wg.Add(1)
		go m.measure(ctx, ip, URL, &wg, redirects)
	}
	wg.Wait()
	redirects <- nil

	resp := <-redirects
	if resp != nil {
		if nRedirects == 10 {
			return errors.New("stopped after 10 redirects")
		}
		loc, _ := resp.Location()
		measurement.Input = model.MeasurementTarget(loc.String())
		return m.runWithRedirect(ctx, sess, measurement, callbacks, nRedirects+1)
	}
	return nil

}

func (m *Measurer) measure(
	ctx context.Context,
	addr string,
	URL *url.URL,
	wg *sync.WaitGroup,
	redirects chan *http.Response,
) error {
	defer wg.Done()
	// connect
	conn, err := m.connect(ctx, addr)
	if err != nil {
		fmt.Println(err)
		return err
	}
	var transport http.RoundTripper
	switch URL.Scheme {
	case "http":
		transport = m.getHTTP1Transport(conn)
	case "https":
		// Handshake
		transport, err = m.tlsHandshake(ctx, conn, URL.Hostname())
		if err != nil {
			fmt.Println(err)
			return err
		}
	default:
		// This should not occur because we handle it before. But the check makes the function more robust.
		return errors.New("invalid scheme")
	}

	// HTTP roundtrip
	resp, err := m.httpRoundtrip(ctx, URL, transport, redirects)
	if err != nil {
		fmt.Println(err)
		return err
	}
	fmt.Println("HTTP response", resp.StatusCode)

	// QUIC handshake
	transport, err = m.quicHandshake(ctx, addr, URL.Hostname())
	if err != nil {
		fmt.Println(err)
		return err
	}
	// HTTP/3 roundtrip
	resp, err = m.httpRoundtrip(ctx, URL, transport, redirects)
	if err != nil {
		fmt.Println(err)
		return err
	}
	fmt.Println("HTTP/3 response", resp.StatusCode)

	return nil
}

// httpRoundtrip constructs the HTTP request and HTTP client and performs the HTTP Roundtrip with the given transport
func (m *Measurer) httpRoundtrip(ctx context.Context, URL *url.URL, transport http.RoundTripper, redirects chan *http.Response) (*http.Response, error) {
	req := m.getRequest(ctx, URL)
	jar, err := cookiejar.New(nil)
	runtimex.PanicOnError(err, "cookiejar.New failed")
	httpClient := &http.Client{
		Jar:       jar,
		Transport: transport,
	}
	httpClient.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	defer httpClient.CloseIdleConnections()
	resp, err := httpClient.Do(req)
	if resp != nil {
		switch resp.StatusCode {
		case 301, 302, 303, 307, 308:
			redirects <- resp
			return nil, errors.New("redirect QUIC")
		}
	}
	return resp, err
}

// quicHandshake performs the QUIC handshake
func (m *Measurer) quicHandshake(ctx context.Context, addr string, hostname string) (http.RoundTripper, error) {
	tlscfg := &tls.Config{
		ServerName: hostname,
		NextProtos: []string{"h3"},
	}
	qcfg := &quic.Config{}
	qsess, err := m.quicDialer.DialContext(ctx, "udp", addr, tlscfg, qcfg)
	if err != nil {
		return nil, err
	}
	return m.getTransport(qsess.ConnectionState().TLS.ConnectionState, qsess, tlscfg), nil
}

// tlsHandshake performs the TLS handshake
func (m *Measurer) tlsHandshake(ctx context.Context, conn net.Conn, hostname string) (http.RoundTripper, error) {
	config := &tls.Config{
		ServerName: hostname,
		NextProtos: []string{"h2", "http/1.1"},
	}
	handshaker := m.tlsDialer.(*netxlite.TLSDialer).TLSHandshaker
	tlsconn, state, err := handshaker.Handshake(ctx, conn, config)
	if err != nil {
		return nil, err
	}
	return m.getTransport(state, tlsconn, config), nil
}

// connect performs the TCP three way handshake
func (m *Measurer) connect(ctx context.Context, addr string) (net.Conn, error) {
	return m.dialer.DialContext(ctx, "tcp", addr)
}

// dnsLookup finds the IP address(es) associated with a domain name
func (m *Measurer) dnsLookup(ctx context.Context, hostname string) (addrs []string, err error) {
	resolver := &errorsx.ErrorWrapperResolver{Resolver: &netxlite.ResolverSystem{}}
	return resolver.LookupHost(ctx, hostname)
}

// getEndpoints connects IP addresses with the port associated with the URL scheme
func (m *Measurer) getEndpoints(addrs []string, scheme string) []string {
	out := []string{}
	if scheme != "http" && scheme != "https" {
		panic("passed an unexpected scheme")
	}
	for _, a := range addrs {
		var port string
		switch scheme {
		case "http":
			port = "80"
		case "https":
			port = "443"
		}
		endpoint := net.JoinHostPort(a, port)
		out = append(out, endpoint)
	}
	return out
}

// getTransport determines the appropriate HTTP Transport from the ALPN
func (m *Measurer) getTransport(state tls.ConnectionState, connsess interface{}, config *tls.Config) http.RoundTripper {
	// ALPN ?
	switch state.NegotiatedProtocol {
	case "h3":
		return m.getHTTP3Transport(connsess.(quic.EarlySession), config, &quic.Config{})
	case "h2":
		// HTTP 2 + TLS.
		return m.getHTTP2Transport(connsess.(net.Conn), config)
	default:
		// assume HTTP 1.x + TLS.
		return m.getHTTP1Transport(connsess.(net.Conn))
	}
}

func (m *Measurer) getHTTP1Transport(conn net.Conn) *http.Transport {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DisableCompression = true
	transport.Dial = (&singleDialerHTTP1{conn: &conn}).getConn
	return transport
}

func (m *Measurer) getHTTP2Transport(conn net.Conn, config *tls.Config) *http2.Transport {
	transport := &http2.Transport{
		DialTLS:            (&singleDialerH2{conn: &conn}).getTLSConn,
		TLSClientConfig:    config,
		DisableCompression: true,
	}
	return transport
}

func (m *Measurer) getHTTP3Transport(qsess quic.EarlySession, tlscfg *tls.Config, qcfg *quic.Config) *http3.RoundTripper {
	transport := &http3.RoundTripper{
		DisableCompression: true,
		TLSClientConfig:    tlscfg,
		QuicConfig:         qcfg,
		Dial:               (&singleDialerH3{qsess: &qsess}).getQUICSess,
	}
	return transport
}

func (m *Measurer) getRequest(ctx context.Context, URL *url.URL) *http.Request {
	req, err := http.NewRequest("GET", URL.String(), nil)
	runtimex.PanicOnError(err, "http.NewRequest failed")
	req = req.WithContext(ctx)
	req.Header.Set("Accept", httpheader.Accept())
	req.Header.Set("Accept-Language", httpheader.AcceptLanguage())
	req.Host = URL.Hostname()
	return req
}

// SummaryKeys contains summary keys for this experiment.
//
// Note that this structure is part of the ABI contract with probe-cli
// therefore we should be careful when changing it.
type SummaryKeys struct {
	Accessible bool   `json:"accessible"`
	Blocking   string `json:"blocking"`
	IsAnomaly  bool   `json:"-"`
}

// GetSummaryKeys implements model.ExperimentMeasurer.GetSummaryKeys.
func (m *Measurer) GetSummaryKeys(measurement *model.Measurement) (interface{}, error) {
	sk := SummaryKeys{IsAnomaly: false}
	return sk, nil
}
