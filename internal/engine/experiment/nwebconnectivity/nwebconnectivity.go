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
	"github.com/ooni/probe-cli/v3/internal/engine/experiment/webconnectivity"
	"github.com/ooni/probe-cli/v3/internal/engine/httpheader"
	"github.com/ooni/probe-cli/v3/internal/engine/model"
	"github.com/ooni/probe-cli/v3/internal/engine/netx"
	"github.com/ooni/probe-cli/v3/internal/engine/netx/archival"
	"github.com/ooni/probe-cli/v3/internal/netxlite"
	"github.com/ooni/probe-cli/v3/internal/runtimex"
	"golang.org/x/net/http2"
)

// Config contains the experiment config.
type Config struct{}

// Measurer performs the measurement.
type Measurer struct {
	Config     Config
	Dialer     netx.Dialer
	TLSDialer  netx.TLSDialer
	QUICDialer netx.QUICDialer
}

type SingleDialer struct {
	conn  *net.Conn
	qsess *quic.EarlySession
}

func (s *SingleDialer) getConn(network string, addr string) (net.Conn, error) {
	if s.conn != nil {
		c := s.conn
		s.conn = nil
		return *c, nil
	}
	return nil, errors.New("cannot reuse connection")
}

func (s *SingleDialer) getTLSConn(network string, addr string, cfg *tls.Config) (net.Conn, error) {
	if s.conn != nil {
		c := s.conn
		s.conn = nil
		return *c, nil
	}
	return nil, errors.New("cannot reuse connection")
}

func (s *SingleDialer) getQUICSess(network, addr string, tlsCfg *tls.Config, cfg *quic.Config) (quic.EarlySession, error) {
	if s.qsess != nil {
		qs := s.qsess
		s.qsess = nil
		return *qs, nil
	}
	return nil, errors.New("cannot reuse session")
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
		Dialer:     netx.NewDialer(nConf),
		TLSDialer:  netx.NewTLSDialer(nConf),
		QUICDialer: netx.NewQUICDialer(nConf),
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
		return errors.New("invalid scheme")
	}

	// // roundtrip
	resp, err := m.httpRoundtrip(ctx, URL, transport)
	if err != nil {
		fmt.Println(err)
		return err
	}
	switch resp.StatusCode {
	case 301, 302, 303, 307, 308:
		redirects <- resp
		return errors.New("redirect")
	}
	fmt.Println("HTTP response", resp.StatusCode)

	transport, err = m.quicHandshake(ctx, addr, URL.Hostname())
	resp, err = m.httpRoundtrip(ctx, URL, transport)
	if err != nil {
		fmt.Println(err)
		return err
	}
	switch resp.StatusCode {
	case 301, 302, 303, 307, 308:
		redirects <- resp
		return errors.New("redirect QUIC")
	}
	fmt.Println("HTTP/3 response", resp.StatusCode)

	return nil
}

// httpRoundtrip constructs the HTTP request and HTTP client and performs the HTTP Roundtrip with the given transport
func (m *Measurer) httpRoundtrip(ctx context.Context, URL *url.URL, transport http.RoundTripper) (*http.Response, error) {
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
	return httpClient.Do(req)
}

func (m *Measurer) quicHandshake(ctx context.Context, addr string, hostname string) (http.RoundTripper, error) {
	tlscfg := &tls.Config{
		ServerName: hostname,
		NextProtos: []string{"h3"},
	}
	qcfg := &quic.Config{}
	qsess, err := m.QUICDialer.DialContext(ctx, "udp", addr, tlscfg, qcfg)
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
	handshaker := m.TLSDialer.(*netxlite.TLSDialer).TLSHandshaker
	tlsconn, state, err := handshaker.Handshake(ctx, conn, config)
	if err != nil {
		return nil, err
	}
	return m.getTransport(state, tlsconn, config), nil
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

func (m *Measurer) connect(ctx context.Context, addr string) (net.Conn, error) {
	return m.Dialer.DialContext(ctx, "tcp", addr)
}

// Run implements ExperimentMeasurer.Run.
func (m *Measurer) Run(
	ctx context.Context,
	sess model.ExperimentSession,
	measurement *model.Measurement,
	callbacks model.ExperimentCallbacks,
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
	dnsResult := webconnectivity.DNSLookup(ctx, webconnectivity.DNSLookupConfig{
		Begin:   measurement.MeasurementStartTimeSaved,
		Session: sess, URL: URL})
	epnts := webconnectivity.NewEndpoints(URL, dnsResult.Addresses()).Endpoints()

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
		loc, _ := resp.Location()
		measurement.Input = model.MeasurementTarget(loc.String())
		return m.Run(ctx, sess, measurement, callbacks)
	}
	return nil

}

func (m *Measurer) getHTTP1Transport(conn net.Conn) *http.Transport {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DisableCompression = true
	transport.Dial = (&SingleDialer{conn: &conn}).getConn
	return transport
}

func (m *Measurer) getHTTP2Transport(conn net.Conn, config *tls.Config) *http2.Transport {
	transport := &http2.Transport{
		DialTLS:            (&SingleDialer{conn: &conn}).getTLSConn,
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
		Dial:               (&SingleDialer{qsess: &qsess}).getQUICSess,
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
