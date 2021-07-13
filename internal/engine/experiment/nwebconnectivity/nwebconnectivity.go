package nwebconnectivity

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/apex/log"
	"github.com/lucas-clemente/quic-go"
	"github.com/lucas-clemente/quic-go/http3"
	"github.com/ooni/probe-cli/v3/internal/engine/geolocate"
	"github.com/ooni/probe-cli/v3/internal/engine/httpheader"
	"github.com/ooni/probe-cli/v3/internal/engine/model"
	"github.com/ooni/probe-cli/v3/internal/engine/netx/archival"
	"github.com/ooni/probe-cli/v3/internal/engine/netx/trace"
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
	dialer     netxlite.Dialer
	handshaker netxlite.TLSHandshaker
	logger     netxlite.Logger
	quicDialer netxlite.QUICContextDialer
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
	logger := log.Log
	return &Measurer{
		Config:     config,
		dialer:     newDialer(logger),
		handshaker: newHandshaker(),
		logger:     logger,
		quicDialer: newQUICDialer(logger),
	}
}

func newHandshaker() netxlite.TLSHandshaker {
	return &errorsx.ErrorWrapperTLSHandshaker{TLSHandshaker: &netxlite.TLSHandshakerConfigurable{}}
}

func newDialer(logger netxlite.Logger) netxlite.Dialer {
	var d netxlite.Dialer
	d = &errorsx.ErrorWrapperDialer{Dialer: netxlite.DefaultDialer}
	d = &netxlite.DialerLogger{Dialer: d, Logger: logger}
	return d
}

func newQUICDialer(logger netxlite.Logger) netxlite.QUICContextDialer {
	ql := &errorsx.ErrorWrapperQUICListener{QUICListener: &netxlite.QUICListenerStdlib{}}
	var d netxlite.QUICContextDialer = &netxlite.QUICDialerQUICGo{QUICListener: ql}
	d = &errorsx.ErrorWrapperQUICDialer{Dialer: d}
	return d
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
	tk := new(TestKeys)
	measurement.TestKeys = tk
	URL, err := url.Parse(string(measurement.Input))
	if err != nil {
		return ErrInputIsNotAnURL
	}
	return m.runWithRedirect(measurement, ctx, URL, 0)
}

func (m *Measurer) runWithRedirect(
	measurement *model.Measurement,
	ctx context.Context,
	URL *url.URL,
	nRedirects int,
) error {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	if URL.Scheme != "http" && URL.Scheme != "https" {
		return ErrUnsupportedInput
	}

	// 1. perform DNS lookup
	addresses := m.dnsLookup(measurement, ctx, URL.Hostname())
	epnts := m.getEndpoints(addresses, URL.Scheme)

	var wg sync.WaitGroup
	fmt.Println(URL, len(epnts))
	redirects := make(chan *http.Response, len(epnts)+1)

	// 2. each IP address
	for _, ip := range epnts {
		// TODO discard ipv6?
		wg.Add(1)
		go m.measure(measurement, ctx, ip, URL, &wg, redirects)
	}
	wg.Wait()
	redirects <- nil

	resp := <-redirects
	if resp != nil {
		if nRedirects == 10 {
			return errors.New("stopped after 10 redirects")
		}
		loc, _ := resp.Location()
		return m.runWithRedirect(measurement, ctx, loc, nRedirects+1)
	}
	return nil

}

// dnsLookup finds the IP address(es) associated with a domain name
func (m *Measurer) dnsLookup(measurement *model.Measurement, ctx context.Context, hostname string) []string {
	resolver := &errorsx.ErrorWrapperResolver{Resolver: &netxlite.ResolverSystem{}}
	addrs, err := resolver.LookupHost(ctx, hostname)
	stop := time.Now()
	tk := measurement.TestKeys.(*TestKeys)
	for _, qtype := range []dnsQueryType{"A", "AAAA"} {
		entry := archival.DNSQueryEntry{
			Engine:          resolver.Network(),
			Failure:         archival.NewFailure(err),
			Hostname:        hostname,
			QueryType:       string(qtype),
			ResolverAddress: resolver.Address(),
			T:               stop.Sub(measurement.MeasurementStartTimeSaved).Seconds(),
		}
		for _, addr := range addrs {
			if qtype.ipoftype(addr) {
				entry.Answers = append(entry.Answers, qtype.makeanswerentry(addr))
			}
		}
		if len(entry.Answers) <= 0 && err == nil {
			continue
		}
		tk.Queries = append(tk.Queries, entry)
	}
	return addrs
}

func (m *Measurer) measure(
	measurement *model.Measurement,
	ctx context.Context,
	addr string,
	URL *url.URL,
	wg *sync.WaitGroup,
	redirects chan *http.Response,
) error {
	defer wg.Done()
	// connect
	conn := m.connect(measurement, ctx, addr)
	var transport http.RoundTripper
	switch URL.Scheme {
	case "http":
		transport = netxlite.NewHTTPTransport(&singleDialerHTTP1{conn: &conn}, nil, nil)
	case "https":
		// Handshake
		transport = m.tlsHandshake(measurement, ctx, conn, URL.Hostname())
	default:
		// This should not occur because we handle it before. But the check makes the function more robust.
		return errors.New("invalid scheme")
	}
	// HTTP roundtrip
	m.httpRoundtrip(ctx, URL, transport, redirects)

	// QUIC handshake
	transport = m.quicHandshake(measurement, ctx, addr, URL.Hostname())
	// HTTP/3 roundtrip
	m.httpRoundtrip(ctx, URL, transport, redirects)

	return nil
}

// connect performs the TCP three way handshake
func (m *Measurer) connect(measurement *model.Measurement, ctx context.Context, addr string) net.Conn {
	conn, err := m.dialer.DialContext(ctx, "tcp", addr)
	stop := time.Now()

	a, sport, _ := net.SplitHostPort(addr)
	iport, _ := strconv.Atoi(sport)
	entry := archival.TCPConnectEntry{
		IP:   a,
		Port: iport,
		Status: archival.TCPConnectStatus{
			Failure: archival.NewFailure(err),
			Success: err == nil,
		},
		T: stop.Sub(measurement.MeasurementStartTimeSaved).Seconds(),
	}
	tk := measurement.TestKeys.(*TestKeys)
	tk.TCPConnect = append(tk.TCPConnect, entry)
	return conn
}

// quicHandshake performs the QUIC handshake
func (m *Measurer) quicHandshake(measurement *model.Measurement, ctx context.Context, addr string, hostname string) http.RoundTripper {
	tlscfg := &tls.Config{
		ServerName: hostname,
		NextProtos: []string{"h3"},
	}
	qcfg := &quic.Config{}
	qsess, err := m.quicDialer.DialContext(ctx, "udp", addr, tlscfg, qcfg)
	stop := time.Now()
	if err != nil {
		entry := archival.TLSHandshake{
			Failure:     archival.NewFailure(err),
			NoTLSVerify: tlscfg.InsecureSkipVerify,
			ServerName:  tlscfg.ServerName,
			T:           stop.Sub(measurement.MeasurementStartTimeSaved).Seconds(),
		}
		tk := measurement.TestKeys.(*TestKeys)
		tk.TLSHandshakes = append(tk.TLSHandshakes, entry)
		return nil
	}
	state := qsess.ConnectionState().TLS.ConnectionState
	entry := archival.TLSHandshake{
		CipherSuite:        netxlite.TLSCipherSuiteString(state.CipherSuite),
		Failure:            archival.NewFailure(err),
		NegotiatedProtocol: state.NegotiatedProtocol,
		NoTLSVerify:        tlscfg.InsecureSkipVerify,
		PeerCertificates:   makePeerCerts(trace.PeerCerts(state, err)),
		ServerName:         tlscfg.ServerName,
		TLSVersion:         netxlite.TLSVersionString(state.Version),
		T:                  stop.Sub(measurement.MeasurementStartTimeSaved).Seconds(),
	}
	tk := measurement.TestKeys.(*TestKeys)
	tk.TLSHandshakes = append(tk.TLSHandshakes, entry)
	return m.getHTTP3Transport(qsess, tlscfg, &quic.Config{})
}

// tlsHandshake performs the TLS handshake
func (m *Measurer) tlsHandshake(measurement *model.Measurement, ctx context.Context, conn net.Conn, hostname string) http.RoundTripper {
	config := &tls.Config{
		ServerName: hostname,
		NextProtos: []string{"h2", "http/1.1"},
	}
	tlsconn, state, err := m.handshaker.Handshake(ctx, conn, config)
	stop := time.Now()

	if err != nil {
		entry := archival.TLSHandshake{
			Failure:     archival.NewFailure(err),
			NoTLSVerify: config.InsecureSkipVerify,
			ServerName:  config.ServerName,
			T:           stop.Sub(measurement.MeasurementStartTimeSaved).Seconds(),
		}
		tk := measurement.TestKeys.(*TestKeys)
		tk.TLSHandshakes = append(tk.TLSHandshakes, entry)
		return nil
	}
	entry := archival.TLSHandshake{
		CipherSuite:        netxlite.TLSCipherSuiteString(state.CipherSuite),
		Failure:            archival.NewFailure(err),
		NegotiatedProtocol: state.NegotiatedProtocol,
		NoTLSVerify:        config.InsecureSkipVerify,
		PeerCertificates:   makePeerCerts(trace.PeerCerts(state, err)),
		ServerName:         config.ServerName,
		TLSVersion:         netxlite.TLSVersionString(state.Version),
		T:                  stop.Sub(measurement.MeasurementStartTimeSaved).Seconds(),
	}
	tk := measurement.TestKeys.(*TestKeys)
	tk.TLSHandshakes = append(tk.TLSHandshakes, entry)
	return m.getTransport(state, tlsconn, config)
}

// httpRoundtrip constructs the HTTP request and HTTP client and performs the HTTP Roundtrip with the given transport
func (m *Measurer) httpRoundtrip(ctx context.Context, URL *url.URL, transport http.RoundTripper, redirects chan *http.Response) {
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
	if resp == nil {
		return
	}
	switch resp.StatusCode {
	case 301, 302, 303, 307, 308:
		redirects <- resp
	}
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
func (m *Measurer) getTransport(state tls.ConnectionState, conn net.Conn, config *tls.Config) http.RoundTripper {
	// ALPN ?
	switch state.NegotiatedProtocol {
	case "h2":
		// HTTP 2 + TLS.
		return m.getHTTP2Transport(conn, config)
	default:
		// assume HTTP 1.x + TLS.
		dialer := &singleDialerHTTP1{conn: &conn}
		return netxlite.NewHTTPTransport(dialer, config, m.handshaker)
	}
}

// getHTTP3Transport creates am http2.Transport
func (m *Measurer) getHTTP2Transport(conn net.Conn, config *tls.Config) (transport http.RoundTripper) {
	transport = &http2.Transport{
		DialTLS:            (&singleDialerH2{conn: &conn}).DialTLS,
		TLSClientConfig:    config,
		DisableCompression: true,
	}
	transport = &netxlite.HTTPTransportLogger{Logger: log.Log, HTTPTransport: transport.(*http2.Transport)}
	return transport
}

// getHTTP3Transport creates am http3.RoundTripper
func (m *Measurer) getHTTP3Transport(qsess quic.EarlySession, tlscfg *tls.Config, qcfg *quic.Config) *http3.RoundTripper {
	transport := &http3.RoundTripper{
		DisableCompression: true,
		TLSClientConfig:    tlscfg,
		QuicConfig:         qcfg,
		Dial:               (&singleDialerH3{qsess: &qsess}).Dial,
	}
	return transport
}

// getRequest gives us a new HTTP GET request
func (m *Measurer) getRequest(ctx context.Context, URL *url.URL) *http.Request {
	req, err := http.NewRequest("GET", URL.String(), nil)
	runtimex.PanicOnError(err, "http.NewRequest failed")
	req = req.WithContext(ctx)
	req.Header.Set("Accept", httpheader.Accept())
	req.Header.Set("Accept-Language", httpheader.AcceptLanguage())
	req.Host = URL.Hostname()
	return req
}

// TODO(kelmenhorst): this part is stolen from archival.
// decide: make archival functions public or repeat ourselves?
type dnsQueryType string

func (qtype dnsQueryType) ipoftype(addr string) bool {
	switch qtype {
	case "A":
		return !strings.Contains(addr, ":")
	case "AAAA":
		return strings.Contains(addr, ":")
	}
	return false
}

func (qtype dnsQueryType) makeanswerentry(addr string) archival.DNSAnswerEntry {
	answer := archival.DNSAnswerEntry{AnswerType: string(qtype)}
	asn, org, _ := geolocate.LookupASN(addr)
	answer.ASN = int64(asn)
	answer.ASOrgName = org
	switch qtype {
	case "A":
		answer.IPv4 = addr
	case "AAAA":
		answer.IPv6 = addr
	}
	return answer
}

func makePeerCerts(in []*x509.Certificate) (out []archival.MaybeBinaryValue) {
	for _, e := range in {
		out = append(out, archival.MaybeBinaryValue{Value: string(e.Raw)})
	}
	return
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
