package nwebconnectivity

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"

	"github.com/lucas-clemente/quic-go"
	"github.com/ooni/probe-cli/v3/internal/engine/httpheader"
	"github.com/ooni/probe-cli/v3/internal/engine/model"
	"github.com/ooni/probe-cli/v3/internal/engine/netx/archival"
	"github.com/ooni/probe-cli/v3/internal/errorsx"
	"github.com/ooni/probe-cli/v3/internal/netxlite"
	utls "gitlab.com/yawning/utls.git"
)

// Conig contains the experiment config.
type Config struct {
	ClientHello string `ooni:"Use ClientHello of specific client for parroting."`
}

// Measurer performs the measurement.
type Measurer struct {
	Config            Config
	dialer            netxlite.Dialer
	fingerprintClient string
	handshaker        netxlite.TLSHandshaker
	logger            netxlite.Logger
	quicDialer        netxlite.QUICContextDialer
}

// TestKeys contains webconnectivity test keys.
type TestKeys struct {
	sync.Mutex
	Agent          string `json:"agent"`
	ClientResolver string `json:"client_resolver"`

	URLMeasurements map[string]*URLMeasurement

	// Control experiment
	ControlFailure *string         `json:"control_failure"`
	ControlRequest ControlRequest  `json:"-"`
	Control        ControlResponse `json:"control"`

	// TCP/TLS "connect" experiment
	TCPConnect          []archival.TCPConnectEntry `json:"tcp_connect"`
	TCPConnectSuccesses int                        `json:"-"`
	TCPConnectAttempts  int                        `json:"-"`

	// HTTP experiment
	Requests              []archival.RequestEntry `json:"requests"`
	HTTPExperimentFailure *string                 `json:"http_experiment_failure"`
}

// Tags describing the section of this experiment in which
// the data has been collected.
const (
	// TCPTLSExperimentTag is a tag indicating the TCP connect experiment.
	TCPTLSExperimentTag = "tcptls_experiment"

	// QUICTLSExperimentTag is a tag indicating the QUIC handshake experiment.
	QUICTLSExperimentTag = "quictls_experiment"
)

// NewExperimentMeasurer creates a new ExperimentMeasurer.
func NewExperimentMeasurer(config Config) model.ExperimentMeasurer {
	return &Measurer{
		Config: config,
	}
}

func getClientHelloID(stringHelloID string) (utlsID *utls.ClientHelloID) {
	switch strings.ToLower(stringHelloID) {
	case "firefox":
		return &utls.HelloFirefox_Auto
	case "chrome":
		return &utls.HelloChrome_Auto
	case "ios":
		return &utls.HelloIOS_Auto
	case "golang":
		return &utls.HelloGolang
	}
	return nil
}

func newHandshaker(clientHello *utls.ClientHelloID) netxlite.TLSHandshaker {
	var h netxlite.TLSHandshaker
	h = &netxlite.TLSHandshakerConfigurable{}
	if clientHello != nil {
		h.(*netxlite.TLSHandshakerConfigurable).NewConn = netxlite.NewConnUTLS(clientHello)
	}
	h = &errorsx.ErrorWrapperTLSHandshaker{TLSHandshaker: h}
	return h
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

	// ErrInputIsNotAnURL indicates that the input is not an URL.
	ErrInputNotReadable = errors.New("input is not ASCII readable")

	// ErrUnsupportedInput indicates that the input URL scheme is unsupported.
	ErrUnsupportedInput = errors.New("unsupported input scheme")
)

// ErrNoValidIP means that the DNS step failed and the client did not provide IP endpoints for testing.
var ErrNoValidIP = errors.New("no valid IP address to measure")

// supportedQUICVersion are the H3 over QUIC versions we currently support
var supportedQUICVersions = map[string]bool{
	"h3":    true,
	"h3-29": true,
}

// nextLocationInfo contains the redirected location,
// and the http cookiejar used for the redirect chain.
type nextLocationInfo struct {
	jar http.CookieJar `json:"-"`
	url *url.URL       `json:"-"`
}

type URLMeasurement struct {
	URL       string
	DNS       *DNSMeasurement
	Endpoints []ControlEndpointMeasurement
}

type MeasureURLResult struct {
	URLMeasurement *URLMeasurement     `json:"-"`
	redirectedReqs []*nextLocationInfo `json:"-"`
	h3Reqs         []*nextLocationInfo `json:"-"`
}

type MeasureEndpointResult struct {
	CtrlEndpoint ControlEndpointMeasurement
	httpRedirect *nextLocationInfo
	h3Location   *url.URL
}

// Run implements ExperimentMeasurer.Run.
func (m *Measurer) Run(
	ctx context.Context,
	sess model.ExperimentSession,
	measurement *model.Measurement,
	callbacks model.ExperimentCallbacks,
) error {
	tk := new(TestKeys)
	measurement.TestKeys = tk
	tk.Agent = "redirect"
	tk.ClientResolver = sess.ResolverIP()
	return m.Measure(ctx, sess, measurement)
}

func (m *Measurer) measureControl(ctx context.Context, sess model.ExperimentSession, measurement *model.Measurement, URL *url.URL, epnts []string) error {
	testhelper := findTestHelper(sess)
	if testhelper == nil {
		return ErrNoAvailableTestHelpers
	}
	measurement.TestHelpers = map[string]interface{}{
		"backend": testhelper,
	}
	tk := measurement.TestKeys.(*TestKeys)
	var err error
	tk.Control, err = Control(ctx, sess, testhelper.Address, ControlRequest{
		HTTPRequest: URL.String(),
		HTTPRequestHeaders: map[string][]string{
			"Accept":          {httpheader.Accept()},
			"Accept-Language": {httpheader.AcceptLanguage()},
			"User-Agent":      {httpheader.UserAgent()},
		},
		TCPConnect: epnts,
	})
	tk.ControlFailure = archival.NewFailure(err)
	return nil
}

func (m *Measurer) Measure(ctx context.Context, sess model.ExperimentSession, measurement *model.Measurement) error {
	// parse input for correctness
	URL, err := url.Parse(string(measurement.Input))
	if err != nil {
		return err
	}
	mc := &nextLocationInfo{url: URL, jar: nil}
	urlM, err := m.MeasureURL(ctx, sess, measurement, mc)
	if err != nil {
		return err
	}
	tk := measurement.TestKeys.(*TestKeys)
	tk.URLMeasurements = make(map[string]*URLMeasurement)
	tk.URLMeasurements[URL.String()] = urlM.URLMeasurement

	n := 0
	nextRequests := append(urlM.redirectedReqs, urlM.h3Reqs...)
	for len(nextRequests) > n {
		req := nextRequests[n]
		n += 1
		if len(tk.URLMeasurements) == 20 {
			// stop after 20 URLs
			break
		}
		if _, ok := tk.URLMeasurements[req.url.String()]; ok {
			continue
		}
		mc = &nextLocationInfo{url: req.url, jar: req.jar}
		urlM, err := m.MeasureURL(ctx, sess, measurement, mc)
		if err != nil {
			continue
		}
		tk.URLMeasurements[req.url.String()] = urlM.URLMeasurement
		nextRequests = append(nextRequests, urlM.redirectedReqs...)
	}

	return nil
}

// Measure performs the measurement described by the request and
// returns the corresponding response or an error.
func (m *Measurer) MeasureURL(ctx context.Context, sess model.ExperimentSession, measurement *model.Measurement, loc *nextLocationInfo) (*MeasureURLResult, error) {
	URL := loc.url
	err := m.measureControl(ctx, sess, measurement, URL, nil)
	if err != nil {
		return nil, err
	}

	tk := measurement.TestKeys.(*TestKeys)
	// create URLMeasurement struct
	urlMeasurement := &URLMeasurement{
		URL:       URL.String(),
		DNS:       nil,
		Endpoints: []ControlEndpointMeasurement{},
	}

	// dns: start
	dns := dnsLookup(ctx, measurement, URL)

	urlMeasurement.DNS = dns

	enpnts := getEndpoints(dns.Addrs, URL)
	controlAddrs := []string{}
	if _, ok := tk.Control.URLMeasurements[URL.String()]; ok {
		controlAddrs = tk.Control.URLMeasurements[URL.String()].DNS.Addrs
	}
	controlEnpnts := getEndpoints(controlAddrs, URL)
	addrs := mergeEndpoints(enpnts, controlEnpnts)

	if len(addrs) == 0 {
		return nil, ErrNoValidIP
	}

	wg := new(sync.WaitGroup)
	out := make(chan *MeasureEndpointResult, len(enpnts))
	for _, endpoint := range enpnts {
		wg.Add(1)
		go m.MeasureEndpoint(ctx, measurement, loc, endpoint, wg, out)
	}
	wg.Wait()
	close(out)

	h3Reqs := []*nextLocationInfo{}
	redirectedReqs := []*nextLocationInfo{}
	for m := range out {
		urlMeasurement.Endpoints = append(urlMeasurement.Endpoints, m.CtrlEndpoint)
		if m.httpRedirect != nil {
			req := &nextLocationInfo{jar: m.httpRedirect.jar, url: m.httpRedirect.url}
			redirectedReqs = append(redirectedReqs, req)
		}
		if m.h3Location != nil {
			req := &nextLocationInfo{url: m.h3Location}
			h3Reqs = append(h3Reqs, req)
		}
	}
	return &MeasureURLResult{URLMeasurement: urlMeasurement, h3Reqs: h3Reqs, redirectedReqs: redirectedReqs}, nil
}

func (m *Measurer) MeasureEndpoint(ctx context.Context, measurement *model.Measurement, loc *nextLocationInfo, endpoint string, wg *sync.WaitGroup, out chan *MeasureEndpointResult) {
	defer wg.Done()
	var measureFactory = map[string]func(ctx context.Context, measurement *model.Measurement, loc *nextLocationInfo, endpoint string) *MeasureEndpointResult{
		"http":  m.measureHTTP,
		"https": m.measureHTTP,
		"h3":    m.measureH3,
		"h3-29": m.measureH3,
	}
	URL := loc.url
	// endpointResult := &MeasureEndpointResult{}
	endpointResult := measureFactory[URL.Scheme](ctx, measurement, loc, endpoint)
	out <- endpointResult
}

func (m *Measurer) measureHTTP(
	ctx context.Context,
	measurement *model.Measurement,
	loc *nextLocationInfo,
	endpoint string,
) *MeasureEndpointResult {
	result := &MeasureEndpointResult{}
	URL := loc.url
	httpMeasurement := &HTTPMeasurement{Endpoint: endpoint, Protocol: URL.Scheme}
	result.CtrlEndpoint = httpMeasurement

	var (
		conn net.Conn
		err  error
	)
	conn, err, httpMeasurement.TCPConnect = connect(ctx, measurement, endpoint)
	if err != nil {
		return result
	}
	defer conn.Close()
	var transport http.RoundTripper
	switch URL.Scheme {
	case "http":
		transport = NewSingleTransport(conn, nil)
	case "https":
		var tlsconn net.Conn
		cfg := &tls.Config{
			ServerName: URL.Hostname(),
			NextProtos: []string{"h2", "http/1.1"},
		}
		tlsconn, err, httpMeasurement.TLSHandshake = tlsHandshake(ctx, measurement, conn, cfg)
		if err != nil {
			return result
		}
		transport = NewSingleTransport(tlsconn, cfg)
	}
	// perform the HTTP request: this provides us with the HTTP request result and info about HTTP redirection
	result.httpRedirect, httpMeasurement.HTTPRequest = httpRoundtrip(ctx, measurement, loc, transport)

	// TODO: find out of the host also supports h3 support, which is announced in the Alt-Svc Header
	result.h3Location = nil

	return result
}

func (m *Measurer) measureH3(
	ctx context.Context,
	measurement *model.Measurement,
	loc *nextLocationInfo,
	endpoint string,
) *MeasureEndpointResult {
	result := &MeasureEndpointResult{}
	URL := loc.url
	h3Measurement := &H3Measurement{Endpoint: endpoint, Protocol: URL.Scheme}
	result.CtrlEndpoint = h3Measurement

	var sess quic.EarlySession
	tlscfg := &tls.Config{
		ServerName: URL.Hostname(),
		NextProtos: []string{URL.Scheme},
	}
	qcfg := &quic.Config{}
	sess, h3Measurement.QUICHandshake = quicHandshake(ctx, measurement, loc, tlscfg, qcfg, endpoint)
	if sess == nil {
		return result
	}
	transport := NewSingleH3Transport(sess, tlscfg, qcfg)
	// perform the HTTP request: this provides us with the HTTP request result and info about HTTP redirection
	result.httpRedirect, h3Measurement.HTTPRequest = httpRoundtrip(ctx, measurement, loc, transport)
	return result
}

// mergeEndpoints creates a (duplicate-free) union set of the IP endpoints provided by the client,
// and the IP endpoints resulting from the testhelper's DNS step
func mergeEndpoints(endpoints []string, clientEndpoints []string) (out []string) {
	unique := make(map[string]bool, len(endpoints)+len(clientEndpoints))
	for _, a := range endpoints {
		unique[a] = true
	}
	for _, a := range clientEndpoints {
		unique[a] = true
	}
	for key := range unique {
		out = append(out, key)
	}
	return out
}

// getEndpoints connects IP addresses with the port associated with the URL scheme
func getEndpoints(addrs []string, URL *url.URL) []string {
	out := []string{}
	_, h3ok := supportedQUICVersions[URL.Scheme]
	if URL.Scheme != "http" && URL.Scheme != "https" && !h3ok {
		panic("passed an unexpected scheme")
	}
	p := URL.Port()
	for _, a := range addrs {
		var port string
		switch {
		case p != "":
			// explicit port
			port = p
		case URL.Scheme == "http":
			port = "80"
		case URL.Scheme == "https":
			port = "443"
		case h3ok:
			port = "443"
		}
		endpoint := net.JoinHostPort(a, port)
		out = append(out, endpoint)
	}
	return out
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
