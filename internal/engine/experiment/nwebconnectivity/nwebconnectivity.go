package nwebconnectivity

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/apex/log"
	"github.com/ooni/probe-cli/v3/internal/engine/httpheader"
	"github.com/ooni/probe-cli/v3/internal/engine/model"
	"github.com/ooni/probe-cli/v3/internal/engine/netx/archival"
	"github.com/ooni/probe-cli/v3/internal/errorsx"
	"github.com/ooni/probe-cli/v3/internal/netxlite"
	"github.com/ooni/probe-cli/v3/internal/runtimex"
	utls "gitlab.com/yawning/utls.git"
	"golang.org/x/net/idna"
)

// Conig contains the experiment config.
type Config struct {
	ClientHello string `ooni:"Use ClientHello of specific client for parroting."`
}

type ErrNoConnReuse struct {
	error
	location string
}

func (err ErrNoConnReuse) Error() string {
	return "cannot reuse connection"
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
	logger := log.Log
	clientHello := getClientHelloID(config.ClientHello)
	var fingerprintClient string
	if clientHello != nil {
		fingerprintClient = clientHello.Client
	}
	return &Measurer{
		Config:            config,
		dialer:            newDialer(logger),
		fingerprintClient: fingerprintClient,
		handshaker:        newHandshaker(config, clientHello),
		logger:            logger,
		quicDialer:        newQUICDialer(logger),
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

func newHandshaker(config Config, clientHello *utls.ClientHelloID) netxlite.TLSHandshaker {
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

// MeasureEndpointConfig contains measurement configuration data
// which is newly created for each endpoint
type MeasureEndpointConfig struct {
	addr       string
	h3jar      *cookiejar.Jar
	h3Support  bool
	jar        *cookiejar.Jar
	redirectch chan *RedirectInfo
	redirected *RedirectInfo // this field is null for the first request, and contains redirection data for redirected requests
	URL        *url.URL
	wg         *sync.WaitGroup
}

// RedirectInfo contains the redirected location as well as the request object which forwards most headers of the initial request.
// This forwarded request is generated by the http.Client and
type RedirectInfo struct {
	Jar      *cookiejar.Jar
	Location *url.URL
	Req      *http.Request
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
	return m.runWithRedirect(sess, measurement, ctx, 0, nil)
}

func (m *Measurer) runWithRedirect(
	sess model.ExperimentSession,
	measurement *model.Measurement,
	ctx context.Context,
	nRedirects int,
	rdrct *RedirectInfo,
) error {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	var URL *url.URL
	var err error
	switch rdrct {
	case nil:
		URL, err = url.Parse(string(measurement.Input))
		if err != nil {
			return ErrInputIsNotAnURL
		}
		URL.Host, err = idna.ToASCII(URL.Host)
		if err != nil {
			return ErrInputNotReadable
		}
	default:
		URL = rdrct.Location
	}

	if URL.Scheme != "http" && URL.Scheme != "https" {
		return ErrUnsupportedInput
	}

	// perform DNS lookup
	addresses := dnsLookup(ctx, &DNSConfig{
		Measurement: measurement,
		URL:         URL,
	})
	if len(addresses) == 0 {
		addr := net.ParseIP(URL.String())
		if addr != nil {
			addresses = []string{addr.String()}
		}
	}
	epnts := m.getEndpoints(addresses, URL.Scheme)

	tk := measurement.TestKeys.(*TestKeys)
	// control
	// only do this on the first request, not on redirects
	if rdrct == nil {
		m.measureControl(sess, measurement, ctx, URL, epnts)
	}
	ctrlAddrs := []string{}
	if len(tk.Control.URLMeasurements) > 0 && tk.Control.URLMeasurements[0].DNS != nil {
		ctrlAddrs = tk.Control.URLMeasurements[0].DNS.Addrs
	}
	addresses = mergeAddresses(addresses, ctrlAddrs)
	epnts = m.getEndpoints(addresses, URL.Scheme)

	// TODO: replace this by checking whether the Control response has a successful H3 entry
	h3Support := true

	var wg sync.WaitGroup
	// at most we should get a redirect response from each endpoint, for both TCP and QUIC
	redirectch := make(chan *RedirectInfo, len(epnts)*2+1)

	// for each IP address
	for _, ip := range epnts {
		wg.Add(1)
		// we need a separate jar for the TCP and QUIC based HTTP request
		var jar, h3jar *cookiejar.Jar
		jar, err = cookiejar.New(nil)
		h3jar, err = cookiejar.New(nil)
		runtimex.PanicOnError(err, "cookiejar.New failed")
		if rdrct != nil && rdrct.Jar != nil {
			jar = rdrct.Jar
			h3jar = rdrct.Jar
		}
		mconfig := &MeasureEndpointConfig{
			addr:       ip,
			h3jar:      h3jar,
			h3Support:  h3Support,
			jar:        jar,
			redirectch: redirectch,
			redirected: rdrct,
			URL:        URL,
			wg:         &wg,
		}
		go m.measure(measurement, ctx, mconfig)
	}
	wg.Wait()
	close(redirectch)

	test := make(map[string]bool, len(redirectch))
	for rdrct := range redirectch {
		if _, ok := test[rdrct.Location.String()]; ok {
			continue
		}
		test[rdrct.Location.String()] = true
		if nRedirects == 20 {
			// we stop after 20 redirects, as do Chrome and Firefox, TODO(kelmenhorst): how do we test this?
			return errors.New("stopped after 20 redirects")
		}
		// TODO(kelmenhorst): do this concurrently?
		m.runWithRedirect(sess, measurement, ctx, nRedirects+1, rdrct)
	}
	return nil

}

func mergeAddresses(addrs []string, controlAddrs []string) []string {
	appendIfUnique := func(slice []string, item string) []string {
		for _, i := range slice {
			if i == item {
				return slice
			}
		}
		return append(slice, item)
	}
	for _, c := range controlAddrs {
		addrs = appendIfUnique(addrs, c)
	}
	return addrs
}

func (m *Measurer) measureControl(sess model.ExperimentSession, measurement *model.Measurement, ctx context.Context, URL *url.URL, epnts []string) error {
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

func (m *Measurer) measure(
	measurement *model.Measurement,
	ctx context.Context,
	mconfig *MeasureEndpointConfig,
) error {
	defer mconfig.wg.Done()
	// connect
	conn, err := connect(ctx, &TCPConfig{
		Addr:        mconfig.addr,
		Dialer:      m.dialer,
		Measurement: measurement,
	})
	if err != nil {
		return nil
	}
	var transport http.RoundTripper
	switch mconfig.URL.Scheme {
	case "http":
		transport = netxlite.NewHTTPTransport(&SingleDialerHTTP1{conn: &conn}, nil, nil)
	case "https":
		// Handshake
		config := &tls.Config{
			ServerName: mconfig.URL.Hostname(),
			NextProtos: []string{"h2", "http/1.1"},
		}
		// transport, err = tlsHandshake(measurement, ctx, conn, config, false)
		transport, err = tlsHandshake(ctx, &TLSHandshakeConfig{
			Conn:        conn,
			Client:      m.fingerprintClient,
			Handshaker:  m.handshaker,
			Measurement: measurement,
			SNIExample:  false,
			TLSConf:     config,
		})
		// SNI example.com experiment
		if err != nil {
			transport, err = m.measureWithExampleSNI(measurement, ctx, mconfig)
		}
	}
	if transport == nil {
		return nil
	}

	// HTTP roundtrip
	httpRoundtrip(ctx, mconfig.redirectch, &HTTPConfig{
		Jar:         mconfig.jar,
		Measurement: measurement,
		Transport:   transport,
		URL:         mconfig.URL,
	})

	// stop if h3 is not supported
	if !mconfig.h3Support {
		return nil
	}
	// QUIC handshake
	transport, err = quicHandshake(ctx, &QUICConfig{
		Addr:        mconfig.addr,
		Dialer:      m.quicDialer,
		Measurement: measurement,
		SNIExample:  false,
		URL:         mconfig.URL,
	})
	// SNI example.com experiment
	if err != nil {
		transport, err = m.measureWithExampleSNI(measurement, ctx, mconfig)
	}
	if transport == nil {
		return nil
	}
	// HTTP/3 roundtrip
	httpRoundtrip(ctx, mconfig.redirectch, &HTTPConfig{
		Jar:         mconfig.h3jar,
		Measurement: measurement,
		Transport:   transport,
		URL:         mconfig.URL,
	})

	return nil
}

func (m *Measurer) measureWithExampleSNI(measurement *model.Measurement, ctx context.Context, mconfig *MeasureEndpointConfig) (http.RoundTripper, error) {
	conn, err := connect(ctx, &TCPConfig{
		Addr:        mconfig.addr,
		Dialer:      m.dialer,
		Measurement: measurement,
	})
	if err != nil {
		return nil, err
	}
	config := &tls.Config{
		ServerName: "example.com",
		NextProtos: []string{"h2", "http/1.1"},
	}
	return tlsHandshake(ctx, &TLSHandshakeConfig{
		Conn:        conn,
		Client:      m.fingerprintClient,
		Handshaker:  m.handshaker,
		Measurement: measurement,
		SNIExample:  true,
		TLSConf:     config,
	})
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
