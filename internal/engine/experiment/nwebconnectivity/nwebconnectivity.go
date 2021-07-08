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
type Config struct {
	dialer     netx.Dialer
	tlsDialer  netx.TLSDialer
	quicDialer netx.QUICDialer
}

// Measurer performs the measurement.
type Measurer struct {
	Config Config
}

func (m *Measurer) Init() {
	conf := netx.Config{}
	m.Config.dialer = netx.NewDialer(conf)
	m.Config.tlsDialer = netx.NewTLSDialer(conf)
	m.Config.quicDialer = netx.NewQUICDialer(conf)
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
	return &Measurer{Config: config}
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
	handleRedirect := func(resp *http.Response) error {
		loc, _ := resp.Location()
		measurement.Input = model.MeasurementTarget(loc.String())
		return m.Run(ctx, sess, measurement, callbacks)
	}

	m.Init()

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

	// 2. each IP address: sequence (later: parrallelism)
	for _, ip := range epnts {
		// TODO discard ipv6?

		// Dial connect
		conn, err := m.Config.dialer.DialContext(ctx, "tcp", ip)
		if err != nil {
			continue
		}
		// TODO(wrap error)

		var transport http.RoundTripper
		switch URL.Scheme {
		case "http":
			transport = getHTTP1Transport(conn)
		case "https":
			config := &tls.Config{
				ServerName: URL.Hostname(),
				NextProtos: []string{"h2", "http/1.1"},
			}
			// Handshake
			handshaker := m.Config.tlsDialer.(*netxlite.TLSDialer).TLSHandshaker
			tlsconn, state, err := handshaker.Handshake(ctx, conn, config)
			if err != nil {
				continue
			}
			// TODO(wrap error)
			// ALPN ?
			switch state.NegotiatedProtocol {
			case "h2":
				// HTTP 2 + TLS.
				transport = getHTTP2Transport(tlsconn, config)
			default:
				// assume HTTP 1.x + TLS.
				transport = getHTTP1Transport(conn)
			}
		default:
			return errors.New("invalid scheme")
		}
		// Roundtrip
		req := getRequest(ctx, URL)

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
		if err != nil {
			continue
		}
		switch resp.StatusCode {
		case 301, 302, 303, 307, 308:
			return handleRedirect(resp)
		}
		fmt.Println("HTTP response", resp.StatusCode)

		// Transport: QUIC
		if URL.Scheme == "https" {
			tlscfg := &tls.Config{
				ServerName: URL.Hostname(),
				NextProtos: []string{"h3"},
			}
			qcfg := &quic.Config{}
			// Dial QUIC
			qsess, err := m.Config.quicDialer.DialContext(ctx, "udp", ip, tlscfg, qcfg)
			if err != nil {
				continue
			}
			// HTTP/3 Roundtrip
			transport = &http3.RoundTripper{
				DisableCompression: true,
				TLSClientConfig:    tlscfg,
				QuicConfig:         qcfg,
				Dial: func(network, addr string, tlsCfg *tls.Config, cfg *quic.Config) (quic.EarlySession, error) {
					return qsess, nil
				},
			}
			httpClient.Transport = transport
			resp, err := httpClient.Do(req)
			if err != nil {
				continue
			}
			switch resp.StatusCode {
			case 301, 302, 303, 307, 308:
				return handleRedirect(resp)
			}
			fmt.Println("HTTP/3 response", resp.StatusCode)
		}

	}

	return nil

}

func getHTTP1Transport(conn net.Conn) *http.Transport {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DisableCompression = true
	transport.Dial = func(network string, addr string) (net.Conn, error) {
		return conn, nil
	}
	return transport
}

func getHTTP2Transport(conn net.Conn, config *tls.Config) *http2.Transport {
	transport := &http2.Transport{
		DialTLS: func(network string, addr string, cfg *tls.Config) (net.Conn, error) {
			return conn, nil
		},
		TLSClientConfig:    config,
		DisableCompression: true,
	}
	return transport
}

func getRequest(ctx context.Context, URL *url.URL) *http.Request {
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
