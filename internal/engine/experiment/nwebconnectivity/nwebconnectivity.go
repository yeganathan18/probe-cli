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
	"github.com/ooni/probe-cli/v3/internal/engine/netx/archival"
	"github.com/ooni/probe-cli/v3/internal/runtimex"
	"golang.org/x/net/http2"
)

// Config contains the experiment config.
type Config struct{}

// Measurer performs the measurement.
type Measurer struct {
	Config Config
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
	return Measurer{Config: config}
}

// ExperimentName implements ExperimentMeasurer.ExperExperimentName.
func (m Measurer) ExperimentName() string {
	return "new_webconnectivity"
}

// ExperimentVersion implements ExperimentMeasurer.ExperExperimentVersion.
func (m Measurer) ExperimentVersion() string {
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
func (m Measurer) Run(
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
	// 2. each IP address: sequence (later: parrallelism)
	for _, ip := range epnts {
		// TODO discard ipv6?
		// 3a. Dial connect
		conn, err := net.Dial("tcp", ip)
		if err != nil {
			fmt.Println("dial failure", err)
			continue
		}
		// TODO(wrap error)

		var transport http.RoundTripper
		switch URL.Scheme {
		case "http":
		case "https":
			config := &tls.Config{
				ServerName: URL.Hostname(),
				NextProtos: []string{"h2", "http/1.1"},
			}
			// 4a. Handshake
			tlsconn := tls.Client(conn, config)
			err = tlsconn.Handshake()
			if err != nil {
				fmt.Println("TLS handshake failure", err)
				continue
			}
			// TODO(wrap error)
			state := tlsconn.ConnectionState()
			// ALPN ?
			switch state.NegotiatedProtocol {
			case "h2":
				// HTTP 2 + TLS.
				transport = &http2.Transport{
					DialTLS: func(network string, addr string, cfg *tls.Config) (net.Conn, error) {
						return tlsconn, nil
					},
					TLSClientConfig:    config,
					DisableCompression: true,
				}
			default:
				// assume HTTP 1.x + TLS.
				transport = http.DefaultTransport.(*http.Transport).Clone()
				transport.(*http.Transport).DisableCompression = true
				transport.(*http.Transport).DialTLS = func(network string, addr string) (net.Conn, error) {
					return tlsconn, nil
				}
			}
		default:
			return errors.New("invalid scheme")
		}
		// 5a. Roundtrip
		// TODO handle redirect
		req, err := http.NewRequest("GET", URL.String(), nil)
		runtimex.PanicOnError(err, "http.NewRequest failed")
		req = req.WithContext(ctx)
		req.Header.Set("Accept", httpheader.Accept())
		req.Header.Set("Accept-Language", httpheader.AcceptLanguage())
		req.Host = URL.Hostname()

		jar, err := cookiejar.New(nil)
		runtimex.PanicOnError(err, "cookiejar.New failed")
		httpClient := &http.Client{
			Jar:       jar,
			Transport: transport,
		}

		httpClient.CheckRedirect = func(*http.Request, []*http.Request) error {
			fmt.Println("redirect")
			if t, ok := httpClient.Transport.(*http.Transport); ok {
				t.DialTLS = nil
			}
			if t, ok := httpClient.Transport.(*http2.Transport); ok {
				t.DialTLS = nil
			}
			if t, ok := httpClient.Transport.(*http3.RoundTripper); ok {
				t.Dial = nil
			}
			return nil
		}

		defer httpClient.CloseIdleConnections()
		resp, err := httpClient.Do(req)
		if err != nil {
			fmt.Println("HTTP failure", err, resp)
			continue
		}
		fmt.Println("HTTP response", resp.StatusCode)

		if URL.Scheme == "https" {
			tlscfg := &tls.Config{
				ServerName: URL.Hostname(),
				NextProtos: []string{"h3"},
			}
			qcfg := &quic.Config{}
			// 3b. Dial QUIC
			qsess, err := quic.DialAddrEarly(ip, tlscfg, qcfg)
			if err != nil {
				fmt.Println("quic dial failure", err)
				continue
			}
			// 5b. HTTP/3 Roundtrip
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
				fmt.Println("HTTP/3 failure", err)
				continue
			}
			fmt.Println("HTTP/3 response", resp.StatusCode)
		}

	}

	return nil

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
func (m Measurer) GetSummaryKeys(measurement *model.Measurement) (interface{}, error) {
	sk := SummaryKeys{IsAnomaly: false}
	return sk, nil
}
