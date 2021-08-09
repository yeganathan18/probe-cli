package nwebconnectivity

import (
	"context"
	"errors"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"time"

	"github.com/ooni/probe-cli/v3/internal/atomicx"
	"github.com/ooni/probe-cli/v3/internal/engine/httpheader"
	"github.com/ooni/probe-cli/v3/internal/engine/model"
	"github.com/ooni/probe-cli/v3/internal/engine/netx/archival"
	"github.com/ooni/probe-cli/v3/internal/runtimex"
)

const maxAcceptableBody = 1 << 24

// ErrNoH3Location means that a server's h3 support could not be derived from Alt-Svc
var ErrNoH3Location = errors.New("no h3 server location")

type HTTPMeasurement struct {
	Endpoint     string                    `json:"endpoint"`
	Protocol     string                    `json:"protocol"`
	TCPConnect   *archival.TCPConnectEntry `json:"tcp_connect"`
	TLSHandshake *archival.TLSHandshake    `json:"tls_handshake"`
	HTTPRequest  *archival.RequestEntry    `json:"http_request"`
}

func (m *HTTPMeasurement) IsEndpointMeasurement() {}

type H3Measurement struct {
	Endpoint      string                 `json:"endpoint"`
	Protocol      string                 `json:"protocol"`
	QUICHandshake *archival.TLSHandshake `json:"tls_handshake"`
	HTTPRequest   *archival.RequestEntry `json:"http_request"`
}

func (m *H3Measurement) IsEndpointMeasurement() {}

// newRequest creates a new *http.Request.
// h3 URL schemes are replaced by "https", to avoid invalid-scheme-errors during HTTP GET.
func newRequest(ctx context.Context, URL *url.URL) *http.Request {
	realSchemes := map[string]string{
		"http":  "http",
		"https": "https",
		"h3":    "https",
		"h3-29": "https",
	}
	newURL, err := url.Parse(URL.String())
	runtimex.PanicOnError(err, "url.Parse failed")
	newURL.Scheme = realSchemes[URL.Scheme]
	req, err := http.NewRequestWithContext(ctx, "GET", newURL.String(), nil)
	runtimex.PanicOnError(err, "http.NewRequestWithContext failed")
	req = req.WithContext(ctx)
	req.Header.Set("Accept", httpheader.Accept())
	req.Header.Set("Accept-Language", httpheader.AcceptLanguage())
	return req
}

// httpRoundtrip performs the HTTP Roundtrip with the given transport
// nextLocationInfo contains information needed in case of an HTTP redirect. Nil, if no redirect occured.
func httpRoundtrip(ctx context.Context, measurement *model.Measurement, loc *nextLocationInfo, transport http.RoundTripper) (*nextLocationInfo, *archival.RequestEntry) {
	req := newRequest(ctx, loc.url)

	var err error
	jar := loc.jar
	if jar == nil {
		jar, err = cookiejar.New(nil)
		runtimex.PanicOnError(err, "cookiejar.New failed")
	}
	// To know whether we need to redirect, we exploit the redirect check of the http.Client:
	// http.(*Client).do calls redirectBehavior to find out if an HTTP redirect status
	// (301, 302, 303, 307, 308) was returned. Only then it uses the CheckRedirect callback.
	// I.e., the client lands in the CheckRedirect callback, if and only if we need to redirect.
	// We use an atomic value to mark that CheckRedirect has been visited.
	shouldRedirect := &atomicx.Int64{}
	client := http.Client{
		CheckRedirect: func(r *http.Request, reqs []*http.Request) error {
			shouldRedirect.Add(1)
			return http.ErrUseLastResponse
		},
		Jar:       jar,
		Transport: transport,
	}
	startHTTP := time.Now()
	entry := makeRequestEntry(measurement.MeasurementStartTimeSaved, startHTTP)
	entry.setRequest(ctx, req)
	resp, err := client.Do(req)
	entry.setFailure(err)
	entry.setResponse(ctx, resp)

	if err != nil {
		return nil, &entry.RequestEntry
	}

	var httpRedirect *nextLocationInfo
	redloc, err := resp.Location()
	if shouldRedirect.Load() > 0 && err == nil {
		redloc.Scheme = loc.url.Scheme
		httpRedirect = &nextLocationInfo{jar: jar, url: redloc}
	}
	defer resp.Body.Close()
	return httpRedirect, &entry.RequestEntry
}
