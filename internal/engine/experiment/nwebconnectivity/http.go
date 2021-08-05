package nwebconnectivity

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"time"

	"github.com/ooni/probe-cli/v3/internal/engine/httpheader"
	"github.com/ooni/probe-cli/v3/internal/engine/model"
	"github.com/ooni/probe-cli/v3/internal/runtimex"
)

type HTTPConfig struct {
	Jar         *cookiejar.Jar
	Measurement *model.Measurement
	Transport   http.RoundTripper
	URL         *url.URL
}

// httpRoundtrip constructs the HTTP request and HTTP client and performs the HTTP Roundtrip with the given transport
func httpRoundtrip(ctx context.Context, redirectch chan *NextLocationInfo, config *HTTPConfig) {
	req := getRequest(ctx, config.URL, "GET", nil)
	var redirectReq *http.Request = nil
	httpClient := &http.Client{
		CheckRedirect: func(r *http.Request, reqs []*http.Request) error {
			redirectReq = r
			return http.ErrUseLastResponse
		},
		Jar:       config.Jar,
		Transport: config.Transport,
	}
	defer httpClient.CloseIdleConnections()

	startHTTP := time.Now()
	entry := makeRequestEntry(config.Measurement.MeasurementStartTimeSaved, startHTTP)
	entry.setRequest(ctx, req)
	resp, err := httpClient.Do(req)
	entry.setFailure(err)
	entry.setResponse(ctx, resp)

	tk := config.Measurement.TestKeys.(*TestKeys)
	tk.Lock()
	tk.Requests = append(tk.Requests, entry.RequestEntry)
	tk.Unlock()

	if resp == nil {
		return
	}
	loc, _ := resp.Location()
	if loc != nil && redirectReq != nil {
		redirectch <- &NextLocationInfo{Jar: config.Jar, Location: loc, HTTPRedirectReq: redirectReq}
	}
}

// getRequest gives us a new HTTP GET request
func getRequest(ctx context.Context, URL *url.URL, method string, body io.ReadCloser) *http.Request {
	req, err := http.NewRequest(method, URL.String(), nil)
	runtimex.PanicOnError(err, "http.NewRequest failed")
	req = req.WithContext(ctx)
	req.Header.Set("Accept", httpheader.Accept())
	req.Header.Set("Accept-Language", httpheader.AcceptLanguage())
	req.Host = URL.Hostname()
	if body != nil {
		req.Body = body
	}
	return req
}

// getEndpoints connects IP addresses with the port associated with the URL scheme
func getURL(addr string) *url.URL {
	a, sport, _ := net.SplitHostPort(addr)
	var scheme string
	switch sport {
	case "80":
		scheme = "http://"
	case "443":
		scheme = "https://"
	}
	ustring := scheme + a
	u, _ := url.Parse(ustring)
	return u
}
