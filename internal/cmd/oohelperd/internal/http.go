package internal

import (
	"context"
	"io"
	"net/http"
	"strings"

	"github.com/ooni/probe-cli/v3/internal/engine/experiment/nwebconnectivity"
	"github.com/ooni/probe-cli/v3/internal/iox"
)

type RedirectInfo = nwebconnectivity.RedirectInfo

// HTTPConfig configures the HTTP check.
type HTTPConfig struct {
	Client            *http.Client
	Headers           map[string][]string
	MaxAcceptableBody int64
	URL               string
}

// HTTPDo performs the HTTP check.
func HTTPDo(ctx context.Context, config *HTTPConfig, redirectch chan *RedirectInfo) *CtrlHTTPRequest {
	req, err := http.NewRequestWithContext(ctx, "GET", config.URL, nil)
	if err != nil {
		return &CtrlHTTPRequest{Failure: newfailure(err)}
	}
	// The original test helper failed with extra headers while here
	// we're implementing (for now?) a more liberal approach.
	for k, vs := range config.Headers {
		switch strings.ToLower(k) {
		case "user-agent":
		case "accept":
		case "accept-language":
			for _, v := range vs {
				req.Header.Add(k, v)
			}
		}
	}
	var redirectReq *http.Request
	config.Client.CheckRedirect = func(r *http.Request, reqs []*http.Request) error {
		redirectReq = r
		return http.ErrUseLastResponse
	}
	resp, err := config.Client.Do(req)
	if err != nil {
		return &CtrlHTTPRequest{Failure: newfailure(err)}
	}
	loc, _ := resp.Location()
	if loc != nil && redirectReq != nil {
		redirectch <- &RedirectInfo{Location: loc, Req: redirectReq}
	}
	defer resp.Body.Close()
	headers := make(map[string]string)
	for k := range resp.Header {
		headers[k] = resp.Header.Get(k)
	}
	reader := &io.LimitedReader{R: resp.Body, N: config.MaxAcceptableBody}
	data, err := iox.ReadAllContext(ctx, reader)
	return &CtrlHTTPRequest{
		BodyLength: int64(len(data)),
		Failure:    newfailure(err),
		StatusCode: int64(resp.StatusCode),
		Headers:    headers,
	}
}
