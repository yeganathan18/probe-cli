package internal_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/lucas-clemente/quic-go/http3"
	"github.com/ooni/probe-cli/v3/internal/cmd/oohelperd/internal"
)

var redirectch = make(chan *internal.RedirectInfo)

func TestHTTPDoWithInvalidURL(t *testing.T) {
	ctx := context.Background()
	resp := internal.HTTPDo(ctx, &internal.HTTPConfig{
		Client:            http.DefaultClient,
		Headers:           nil,
		MaxAcceptableBody: 1 << 24,
		URL:               "http://[::1]aaaa",
	}, redirectch)
	if resp.Failure == nil || !strings.HasSuffix(*resp.Failure, `invalid port "aaaa" after host`) {
		t.Fatal("not the failure we expected")
	}
}

func TestHTTPDoWithHTTPTransportFailure(t *testing.T) {
	expected := errors.New("mocked error")
	ctx := context.Background()
	resp := internal.HTTPDo(ctx, &internal.HTTPConfig{
		Client: &http.Client{
			Transport: internal.FakeTransport{
				Err: expected,
			},
		},
		Headers:           nil,
		MaxAcceptableBody: 1 << 24,
		URL:               "http://www.x.org",
	}, redirectch)
	if resp.Failure == nil || !strings.HasSuffix(*resp.Failure, "mocked error") {
		t.Fatal("not the error we expected")
	}
}

func TestHTTPDoWithHTTP3(t *testing.T) {
	ctx := context.Background()
	resp := internal.HTTPDo(ctx, &internal.HTTPConfig{
		Client: &http.Client{
			Transport: &http3.RoundTripper{},
		},
		Headers:           nil,
		MaxAcceptableBody: 1 << 24,
		URL:               "https://www.google.com",
	}, redirectch)
	if resp.Failure != nil {
		t.Fatal(resp.Failure)
	}
}
