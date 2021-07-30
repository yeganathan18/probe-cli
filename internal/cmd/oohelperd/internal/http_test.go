package internal_test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/lucas-clemente/quic-go/http3"
	"github.com/ooni/probe-cli/v3/internal/cmd/oohelperd/internal"
)

func TestHTTPDoWithInvalidURL(t *testing.T) {
	ctx := context.Background()
	wg := new(sync.WaitGroup)
	httpch := make(chan internal.CtrlHTTPResponse, 1)
	wg.Add(1)
	go internal.HTTPDo(ctx, &internal.HTTPConfig{
		Client:            http.DefaultClient,
		Headers:           nil,
		MaxAcceptableBody: 1 << 24,
		Out:               httpch,
		URL:               "http://[::1]aaaa",
		Wg:                wg,
	})
	// wait for measurement steps to complete
	wg.Wait()
	resp := <-httpch
	if resp.Failure == nil || !strings.HasSuffix(*resp.Failure, `invalid port "aaaa" after host`) {
		t.Fatal("not the failure we expected")
	}
}

func TestHTTPDoWithHTTPTransportFailure(t *testing.T) {
	expected := errors.New("mocked error")
	ctx := context.Background()
	wg := new(sync.WaitGroup)
	httpch := make(chan internal.CtrlHTTPResponse, 1)
	wg.Add(1)
	go internal.HTTPDo(ctx, &internal.HTTPConfig{
		Client: &http.Client{
			Transport: internal.FakeTransport{
				Err: expected,
			},
		},
		Headers:           nil,
		MaxAcceptableBody: 1 << 24,
		Out:               httpch,
		URL:               "http://www.x.org",
		Wg:                wg,
	})
	// wait for measurement steps to complete
	wg.Wait()
	resp := <-httpch
	if resp.Failure == nil || !strings.HasSuffix(*resp.Failure, "mocked error") {
		t.Fatal("not the error we expected")
	}
}
func TestHTTPDoWithHTTP3(t *testing.T) {
	ctx := context.Background()
	wg := new(sync.WaitGroup)
	http3ch := make(chan internal.CtrlHTTPResponse, 1)
	wg.Add(1)
	go internal.HTTPDo(ctx, &internal.HTTPConfig{
		Client: &http.Client{
			Transport: &http3.RoundTripper{},
		},
		Headers:           nil,
		MaxAcceptableBody: 1 << 24,
		Out:               http3ch,
		URL:               "https://www.google.com",
		Wg:                wg,
	})
	// wait for measurement steps to complete
	wg.Wait()
	resp := <-http3ch
	if resp.Failure != nil {
		t.Fatal(resp.Failure)
	}
}
