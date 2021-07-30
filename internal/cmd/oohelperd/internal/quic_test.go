package internal

import (
	"context"
	"net/http"
	"net/url"
	"sync"
	"testing"
)

func TestH3ServerDiscovery(t *testing.T) {
	type host struct {
		url string
		h3  bool
	}
	expectations := []host{{
		url: "https://www.google.com",
		h3:  true,
	}, {
		url: "http://www.google.com",
		h3:  false,
	}, {
		url: "https://ooni.org",
		h3:  false,
	}}

	for _, expected := range expectations {
		ctx := context.Background()
		wg := new(sync.WaitGroup)
		httpch := make(chan CtrlHTTPResponse, 1)
		wg.Add(1)
		go HTTPDo(ctx, &HTTPConfig{
			Client: &http.Client{
				Transport: http.DefaultTransport,
			},
			Headers:           nil,
			MaxAcceptableBody: 1 << 24,
			Out:               httpch,
			URL:               expected.url,
			Wg:                wg,
		})
		// wait for measurement steps to complete
		wg.Wait()
		resp := <-httpch
		if resp.Failure != nil {
			t.Fatal(resp.Failure)
		}
		u, _ := url.Parse(expected.url)
		h3 := discoverH3Server(resp, u)
		if h3 != expected.h3 {
			t.Fatal("unexpected h3 discovery result")
		}
	}
}
