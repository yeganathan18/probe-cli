package nwebconnectivity

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ooni/probe-cli/v3/internal/errorsx"
)

func TestRequestEntry(t *testing.T) {
	begin := time.Now()
	stop := time.Now()
	entry := makeRequestEntry(begin, stop)
	if entry.T != stop.Sub(begin).Seconds() {
		t.Fatal("unexpected timestamp")
	}
	req := &http.Request{
		Body:   io.NopCloser(strings.NewReader("test-body")),
		Method: "GET",
		Header: http.Header{
			"Content-Type": []string{"text/plain"},
		},
		URL: &url.URL{
			Scheme: "http",
			Host:   "example.host",
		},
	}
	entry.setRequest(context.Background(), req)
	if len(entry.Request.Headers) != 1 {
		t.Fatal("unexpected header length")
	}
	if entry.Request.Method != "GET" {
		t.Fatal("unexpected method")
	}
	if entry.Request.Body.Value != "test-body" {
		t.Fatal("unexpected body")
	}
	if entry.Request.BodyIsTruncated {
		t.Fatal("unexpected BodyIsTruncated")
	}
	if entry.Request.URL != "http://example.host" {
		t.Fatal("unexpected host", entry.Request.URL)
	}

	resp := &http.Response{
		Body:       io.NopCloser(strings.NewReader("test-response-body")),
		StatusCode: 200,
		Proto:      "h3",
		Header:     http.Header{},
	}
	entry.setResponse(context.Background(), resp)
	if len(entry.Response.Headers) != 0 {
		t.Fatal("unexpected header length")
	}
	if entry.Response.Code != 200 {
		t.Fatal("unexpected status")
	}
	if entry.Response.Body.Value != "test-response-body" {
		t.Fatal("unexpected body")
	}
	if entry.Response.BodyIsTruncated {
		t.Fatal("unexpected BodyIsTruncated")
	}
}

type FakeResolver struct{}

func (r *FakeResolver) Network() string {
	return "test-proto"
}

func (r *FakeResolver) Address() string {
	return "0.0.0.0:0"
}

func (r *FakeResolver) LookupHost(ctx context.Context, hostname string) ([]string, error) {
	return nil, nil
}

func TestDNSQueryEntry(t *testing.T) {
	begin := time.Now()
	stop := time.Now()
	entry := makeDNSQueryEntry(begin, stop)
	if entry.T != stop.Sub(begin).Seconds() {
		t.Fatal("unexpected timestamp")
	}

	resolver := &errorsx.ErrorWrapperResolver{Resolver: &FakeResolver{}}
	entry.setMetadata(resolver, "testhost.com")
	if entry.Hostname != "testhost.com" {
		t.Fatal("unexpected hostname")
	}
	if entry.ResolverAddress != "0.0.0.0:0" {
		t.Fatal("unexpected resolver address")
	}
	if entry.Engine != "test-proto" {
		t.Fatal("unexpected engine")
	}

	entry.setResult([]string{"1.1.1.1"}, io.EOF, "A")
	if entry.QueryType != "A" {
		t.Fatal("unexpected query type")
	}
	if *entry.Failure != "eof_error" {
		t.Fatal("unexpected error")
	}
	if len(entry.Answers) != 1 {
		t.Fatal("unexpected number of answers")
	}
	if entry.Answers[0].IPv4 != "1.1.1.1" {
		t.Fatal("unexpected answer")
	}
	if entry.Answers[0].ASOrgName != "Cloudflare, Inc." {
		t.Fatal("unexpected ASN")
	}
}

func TestTLSHandshake(t *testing.T) {
	begin := time.Now()
	stop := time.Now()
	entry := makeTLSHandshakeEntry(begin, stop, QUICTLSExperimentTag, false)
	if entry.T != stop.Sub(begin).Seconds() {
		t.Fatal("unexpected timestamp")
	}
	if entry.Tags[0] != QUICTLSExperimentTag {
		t.Fatal("unexpected tag")
	}
	conn, _ := net.Dial("tcp", "ooni.org:443")
	cfg := &tls.Config{ServerName: "ooni.org", InsecureSkipVerify: true}
	tlsconn := tls.Client(conn, cfg)
	tlsconn.Handshake()
	entry.setHandshakeResult(cfg, tlsconn.ConnectionState(), nil)
	if !entry.NoTLSVerify {
		t.Fatal("unexpected NoTLSVerify")
	}
	if entry.ServerName != "ooni.org" {
		t.Fatal("unexpected SNI")
	}
	if entry.Failure != nil {
		t.Fatal("unexpected failure")
	}
}
