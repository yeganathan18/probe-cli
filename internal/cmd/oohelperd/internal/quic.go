package internal

import (
	"context"
	"crypto/tls"
	"net/url"
	"strings"
	"sync"

	"github.com/lucas-clemente/quic-go"
	"github.com/ooni/probe-cli/v3/internal/engine/experiment/nwebconnectivity"
	"github.com/ooni/probe-cli/v3/internal/engine/netx"
)

// CtrlQUICResult is the result of the QUIC check performed by the test helper.
type CtrlQUICResult = nwebconnectivity.ControlQUICHandshakeResult

// QUICResultPair contains the endpoint and the corresponding result.
type QUICResultPair struct {
	Endpoint string
	Result   CtrlQUICResult
}

// QUICConfig configures the QUIC handshake check.
type QUICConfig struct {
	Dialer    netx.QUICDialer
	Endpoint  string
	Out       chan QUICResultPair
	QConfig   *quic.Config
	TLSConfig *tls.Config
	Wg        *sync.WaitGroup
}

// QUICDo performs the QUIC check.
func QUICDo(ctx context.Context, config *QUICConfig) {
	defer config.Wg.Done()
	_, err := config.Dialer.DialContext(ctx, "udp", config.Endpoint, config.TLSConfig, config.QConfig)
	config.Out <- QUICResultPair{
		Endpoint: config.Endpoint,
		Result: CtrlQUICResult{
			Failure: newfailure(err),
			Status:  err == nil,
		},
	}
}

// discoverH3Server inspects the Alt-Svc Header of the HTTP (over TCP) response of the control measurement
// to check whether the server announces to support h3
func discoverH3Server(resp CtrlHTTPResponse, URL *url.URL) (h3 bool) {
	if URL.Scheme != "https" {
		return false
	}
	alt_svc := resp.Headers["Alt-Svc"]
	entries := strings.Split(alt_svc, ";")
	for _, e := range entries {
		if strings.Contains(e, "h3") {
			return true
		}
	}
	return false
}
