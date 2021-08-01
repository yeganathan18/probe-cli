package nwebconnectivity

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"sort"
	"time"

	"github.com/lucas-clemente/quic-go"
	"github.com/ooni/probe-cli/v3/internal/engine/netx/archival"
	"github.com/ooni/probe-cli/v3/internal/engine/netx/resolver"
	"github.com/ooni/probe-cli/v3/internal/engine/netx/trace"
	"github.com/ooni/probe-cli/v3/internal/iox"
	"github.com/ooni/probe-cli/v3/internal/netxlite"
)

type RequestEntry struct {
	archival.RequestEntry
}

func makeRequestEntry(begin time.Time, stop time.Time) *RequestEntry {
	startTime := stop.Sub(begin).Seconds()
	return &RequestEntry{archival.RequestEntry{T: startTime}}
}

const defaultSnapSize = 1 << 17

// TODO(kelmenhorst): make this function public in archival or have this duplicate?
func addheaders(
	source http.Header,
	destList *[]archival.HTTPHeader,
	destMap *map[string]archival.MaybeBinaryValue,
) {
	for key, values := range source {
		for index, value := range values {
			value := archival.MaybeBinaryValue{Value: value}
			// With the map representation we can only represent a single
			// value for every key. Hence the list representation.
			if index == 0 {
				(*destMap)[key] = value
			}
			*destList = append(*destList, archival.HTTPHeader{
				Key:   key,
				Value: value,
			})
		}
	}
	sort.Slice(*destList, func(i, j int) bool {
		return (*destList)[i].Key < (*destList)[j].Key
	})
}

func (e *RequestEntry) setRequest(ctx context.Context, req *http.Request) {
	e.setRequestBody(ctx, req)
	e.setRequestMetadata(req)
}

func (e *RequestEntry) setRequestBody(ctx context.Context, req *http.Request) {
	if req.Body == nil {
		return
	}
	data, err := iox.ReadAllContext(ctx, io.LimitReader(req.Body, int64(defaultSnapSize)))
	if err != nil {
		return
	}
	e.Request.Body.Value = string(data)
	e.Request.BodyIsTruncated = len(data) >= defaultSnapSize
}

func (e *RequestEntry) setRequestMetadata(req *http.Request) {
	e.Request.Headers = make(map[string]archival.MaybeBinaryValue)
	addheaders(
		req.Header, &e.Request.HeadersList, &e.Request.Headers)
	e.Request.Method = req.Method
	e.Request.URL = req.URL.String()
	// e.Request.Transport
}

func (e *RequestEntry) setFailure(err error) {
	e.Failure = archival.NewFailure(err)
}

func (e *RequestEntry) setResponse(ctx context.Context, resp *http.Response) {
	if resp == nil {
		return
	}
	e.setResponseBody(ctx, resp)
	e.setResponseMetadata(resp)
}

func (e *RequestEntry) setResponseMetadata(resp *http.Response) {
	e.Response.Headers = make(map[string]archival.MaybeBinaryValue)
	addheaders(
		resp.Header, &e.Response.HeadersList, &e.Response.Headers)
	e.Response.Code = int64(resp.StatusCode)
	e.Response.Locations = resp.Header.Values("Location")
}

func (e *RequestEntry) setResponseBody(ctx context.Context, resp *http.Response) {
	if resp.Body == nil {
		return
	}
	data, err := iox.ReadAllContext(ctx, io.LimitReader(resp.Body, int64(defaultSnapSize)))
	if err != nil {
		return
	}
	e.Response.Body.Value = string(data)
	e.Response.BodyIsTruncated = len(data) >= defaultSnapSize
}

type DNSQueryEntry struct {
	archival.DNSQueryEntry
}

func makeDNSQueryEntry(begin time.Time, stop time.Time) *DNSQueryEntry {
	return &DNSQueryEntry{archival.DNSQueryEntry{
		T: stop.Sub(begin).Seconds(),
	}}
}

func (e *DNSQueryEntry) setMetadata(r resolver.Resolver, hostname string) {
	e.Engine = r.(resolver.IDNAResolver).Network()
	e.ResolverAddress = r.(resolver.IDNAResolver).Address()
	e.Hostname = hostname
}

func (e *DNSQueryEntry) setResult(addrs []string, err error, qtype archival.DNSQueryType) {
	e.QueryType = string(qtype)
	e.Failure = archival.NewFailure(err)
	for _, addr := range addrs {
		if qtype.IPofType(addr) {
			e.Answers = append(e.Answers, qtype.Makeanswerentry(addr))
		}
	}
}

type TLSHandshake struct {
	archival.TLSHandshake
}

func makeTLSHandshakeEntry(begin time.Time, stop time.Time, protoTag string, examplesni bool) *TLSHandshake {
	if examplesni {
		protoTag = protoTag + "_example"
	}
	return &TLSHandshake{archival.TLSHandshake{
		T:    stop.Sub(begin).Seconds(),
		Tags: []string{protoTag},
	}}
}

func (e *TLSHandshake) setQUICHandshakeResult(tlscfg *tls.Config, qsess quic.EarlySession, err error) {
	state := tls.ConnectionState{}
	if err == nil {
		state = qsess.ConnectionState().TLS.ConnectionState
	}
	e.setHandshakeResult(tlscfg, state, err)
}

func (e *TLSHandshake) setHandshakeResult(tlscfg *tls.Config, state tls.ConnectionState, err error) {
	e.Failure = archival.NewFailure(err)
	e.NoTLSVerify = tlscfg.InsecureSkipVerify
	e.ServerName = tlscfg.ServerName
	if err != nil {
		return
	}
	e.setHandshakeSuccess(tlscfg, state)
}

func (e *TLSHandshake) setHandshakeSuccess(tlscfg *tls.Config, state tls.ConnectionState) {
	e.CipherSuite = netxlite.TLSCipherSuiteString(state.CipherSuite)
	e.NegotiatedProtocol = state.NegotiatedProtocol
	e.PeerCertificates = archival.MakePeerCerts(trace.PeerCerts(state, nil))
	e.TLSVersion = netxlite.TLSVersionString(state.Version)
}
