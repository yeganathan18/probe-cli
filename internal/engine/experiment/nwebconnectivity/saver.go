package nwebconnectivity

import (
	"context"
	"io"
	"net/http"
	"sort"
	"time"

	"github.com/ooni/probe-cli/v3/internal/engine/netx/archival"
	"github.com/ooni/probe-cli/v3/internal/errorsx"
	"github.com/ooni/probe-cli/v3/internal/iox"
)

type RequestEntry struct {
	archival.RequestEntry
}

func makeRequestEntry(begin time.Time) *RequestEntry {
	startTime := time.Now().Sub(begin).Seconds()
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

func (e *DNSQueryEntry) setMetadata(resolver *errorsx.ErrorWrapperResolver, hostname string) {
	e.Engine = resolver.Network()
	e.ResolverAddress = resolver.Address()
	e.Hostname = hostname
}

func (e *DNSQueryEntry) setResult(addrs []string, err error, qtype dnsQueryType) {
	e.QueryType = string(qtype)
	e.Failure = archival.NewFailure(err)
	for _, addr := range addrs {
		if qtype.ipoftype(addr) {
			e.Answers = append(e.Answers, qtype.makeanswerentry(addr))
		}
	}
}
