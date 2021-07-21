package nwebconnectivity

import (
	"context"
	"io"
	"net/http"
	"sort"

	"github.com/ooni/probe-cli/v3/internal/engine/netx/archival"
	"github.com/ooni/probe-cli/v3/internal/iox"
)

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

func setEntryRequest(ctx context.Context, req *http.Request, entry *archival.RequestEntry) {
	setEntryRequestBody(ctx, req, entry)
	setEntryRequestMetadata(req, entry)
}

func setEntryRequestBody(ctx context.Context, req *http.Request, entry *archival.RequestEntry) {
	if req.Body == nil {
		return
	}
	data, err := iox.ReadAllContext(ctx, io.LimitReader(req.Body, int64(defaultSnapSize)))
	if err != nil {
		return
	}
	entry.Request.Body.Value = string(data)
	entry.Request.BodyIsTruncated = len(data) >= defaultSnapSize
}

func setEntryRequestMetadata(req *http.Request, entry *archival.RequestEntry) {
	entry.Request.Headers = make(map[string]archival.MaybeBinaryValue)
	addheaders(
		req.Header, &entry.Request.HeadersList, &entry.Request.Headers)
	entry.Request.Method = req.Method
	entry.Request.URL = req.URL.String()
	// entry.Request.Transport
}

func setEntryFailure(err error, entry *archival.RequestEntry) {
	entry.Failure = archival.NewFailure(err)
}

func setEntryResponse(ctx context.Context, resp *http.Response, entry *archival.RequestEntry) {
	if resp == nil {
		return
	}
	setEntryResponseBody(ctx, resp, entry)
	setEntryResponseMetadata(resp, entry)
}

func setEntryResponseMetadata(resp *http.Response, entry *archival.RequestEntry) {
	entry.Response.Headers = make(map[string]archival.MaybeBinaryValue)
	addheaders(
		resp.Header, &entry.Response.HeadersList, &entry.Response.Headers)
	entry.Response.Code = int64(resp.StatusCode)
	entry.Response.Locations = resp.Header.Values("Location")
}

func setEntryResponseBody(ctx context.Context, resp *http.Response, entry *archival.RequestEntry) {
	if resp.Body == nil {
		return
	}
	data, err := iox.ReadAllContext(ctx, io.LimitReader(resp.Body, int64(defaultSnapSize)))
	if err != nil {
		return
	}
	entry.Response.Body.Value = string(data)
	entry.Response.BodyIsTruncated = len(data) >= defaultSnapSize
}
