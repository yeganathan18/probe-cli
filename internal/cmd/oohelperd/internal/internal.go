package internal

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/ooni/probe-cli/v3/internal/engine/netx"
	"github.com/ooni/probe-cli/v3/internal/iox"
	"github.com/ooni/probe-cli/v3/internal/version"
)

// Handler implements the Web Connectivity test helper HTTP API.
type Handler struct {
	Client            *http.Client
	Dialer            netx.Dialer
	H3Client          *http.Client
	MaxAcceptableBody int64
	QuicDialer        netx.QUICDialer
	Resolver          netx.Resolver
}

func (h Handler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	w.Header().Add("Server", fmt.Sprintf(
		"oohelperd/%s ooniprobe-engine/%s", version.Version, version.Version,
	))
	if req.Method != "POST" {
		w.WriteHeader(400)
		return
	}
	if req.Header.Get("content-type") != "application/json" {
		w.WriteHeader(400)
		return
	}
	reader := &io.LimitedReader{R: req.Body, N: h.MaxAcceptableBody}
	data, err := iox.ReadAllContext(req.Context(), reader)
	if err != nil {
		w.WriteHeader(400)
		return
	}
	var creq CtrlRequest
	if err := json.Unmarshal(data, &creq); err != nil {
		w.WriteHeader(400)
		return
	}
	measureConfig := MeasureConfig(h)
	var cresp = CtrlResponse{URLMeasurements: []*CtrlURLMeasurement{}}
	urlM, err := Measure(req.Context(), measureConfig, &creq)
	cresp.URLMeasurements = append(cresp.URLMeasurements, urlM)
	if err != nil {
		w.WriteHeader(400)
		return
	}
	// We assume that the following call cannot fail because it's a
	// clearly serializable data structure.
	data, _ = json.Marshal(cresp)
	w.Header().Add("Content-Type", "application/json")
	w.Write(data)
}
