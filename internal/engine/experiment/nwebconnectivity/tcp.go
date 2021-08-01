package nwebconnectivity

import (
	"context"
	"net"
	"strconv"
	"time"

	"github.com/ooni/probe-cli/v3/internal/engine/model"
	"github.com/ooni/probe-cli/v3/internal/engine/netx/archival"
	"github.com/ooni/probe-cli/v3/internal/netxlite"
)

type TCPConfig struct {
	Addr        string
	Dialer      netxlite.Dialer
	Measurement *model.Measurement
}

// connect performs the TCP three way handshake
func connect(ctx context.Context, config *TCPConfig) (net.Conn, error) {
	conn, err := config.Dialer.DialContext(ctx, "tcp", config.Addr)
	stop := time.Now()

	a, sport, _ := net.SplitHostPort(config.Addr)
	iport, _ := strconv.Atoi(sport)
	entry := archival.TCPConnectEntry{
		IP:   a,
		Port: iport,
		Status: archival.TCPConnectStatus{
			Failure: archival.NewFailure(err),
			Success: err == nil,
		},
		T: stop.Sub(config.Measurement.MeasurementStartTimeSaved).Seconds(),
	}
	tk := config.Measurement.TestKeys.(*TestKeys)
	tk.Lock()
	tk.TCPConnect = append(tk.TCPConnect, entry)
	tk.Unlock()
	return conn, err
}
