package nwebconnectivity

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"time"

	"github.com/apex/log"
	"github.com/ooni/probe-cli/v3/internal/engine/model"
	"github.com/ooni/probe-cli/v3/internal/engine/netx/archival"
)

// connect performs the TCP three way handshake
func connect(ctx context.Context, measurement *model.Measurement, endpoint string) (net.Conn, error, *archival.TCPConnectEntry) {
	dialer := newDialer(log.Log)
	fmt.Println(endpoint)
	conn, err := dialer.DialContext(ctx, "tcp", endpoint)
	stop := time.Now()

	a, sport, _ := net.SplitHostPort(endpoint)
	iport, _ := strconv.Atoi(sport)
	entry := archival.TCPConnectEntry{
		IP:   a,
		Port: iport,
		Status: archival.TCPConnectStatus{
			Failure: archival.NewFailure(err),
			Success: err == nil,
		},
		T: stop.Sub(measurement.MeasurementStartTimeSaved).Seconds(),
	}
	return conn, err, &entry
}
