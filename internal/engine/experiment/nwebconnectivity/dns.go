package nwebconnectivity

import (
	"context"
	"net/url"
	"time"

	"github.com/ooni/probe-cli/v3/internal/engine/model"
	"github.com/ooni/probe-cli/v3/internal/engine/netx/archival"
	"github.com/ooni/probe-cli/v3/internal/engine/netx/resolver"
	"github.com/ooni/probe-cli/v3/internal/errorsx"
	"github.com/ooni/probe-cli/v3/internal/netxlite"
)

type DNSConfig struct {
	Measurement *model.Measurement
	URL         *url.URL
}

type DNSMeasurement struct {
	Addrs   []string
	Failure *string
	Queries []*DNSQueryEntry
}

// dnsLookup finds the IP address(es) associated with a domain name
func dnsLookup(ctx context.Context, measurement *model.Measurement, URL *url.URL) *DNSMeasurement {
	dnsMeasurement := &DNSMeasurement{}
	var r resolver.Resolver
	r = &resolver.IDNAResolver{Resolver: &netxlite.ResolverSystem{}}
	r = &errorsx.ErrorWrapperResolver{Resolver: r}
	hostname := URL.Hostname()
	addrs, err := r.LookupHost(ctx, hostname)
	stop := time.Now()
	dnsMeasurement.Addrs = addrs
	dnsMeasurement.Failure = archival.NewFailure(err)
	for _, qtype := range []archival.DNSQueryType{"A", "AAAA"} {
		entry := makeDNSQueryEntry(measurement.MeasurementStartTimeSaved, stop)
		entry.setMetadata(r.(*errorsx.ErrorWrapperResolver), hostname)
		entry.setResult(addrs, err, qtype)
		if len(entry.Answers) <= 0 && err == nil {
			continue
		}
		dnsMeasurement.Queries = append(dnsMeasurement.Queries, entry)
	}
	return dnsMeasurement
}
