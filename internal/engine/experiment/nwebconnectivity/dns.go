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

// dnsLookup finds the IP address(es) associated with a domain name
func dnsLookup(ctx context.Context, config *DNSConfig) []string {
	tk := config.Measurement.TestKeys.(*TestKeys)
	var r resolver.Resolver
	r = &resolver.IDNAResolver{Resolver: &netxlite.ResolverSystem{}}
	r = &errorsx.ErrorWrapperResolver{Resolver: r}
	hostname := config.URL.Hostname()
	addrs, err := r.LookupHost(ctx, hostname)
	stop := time.Now()
	for _, qtype := range []archival.DNSQueryType{"A", "AAAA"} {
		entry := makeDNSQueryEntry(config.Measurement.MeasurementStartTimeSaved, stop)
		entry.setMetadata(r.(*errorsx.ErrorWrapperResolver), hostname)
		entry.setResult(addrs, err, qtype)
		if len(entry.Answers) <= 0 && err == nil {
			continue
		}
		tk.Lock()
		tk.Queries = append(tk.Queries, entry.DNSQueryEntry)
		tk.Unlock()
	}
	tk.DNSExperimentFailure = archival.NewFailure(err)
	return addrs
}
