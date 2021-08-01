package nwebconnectivity

import (
	"context"
	"crypto/x509"
	"net/url"
	"strings"
	"time"

	"github.com/ooni/probe-cli/v3/internal/engine/geolocate"
	"github.com/ooni/probe-cli/v3/internal/engine/model"
	"github.com/ooni/probe-cli/v3/internal/engine/netx/archival"
	"github.com/ooni/probe-cli/v3/internal/errorsx"
	"github.com/ooni/probe-cli/v3/internal/netxlite"
	"golang.org/x/net/idna"
)

type DNSConfig struct {
	Measurement *model.Measurement
	URL         *url.URL
}

// dnsLookup finds the IP address(es) associated with a domain name
func dnsLookup(ctx context.Context, config *DNSConfig) []string {
	tk := config.Measurement.TestKeys.(*TestKeys)
	resolver := &errorsx.ErrorWrapperResolver{Resolver: &netxlite.ResolverSystem{}}
	hostname := config.URL.Hostname()
	idnaHost, err := idna.ToASCII(hostname)
	if err != nil {
		tk.DNSExperimentFailure = archival.NewFailure(err)
		return nil
	}
	addrs, err := resolver.LookupHost(ctx, idnaHost)
	stop := time.Now()
	for _, qtype := range []dnsQueryType{"A", "AAAA"} {
		entry := makeDNSQueryEntry(config.Measurement.MeasurementStartTimeSaved, stop)
		entry.setMetadata(resolver, hostname)
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

// TODO(kelmenhorst): this part is stolen from archival.
// decide: make archival functions public or repeat ourselves?
type dnsQueryType string

func (qtype dnsQueryType) ipoftype(addr string) bool {
	switch qtype {
	case "A":
		return !strings.Contains(addr, ":")
	case "AAAA":
		return strings.Contains(addr, ":")
	}
	return false
}

func (qtype dnsQueryType) makeanswerentry(addr string) archival.DNSAnswerEntry {
	answer := archival.DNSAnswerEntry{AnswerType: string(qtype)}
	asn, org, _ := geolocate.LookupASN(addr)
	answer.ASN = int64(asn)
	answer.ASOrgName = org
	switch qtype {
	case "A":
		answer.IPv4 = addr
	case "AAAA":
		answer.IPv6 = addr
	}
	return answer
}

func makePeerCerts(in []*x509.Certificate) (out []archival.MaybeBinaryValue) {
	for _, e := range in {
		out = append(out, archival.MaybeBinaryValue{Value: string(e.Raw)})
	}
	return
}
