package nwebconnectivity_test

import (
	"context"
	"errors"
	"testing"

	"github.com/apex/log"
	"github.com/ooni/probe-cli/v3/internal/engine"
	"github.com/ooni/probe-cli/v3/internal/engine/experiment/nwebconnectivity"
	"github.com/ooni/probe-cli/v3/internal/engine/model"
	"github.com/ooni/probe-cli/v3/internal/errorsx"
)

func TestNewExperimentMeasurer(t *testing.T) {
	measurer := nwebconnectivity.NewExperimentMeasurer(nwebconnectivity.Config{})
	if measurer.ExperimentName() != "new_webconnectivity" {
		t.Fatal("unexpected name", measurer.ExperimentName())
	}
	if measurer.ExperimentVersion() != "0.1.0" {
		t.Fatal("unexpected version")
	}
}

func TestSuccess(t *testing.T) {
	if testing.Short() {
		t.Skip("skip test in short mode")
	}
	measurer := nwebconnectivity.NewExperimentMeasurer(nwebconnectivity.Config{})
	ctx := context.Background()
	// we need a real session because we need the web-connectivity helper
	// as well as the ASN database
	sess := newsession(t, true)
	measurement := &model.Measurement{Input: "https://www.google.com/"}
	callbacks := model.NewPrinterCallbacks(log.Log)
	err := measurer.Run(ctx, sess, measurement, callbacks)
	if err != nil {
		t.Fatal(err)
	}
	tk := measurement.TestKeys.(*nwebconnectivity.TestKeys)
	if tk.ControlFailure != nil {
		t.Fatal("unexpected control_failure")
	}
	if tk.DNSExperimentFailure != nil {
		t.Fatal("unexpected dns_experiment_failure")
	}
	if tk.HTTPExperimentFailure != nil {
		t.Fatal("unexpected http_experiment_failure")
	}
}

func newsession(t *testing.T, lookupBackends bool) model.ExperimentSession {
	sess, err := engine.NewSession(context.Background(), engine.SessionConfig{
		AvailableProbeServices: []model.Service{{
			Address: "https://ams-pg-test.ooni.org",
			Type:    "https",
		}},
		Logger:          log.Log,
		SoftwareName:    "ooniprobe-engine",
		SoftwareVersion: "0.0.1",
	})
	if err != nil {
		t.Fatal(err)
	}
	if lookupBackends {
		if err := sess.MaybeLookupBackends(); err != nil {
			t.Fatal(err)
		}
	}
	if err := sess.MaybeLookupLocation(); err != nil {
		t.Fatal(err)
	}
	return sess
}

func TestMeasureWithCancelledContext(t *testing.T) {
	if testing.Short() {
		t.Skip("skip test in short mode")
	}
	measurer := nwebconnectivity.NewExperimentMeasurer(nwebconnectivity.Config{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // immediately fail
	// we need a real session because we need the web-connectivity helper
	sess := newsession(t, true)
	measurement := &model.Measurement{Input: "https://www.google.com/"}
	callbacks := model.NewPrinterCallbacks(log.Log)
	if err := measurer.Run(ctx, sess, measurement, callbacks); err != nil {
		t.Fatal(err)
	}
	tk := measurement.TestKeys.(*nwebconnectivity.TestKeys)
	if *tk.DNSExperimentFailure != errorsx.FailureInterrupted {
		t.Fatal("unexpected dns_experiment_failure")
	}
	if tk.HTTPExperimentFailure != nil {
		t.Fatal("unexpected http_experiment_failure")
	}
	sk, err := measurer.GetSummaryKeys(measurement)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := sk.(nwebconnectivity.SummaryKeys); !ok {
		t.Fatal("invalid type for summary keys")
	}
}

func TestWithTLSParrots(t *testing.T) {
	if testing.Short() {
		t.Skip("skip test in short mode")
	}
	measurer := nwebconnectivity.NewExperimentMeasurer(nwebconnectivity.Config{ClientHello: "Chrome"})
	ctx := context.Background()
	sess := newsession(t, true)
	measurement := &model.Measurement{Input: "https://www.google.com/"}
	callbacks := model.NewPrinterCallbacks(log.Log)
	err := measurer.Run(ctx, sess, measurement, callbacks)
	if err != nil {
		t.Fatal(err)
	}
	tk := measurement.TestKeys.(*nwebconnectivity.TestKeys)
	if tk.ControlFailure != nil {
		t.Fatal("unexpected control_failure")
	}
	if tk.DNSExperimentFailure != nil {
		t.Fatal("unexpected dns_experiment_failure")
	}
	if tk.HTTPExperimentFailure != nil {
		t.Fatal("unexpected http_experiment_failure")
	}
	for _, handshake := range tk.TLSHandshakes {
		// we cannot use utls for h3 yet
		if handshake.NegotiatedProtocol == "h3" {
			continue
		}
		if handshake.Fingerprint != "Chrome" {
			t.Fatal("unexpected TLS Client Hello fingerprint")
		}
	}
}

func TestMeasureWithInputNotBeingAnURL(t *testing.T) {
	if testing.Short() {
		t.Skip("skip test in short mode")
	}
	measurer := nwebconnectivity.NewExperimentMeasurer(nwebconnectivity.Config{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sess := newsession(t, true)
	measurement := &model.Measurement{Input: "\t\t\t\t\t\t"}
	callbacks := model.NewPrinterCallbacks(log.Log)
	err := measurer.Run(ctx, sess, measurement, callbacks)
	if !errors.Is(err, nwebconnectivity.ErrInputIsNotAnURL) {
		t.Fatal(err)
	}
	tk := measurement.TestKeys.(*nwebconnectivity.TestKeys)
	if tk.ControlFailure != nil {
		t.Fatal("unexpected control_failure")
	}
	if tk.DNSExperimentFailure != nil {
		t.Fatal("unexpected dns_experiment_failure")
	}
	if tk.HTTPExperimentFailure != nil {
		t.Fatal("unexpected http_experiment_failure")
	}
}

func TestMeasureWithUnsupportedInput(t *testing.T) {
	if testing.Short() {
		t.Skip("skip test in short mode")
	}
	measurer := nwebconnectivity.NewExperimentMeasurer(nwebconnectivity.Config{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// we need a real session because we need the web-connectivity helper
	sess := newsession(t, true)
	measurement := &model.Measurement{Input: "dnslookup://example.com"}
	callbacks := model.NewPrinterCallbacks(log.Log)
	err := measurer.Run(ctx, sess, measurement, callbacks)
	if !errors.Is(err, nwebconnectivity.ErrUnsupportedInput) {
		t.Fatal(err)
	}
	tk := measurement.TestKeys.(*nwebconnectivity.TestKeys)
	if tk.ControlFailure != nil {
		t.Fatal("unexpected control_failure")
	}
	if tk.DNSExperimentFailure != nil {
		t.Fatal("unexpected dns_experiment_failure")
	}
	if tk.HTTPExperimentFailure != nil {
		t.Fatal("unexpected http_experiment_failure")
	}
}

func TestTLSHandshakeFails(t *testing.T) {
	if testing.Short() {
		t.Skip("skip test in short mode")
	}
	measurer := nwebconnectivity.NewExperimentMeasurer(nwebconnectivity.Config{})
	ctx := context.Background()
	sess := newsession(t, true)
	measurement := &model.Measurement{Input: "https://wrong.host.badssl.com/"}
	callbacks := model.NewPrinterCallbacks(log.Log)
	err := measurer.Run(ctx, sess, measurement, callbacks)
	if err != nil {
		t.Fatal(err)
	}
	tk := measurement.TestKeys.(*nwebconnectivity.TestKeys)
	if tk.ControlFailure != nil {
		t.Fatal("unexpected control_failure")
	}
	if tk.DNSExperimentFailure != nil {
		t.Fatal("unexpected dns_experiment_failure")
	}
	if tk.HTTPExperimentFailure != nil {
		t.Fatal("unexpected http_experiment_failure")
	}
	if len(tk.TLSHandshakes) != 1 {
		t.Fatal("unexpected number of TLS handshakes")
	}
	if tk.TLSHandshakes[0].Failure == nil {
		t.Fatal("expected a TLS handshake failure")
	}
	if *tk.TLSHandshakes[0].Failure != errorsx.FailureSSLInvalidHostname {
		t.Fatal("unexpected failure type")
	}
}

func Test308RedirectWithoutLocationHeader(t *testing.T) {
	if testing.Short() {
		t.Skip("skip test in short mode")
	}
	measurer := nwebconnectivity.NewExperimentMeasurer(nwebconnectivity.Config{})
	ctx := context.Background()
	sess := newsession(t, true)
	measurement := &model.Measurement{Input: "http://test.greenbytes.de/tech/tc/httpredirects/t308empty.asis"}
	callbacks := model.NewPrinterCallbacks(log.Log)
	err := measurer.Run(ctx, sess, measurement, callbacks)
	if err != nil {
		t.Fatal(err)
	}
	tk := measurement.TestKeys.(*nwebconnectivity.TestKeys)
	if tk.ControlFailure != nil {
		t.Fatal("unexpected control_failure")
	}
	if tk.DNSExperimentFailure != nil {
		t.Fatal("unexpected dns_experiment_failure")
	}
	if tk.HTTPExperimentFailure != nil {
		t.Fatal("unexpected http_experiment_failure")
	}
}

func TestIDNARedirect(t *testing.T) {
	if testing.Short() {
		t.Skip("skip test in short mode")
	}
	measurer := nwebconnectivity.NewExperimentMeasurer(nwebconnectivity.Config{})
	ctx := context.Background()
	sess := newsession(t, true)
	measurement := &model.Measurement{Input: "http://яндекс.рф"}
	callbacks := model.NewPrinterCallbacks(log.Log)
	err := measurer.Run(ctx, sess, measurement, callbacks)
	if err != nil {
		t.Fatal(err)
	}
	tk := measurement.TestKeys.(*nwebconnectivity.TestKeys)
	if tk.ControlFailure != nil {
		t.Fatal("unexpected control_failure")
	}
	if tk.DNSExperimentFailure != nil {
		t.Fatal("unexpected dns_experiment_failure")
	}
	if tk.HTTPExperimentFailure != nil {
		t.Fatal("unexpected http_experiment_failure")
	}
}
