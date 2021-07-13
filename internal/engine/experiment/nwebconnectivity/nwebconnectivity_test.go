package nwebconnectivity_test

import (
	"context"
	"testing"

	"github.com/apex/log"
	"github.com/ooni/probe-cli/v3/internal/engine"
	"github.com/ooni/probe-cli/v3/internal/engine/experiment/nwebconnectivity"
	"github.com/ooni/probe-cli/v3/internal/engine/model"
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
	measurement := &model.Measurement{Input: "https://ooni.com"}
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
