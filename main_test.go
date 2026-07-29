package main

import "testing"

func TestOCPathParsesListKeys(t *testing.T) {
	path, err := ocPath("/interfaces/interface[name=xe-0/0/0]/state/counters")
	if err != nil {
		t.Fatalf("ocPath returned an error: %v", err)
	}

	if got, want := len(path.GetElem()), 4; got != want {
		t.Fatalf("element count = %d, want %d", got, want)
	}
	elem := path.GetElem()[1]
	if got, want := elem.GetName(), "interface"; got != want {
		t.Errorf("element name = %q, want %q", got, want)
	}
	if got, want := elem.GetKey()["name"], "xe-0/0/0"; got != want {
		t.Errorf("list key = %q, want %q", got, want)
	}
}

func TestOCPathRejectsInvalidKeys(t *testing.T) {
	for _, input := range []string{
		"/interfaces/interface[name=xe-0/0/0",
		"/interfaces/interface[=xe-0/0/0]",
		"/interfaces/interface[name=xe][name=xe]",
		"/interfaces/interface[name=xe]suffix",
	} {
		if _, err := ocPath(input); err == nil {
			t.Errorf("ocPath(%q) succeeded, want error", input)
		}
	}
}

func TestValidateSubscriptionDurations(t *testing.T) {
	originalSample, originalHeartbeat, originalProbe := *sampleInterval, *heartbeat, *probeTimeout
	t.Cleanup(func() {
		*sampleInterval = originalSample
		*heartbeat = originalHeartbeat
		*probeTimeout = originalProbe
	})

	*sampleInterval = -1
	if err := validateSubscriptionDurations(); err == nil {
		t.Error("negative sample interval was accepted")
	}

	*sampleInterval = originalSample
	*heartbeat = -1
	if err := validateSubscriptionDurations(); err == nil {
		t.Error("negative heartbeat was accepted")
	}
}
