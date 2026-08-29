package main

import "testing"

func TestRenewStatusRoundTrip(t *testing.T) {
	c := &proxyConfig{mainFolder: t.TempDir()}

	if _, ok := c.loadRenewStatus(); ok {
		t.Fatal("expected no status before any write")
	}

	c.writeRenewStatus(2, 5, 1)

	st, ok := c.loadRenewStatus()
	if !ok {
		t.Fatal("expected a status after writeRenewStatus")
	}
	if st.Renewed != 2 || st.Skipped != 5 || st.Failed != 1 {
		t.Errorf("got %+v", st)
	}
	if st.At.IsZero() {
		t.Error("expected At to be set")
	}
}
