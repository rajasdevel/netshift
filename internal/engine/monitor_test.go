package engine

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/rajasdevel/netshift/internal/config"
	"github.com/rajasdevel/netshift/internal/discovery"
	"github.com/rajasdevel/netshift/internal/eventlog"
	"github.com/rajasdevel/netshift/internal/store"
)

// A wrong system clock (a device without a real-time clock, before NTP) makes
// every certificate look expired, and the x509 error text includes the
// current time. The saved reason must not change from poll to poll.
func TestObserverReasonIsStableWhenTheClockIsWrong(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "8.8.8.8") })
	first, second := httptest.NewUnstartedServer(handler), httptest.NewUnstartedServer(handler)
	for _, s := range []*httptest.Server{first, second} {
		s.Config.ErrorLog = log.New(io.Discard, "", 0) // rejected handshakes are expected
		s.StartTLS()
		defer s.Close()
	}
	o := discovery.New(config.MonitorConfig{TimeoutSeconds: 2, IPSources: []string{first.URL, second.URL}})
	transport := o.Client.Transport.(*http.Transport)
	transport.TLSClientConfig = first.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	clock := time.Date(2090, 1, 1, 0, 0, 0, 0, time.UTC) // after the test certificate expires
	transport.TLSClientConfig.Time = func() time.Time { return clock }
	e, _, now := featureEngine(t)
	writes := 0
	e.Save = func(*store.State) error { writes++; return nil }
	var logged bytes.Buffer
	e.Log = eventlog.Logger{Out: &logged}
	reasons := map[string]bool{}
	for range 5 {
		clock = clock.Add(30 * time.Second)
		*now = now.Add(30 * time.Second)
		got := o.Observe(t.Context(), "8.8.8.8")
		if got.Online || got.Err == nil {
			t.Fatalf("expired certificate accepted: %+v", got)
		}
		reasons[got.Reason] = true
		if err := e.step(t.Context(), got, acceptConfirmed, reapplyStale); err != nil {
			t.Fatal(err)
		}
	}
	want := "IP discovery unavailable: 127.0.0.1: certificate not valid at the current time (check the system clock); " +
		"127.0.0.1: certificate not valid at the current time (check the system clock)"
	if len(reasons) != 1 || !reasons[want] {
		t.Fatalf("reasons: %v", reasons)
	}
	if writes != e.Config.Monitor.OfflineConfirmations || strings.Count(logged.String(), "observation_unavailable") != 1 {
		t.Fatalf("writes=%d log=%s", writes, logged.String())
	}
	// The log keeps the full detail.
	if !strings.Contains(logged.String(), "x509") {
		t.Fatalf("log lost the certificate error: %s", logged.String())
	}
}
