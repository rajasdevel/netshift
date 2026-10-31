package discovery

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/rajasdevel/netshift/internal/config"
)

func TestObserverStableUsesOneRequestAndChangesNeedConsensus(t *testing.T) {
	var primaryCalls, secondaryCalls atomic.Int32
	primaryIP, secondaryIP := "8.8.8.8", "8.8.8.8"
	first := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { primaryCalls.Add(1); fmt.Fprint(w, primaryIP) }))
	defer first.Close()
	second := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { secondaryCalls.Add(1); fmt.Fprint(w, secondaryIP) }))
	defer second.Close()
	o := &httpObserver{Sources: []string{first.URL, second.URL}, Client: first.Client()}
	got := o.Observe(t.Context(), "8.8.8.8")
	if !got.Verified || got.IP != "8.8.8.8" || primaryCalls.Load() != 1 || secondaryCalls.Load() != 0 {
		t.Fatalf("stable: %+v", got)
	}
	primaryIP = "8.8.4.4"
	secondaryIP = "1.1.1.1"
	got = o.Observe(t.Context(), "8.8.8.8")
	if !got.Online || got.Verified || got.Err == nil {
		t.Fatalf("disagreement: %+v", got)
	}
	secondaryIP = "8.8.4.4"
	got = o.Observe(t.Context(), "8.8.8.8")
	if !got.Verified || got.IP != "8.8.4.4" {
		t.Fatalf("new IP: %+v", got)
	}
}
func TestObserverRejectsPrivateIPAndDoesNotFollowRedirects(t *testing.T) {
	for _, body := range []string{"127.0.0.1", "10.0.0.1", "100.64.0.2", "0.0.0.0", "203.0.113.1", "2001:4860:4860::8888", "<html>login</html>"} {
		t.Run(body, func(t *testing.T) {
			s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, body) }))
			defer s.Close()
			o := &httpObserver{Sources: []string{s.URL}, Client: s.Client()}
			got := o.Observe(t.Context(), "")
			if got.Online || got.Verified {
				t.Fatalf("accepted %q: %+v", body, got)
			}
		})
	}
	c := config.MonitorConfig{TimeoutSeconds: 1}
	o := New(c)
	if o.Client.CheckRedirect == nil {
		t.Fatal("redirect guard missing")
	}
}
func TestObserverFallbackCannotInventAChange(t *testing.T) {
	bad := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(503) }))
	defer bad.Close()
	good := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "8.8.8.8") }))
	defer good.Close()
	o := &httpObserver{Sources: []string{bad.URL, good.URL}, Client: good.Client()}
	if got := o.Observe(t.Context(), ""); !got.Online || got.Verified {
		t.Fatalf("single-source change: %+v", got)
	}
	if got := o.Observe(t.Context(), "8.8.8.8"); !got.Verified {
		t.Fatalf("stable fallback rejected: %+v", got)
	}
}

// An unexpected answer, such as a captive portal page, is described without
// its content, which may change on every request.
func TestObserverReasonOmitsTheAnswer(t *testing.T) {
	var calls atomic.Int32
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "<html>session %d</html>", calls.Add(1))
	}))
	defer s.Close()
	o := &httpObserver{Sources: []string{s.URL}, Client: s.Client()}
	first, second := o.Observe(t.Context(), ""), o.Observe(t.Context(), "")
	want := "IP discovery unavailable: 127.0.0.1: IP endpoint did not answer with a public IPv4 address"
	if first.Reason != want || second.Reason != want {
		t.Fatalf("reasons: %q %q", first.Reason, second.Reason)
	}
	if !errors.Is(first.Err, errNotIPv4Response) || !strings.Contains(first.Err.Error(), "session 1") {
		t.Fatalf("logged detail: %v", first.Err)
	}
}

func TestFailureReasonHasNoAddresses(t *testing.T) {
	dial := func(addr string, errno syscall.Errno) *net.OpError {
		return &net.OpError{Op: "dial", Net: "tcp4", Addr: &net.TCPAddr{IP: net.ParseIP(addr), Port: 443}, Err: os.NewSyscallError("connect", errno)}
	}
	wrap := func(err error) error { return &url.Error{Op: "Get", URL: "https://a.example/ip", Err: err} }
	for _, test := range []struct {
		err  error
		want string
	}{
		{wrap(dial("192.0.2.1", syscall.ECONNREFUSED)), "a.example: dial: connection refused"},
		{wrap(dial("192.0.2.1", syscall.Errno(10061))), "a.example: dial: connection refused"}, // Winsock
		{wrap(dial("192.0.2.2", syscall.Errno(10051))), "a.example: dial: network unreachable"},
		{wrap(&net.OpError{Op: "read", Net: "tcp", Err: os.NewSyscallError("wsarecv", syscall.Errno(10054))}), "a.example: read: connection reset"},
		{wrap(dial("192.0.2.2", syscall.ENETUNREACH)), "a.example: dial: network unreachable"},
		{wrap(dial("192.0.2.3", syscall.EHOSTUNREACH)), "a.example: dial: network unreachable"},
		{wrap(&net.OpError{Op: "read", Net: "tcp", Source: &net.TCPAddr{IP: net.ParseIP("192.0.2.4"), Port: 50000},
			Err: os.NewSyscallError("read", syscall.ECONNRESET)}), "a.example: read: connection reset"},
		// The transport wraps a failed proxy dial, whose text has the proxy address.
		{wrap(&net.OpError{Op: "proxyconnect", Net: "tcp", Err: dial("192.0.2.5", syscall.ECONNREFUSED)}), "a.example: proxyconnect: connection refused"},
		{wrap(&net.OpError{Op: "proxyconnect", Net: "tcp", Err: dial("192.0.2.6", syscall.EACCES)}), "a.example: proxyconnect: connection failed"},
		{wrap(&net.OpError{Op: "remote error", Err: errors.New("tls: handshake failure")}), "a.example: remote error: TLS alert"},
		{wrap(&tls.CertificateVerificationError{Err: x509.UnknownAuthorityError{}}), "a.example: certificate rejected"},
		{wrap(&tls.CertificateVerificationError{Err: x509.HostnameError{Host: "192.0.2.7"}}), "a.example: certificate rejected"},
		{wrap(&tls.CertificateVerificationError{Err: x509.CertificateInvalidError{Reason: x509.Expired, Detail: "current time 2090-01-01T00:00:00Z is after 2084-01-29T16:00:00Z"}}),
			"a.example: certificate not valid at the current time (check the system clock)"},
		{fmt.Errorf("%w: %w", errNotIPv4Response, errors.New(`not a public IPv4 address: "10.0.0.1"`)), "a.example: IP endpoint did not answer with a public IPv4 address"},
		{errors.New("IP endpoint returned HTTP 503"), "a.example: IP endpoint returned HTTP 503"},
	} {
		if got := FailureReason("https://a.example/ip", test.err); got != test.want {
			t.Errorf("%v: got %q, want %q", test.err, got, test.want)
		}
		if strings.Contains(FailureReason("https://a.example/ip", test.err), "192.0.2.") {
			t.Errorf("%v: reason has an address", test.err)
		}
	}
}

// closeCounter is a transport that counts CloseIdleConnections calls.
type closeCounter struct {
	http.RoundTripper
	closes int
}

func (c *closeCounter) CloseIdleConnections() { c.closes++ }

// The monotonic clock stops while the computer sleeps, so the reuse window
// also follows the wall clock, and a wall clock that moves backwards ends it.
func TestObserverReopensConnectionsByWallClock(t *testing.T) {
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "8.8.8.8") }))
	defer s.Close()
	transport := &closeCounter{RoundTripper: s.Client().Transport}
	start := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	clock := start
	o := &httpObserver{Sources: []string{s.URL}, Client: &http.Client{Transport: transport}, Now: func() time.Time { return clock }}
	for _, step := range []struct {
		at     time.Duration
		closes int
	}{
		{0, 1},                  // the first observation starts a window
		{time.Minute, 1},        // within it
		{5*time.Minute - 1, 1},  // still within it
		{6 * time.Minute, 2},    // past it: a new window until 11 minutes
		{5 * time.Minute, 3},    // the clock moved backwards
		{6 * time.Minute, 3},    // the window restarted at 5 minutes
		{10*time.Minute + 1, 4}, // past that window
		{100 * time.Minute, 5},  // a long sleep, which the monotonic clock misses
		{100*time.Minute + 30e9, 5},
	} {
		clock = start.Add(step.at)
		if got := o.Observe(t.Context(), "8.8.8.8"); !got.Verified {
			t.Fatalf("at %v: %+v", step.at, got)
		}
		if transport.closes != step.closes {
			t.Fatalf("at %v: %d closes, want %d", step.at, transport.closes, step.closes)
		}
	}
}
