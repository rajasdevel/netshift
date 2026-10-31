// Package discovery finds this machine's public IPv4 address and whether the
// network is usable, by asking independent HTTPS sources, and snapshots the
// active interface addresses for the optional interface_changed event.
package discovery

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/rajasdevel/netshift/internal/config"
	"github.com/rajasdevel/netshift/internal/version"
)

// Observation is the result of one public-IP discovery attempt.
//
// Online means some source answered; Verified means IP is confirmed (it
// matches the stable address, or two sources agree). Err keeps full detail
// for the event log. Reason, when set, is a stable summary that is saved
// instead, so an outage whose low-level errors vary (rotating DNS answers,
// different timeout stages) does not rewrite state on every poll.
type Observation struct {
	IP       string
	Online   bool
	Verified bool
	Err      error
	Reason   string
}

// Observer discovers the current public IPv4. stable is the last confirmed
// address; one matching answer is enough to confirm that it is unchanged.
type Observer interface {
	Observe(ctx context.Context, stable string) Observation
}

// connectionReuse bounds how long a kept-alive connection answers polls. An
// established connection can keep its old route after the default route
// moves (for example when Ethernet joins Wi-Fi or a VPN starts), and would
// keep reporting the old public IP; a new connection follows the new route.
const connectionReuse = 5 * time.Minute

// maxIPResponse bounds an IP discovery response body.
const maxIPResponse = 128

// errNotIPv4Response reports an IP endpoint answer that is not a public IPv4
// address. Its text is fixed; the answer itself stays in the wrapped detail,
// which is logged but never saved as a Reason.
var errNotIPv4Response = errors.New("IP endpoint did not answer with a public IPv4 address")

// httpObserver is the Observer that asks HTTPS endpoints for the public IPv4,
// over IPv4 only, one source at a time in the configured order. It is not
// safe for concurrent use.
type httpObserver struct {
	Sources []string
	Client  *http.Client
	Now     func() time.Time // clock for connection reuse; nil means time.Now

	// Idle connections are closed when either deadline passes. The monotonic
	// clock does not advance while macOS or Linux sleeps, so the wall-clock
	// deadline is what catches a wake-up on another network.
	reuseUntil     time.Time // monotonic deadline
	wallReuseUntil time.Time // wall-clock deadline
	lastWall       time.Time // wall clock at the previous Observe
}

// New returns an observer for the configured sources. Every stage of
// a request is bounded by TimeoutSeconds, and redirects are refused.
func New(c config.MonitorConfig) *httpObserver {
	timeout := time.Duration(c.TimeoutSeconds) * time.Second
	transport := http.DefaultTransport.(*http.Transport).Clone()
	dialer := &net.Dialer{Timeout: timeout, KeepAlive: -1}
	transport.MaxIdleConns = 4
	transport.MaxIdleConnsPerHost = 1
	transport.MaxConnsPerHost = 1
	transport.MaxResponseHeaderBytes = 16384
	transport.ResponseHeaderTimeout = timeout
	transport.TLSHandshakeTimeout = timeout
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		return dialer.DialContext(ctx, "tcp4", address)
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("IP discovery redirects are not accepted")
		},
	}
	return &httpObserver{Sources: c.IPSources, Client: client}
}

// fetch asks one source for the public IPv4.
func (o *httpObserver) fetch(ctx context.Context, source string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, source, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", "NetShift/"+version.Number)
	req.Header.Set("Cache-Control", "no-cache")
	response, err := o.Client.Do(req)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("IP endpoint returned HTTP %d", response.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxIPResponse))
	if err != nil {
		return "", err
	}
	ip, err := config.PublicIPv4(string(body))
	if err != nil {
		return "", fmt.Errorf("%w: %w", errNotIPv4Response, err)
	}
	return ip, nil
}

// refreshConnections closes idle connections once connectionReuse has passed
// since they were last closed, by the monotonic or the wall clock, or when
// the wall clock moved backwards.
func (o *httpObserver) refreshConnections() {
	now := time.Now()
	if o.Now != nil {
		now = o.Now()
	}
	wall := now.Round(0) // drops the monotonic reading
	if now.After(o.reuseUntil) || wall.After(o.wallReuseUntil) || wall.Before(o.lastWall) {
		o.Client.CloseIdleConnections()
		o.reuseUntil = now.Add(connectionReuse)
		o.wallReuseUntil = wall.Add(connectionReuse)
	}
	o.lastWall = wall
}

// Observe asks the sources in order. While the address is unchanged, the
// first source that reports stable confirms it with a single request; a new
// address needs two sources to agree. With answers that disagree it is
// online but unverified; with no answers, offline.
func (o *httpObserver) Observe(ctx context.Context, stable string) Observation {
	o.refreshConnections()
	votes := map[string]int{}
	var failures []error
	var reasons []string
	for _, source := range o.Sources {
		ip, err := o.fetch(ctx, source)
		if err != nil {
			failures = append(failures, err)
			reasons = append(reasons, FailureReason(source, err))
			continue
		}
		if ip == stable {
			return Observation{IP: ip, Online: true, Verified: true}
		}
		votes[ip]++
		if votes[ip] >= 2 {
			return Observation{IP: ip, Online: true, Verified: true}
		}
	}
	if len(votes) > 0 {
		err := errors.New("IP change not confirmed by two independent sources")
		return Observation{Online: true, Err: err, Reason: err.Error()}
	}
	return Observation{
		Err:    fmt.Errorf("IP discovery unavailable: %w", errors.Join(failures...)),
		Reason: "IP discovery unavailable: " + strings.Join(reasons, "; "),
	}
}

// FailureReason describes a failed request without the details that change
// from poll to poll during one outage: addresses, the current time in a
// certificate error, or an endpoint's answer. The error itself is logged.
func FailureReason(source string, err error) string {
	host := source
	if u, e := url.Parse(source); e == nil {
		host = u.Hostname()
	}
	if urlErr, ok := errors.AsType[*url.Error](err); ok {
		err = urlErr.Err
	}
	var certErr x509.CertificateInvalidError
	var verifyErr *tls.CertificateVerificationError
	var dnsErr *net.DNSError
	var netErr net.Error
	var opErr *net.OpError
	switch {
	case errors.Is(err, errNotIPv4Response):
		return host + ": " + errNotIPv4Response.Error()
	case errors.As(err, &certErr) && certErr.Reason == x509.Expired:
		return host + ": certificate not valid at the current time (check the system clock)"
	case errors.As(err, &verifyErr):
		return host + ": certificate rejected"
	case errors.As(err, &dnsErr):
		return host + ": DNS lookup failed"
	case errors.As(err, &netErr) && netErr.Timeout():
		return host + ": timed out"
	case errors.As(err, &opErr):
		// The outermost operation, such as dial, read, or proxyconnect.
		return host + ": " + opErr.Op + ": " + connectionFailure(opErr)
	}
	return host + ": " + err.Error()
}

// connectionFailure classifies a network error by its system error, without
// the local, remote, or proxy addresses its text includes.
func connectionFailure(err *net.OpError) string {
	switch {
	case err.Op == "remote error" || err.Op == "local error":
		return "TLS alert" // how crypto/tls reports an alert
	case errors.Is(err, syscall.ECONNREFUSED), runtime.GOOS == "windows" && winsockRefused(err):
		return "connection refused"
	case errors.Is(err, syscall.ENETUNREACH), errors.Is(err, syscall.EHOSTUNREACH),
		errors.Is(err, syscall.ENETDOWN), errors.Is(err, syscall.EHOSTDOWN),
		errors.Is(err, syscall.EADDRNOTAVAIL), runtime.GOOS == "windows" && winsockUnreachable(err):
		return "network unreachable"
	case errors.Is(err, syscall.ECONNRESET), errors.Is(err, syscall.ECONNABORTED),
		errors.Is(err, syscall.EPIPE), runtime.GOOS == "windows" && winsockReset(err):
		return "connection reset"
	}
	return "connection failed"
}
