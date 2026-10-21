package daemon

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// leaseRenewStub serves the enterprise-lease renew endpoint for renewer
// tests. It records the presented lease tokens and answers per script.
type leaseRenewStub struct {
	t *testing.T
	// respond maps attempt number (1-based) to (status, body). Attempts past
	// the script repeat the last entry.
	respond []struct {
		status int
		body   map[string]any
	}
	calls  atomic.Int32
	tokens chan string
}

func newLeaseRenewStub(t *testing.T) (*leaseRenewStub, *httptest.Server) {
	s := &leaseRenewStub{t: t, tokens: make(chan string, 64)}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/enterprise-lease/renew") {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		if r.Method != http.MethodPost {
			t.Errorf("method = %q", r.Method)
		}
		s.tokens <- r.Header.Get("X-Enterprise-Lease")
		n := int(s.calls.Add(1))
		entry := s.respond[len(s.respond)-1]
		if n <= len(s.respond) {
			entry = s.respond[n-1]
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(entry.status)
		_ = json.NewEncoder(w).Encode(entry.body)
	}))
	t.Cleanup(srv.Close)
	return s, srv
}

func leaseBody(grantID, token string, expiresAt time.Time) map[string]any {
	return map[string]any{
		"grant_id":         grantID,
		"lease_token":      token,
		"lease_expires_at": expiresAt.UTC().Format(time.RFC3339),
	}
}

func waitForCall(t *testing.T, s *leaseRenewStub) string {
	t.Helper()
	select {
	case tok := <-s.tokens:
		return tok
	case <-time.After(5 * time.Second):
		t.Fatal("no renew call within 5s")
		return ""
	}
}

func TestEnterpriseLeaseRenewerRotatesToken(t *testing.T) {
	stub, srv := newLeaseRenewStub(t)
	expiry := time.Now().Add(time.Hour)
	stub.respond = []struct {
		status int
		body   map[string]any
	}{
		{http.StatusOK, leaseBody("g-1", "lease-2", expiry)},
		{http.StatusOK, leaseBody("g-1", "lease-3", expiry)},
	}

	client := NewClient(srv.URL)
	client.SetToken("daemon-token")
	lost := make(chan struct{})
	r := newEnterpriseLeaseRenewer(client, "rt-1", "task-1", EnterpriseLeaseData{
		GrantID:        "g-1",
		LeaseToken:     "lease-1",
		LeaseExpiresAt: expiry.UTC().Format(time.RFC3339),
	}, 20*time.Millisecond, func() { close(lost) }, nil)
	r.start(context.Background())
	defer r.stop()

	if tok := waitForCall(t, stub); tok != "lease-1" {
		t.Fatalf("first renew presented %q, want the claim-issued lease-1", tok)
	}
	if tok := waitForCall(t, stub); tok != "lease-2" {
		t.Fatalf("second renew presented %q, want the rotated lease-2", tok)
	}
	select {
	case <-lost:
		t.Fatal("healthy renewals reported a lease loss")
	default:
	}
	if err := r.lost(); err != nil {
		t.Fatalf("lost() = %v", err)
	}
}

func TestEnterpriseLeaseRenewerTerminalRefusalStopsTheRun(t *testing.T) {
	stub, srv := newLeaseRenewStub(t)
	stub.respond = []struct {
		status int
		body   map[string]any
	}{
		{http.StatusForbidden, map[string]any{"code": "ENTITLEMENT_REVOKED", "error": "revoked"}},
	}

	client := NewClient(srv.URL)
	lost := make(chan error, 1)
	// The renewer sits between the lease and the run's cancel func; the test
	// stands a real cancellable context in for the run to prove the wiring.
	runCtx, runCancel := context.WithCancel(context.Background())
	defer runCancel()
	r := newEnterpriseLeaseRenewer(client, "rt-1", "task-1", EnterpriseLeaseData{
		GrantID:        "g-1",
		LeaseToken:     "lease-1",
		LeaseExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
	}, 20*time.Millisecond, runCancel, nil)
	r.start(context.Background())
	defer r.stop()

	waitForCall(t, stub)
	select {
	case <-runCtx.Done():
		// The refusal cancelled the run context: no new cloud calls happen.
	case <-time.After(5 * time.Second):
		t.Fatal("terminal refusal did not cancel the run context")
	}
	if err := r.lost(); err == nil {
		t.Fatal("lost() = nil after a 403 refusal")
	} else {
		lost <- err
	}
}

func TestEnterpriseLeaseRenewerTransientFailureRetriesUntilExpiry(t *testing.T) {
	stub, srv := newLeaseRenewStub(t)
	// First two calls fail transiently (502), the third succeeds.
	stub.respond = []struct {
		status int
		body   map[string]any
	}{
		{http.StatusBadGateway, map[string]any{"error": "upstream"}},
		{http.StatusBadGateway, map[string]any{"error": "upstream"}},
		{http.StatusOK, leaseBody("g-1", "lease-2", time.Now().Add(time.Hour))},
	}

	client := NewClient(srv.URL)
	r := newEnterpriseLeaseRenewer(client, "rt-1", "task-1", EnterpriseLeaseData{
		GrantID:        "g-1",
		LeaseToken:     "lease-1",
		LeaseExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
	}, 15*time.Millisecond, func() {
		t.Error("transient renewals must not lose the lease")
	}, nil)
	r.start(context.Background())
	defer r.stop()

	waitForCall(t, stub)
	waitForCall(t, stub)
	if tok := waitForCall(t, stub); tok != "lease-1" {
		// Failed renewals keep presenting the same (still-current) lease.
		t.Fatalf("third renew presented %q, want lease-1", tok)
	}
	if err := r.lost(); err != nil {
		t.Fatalf("lost() = %v after a recovered renewal", err)
	}
}

func TestEnterpriseLeaseRenewerExpiresUnrenewed(t *testing.T) {
	stub, srv := newLeaseRenewStub(t)
	// Every renew fails transiently and the lease TTL has already passed.
	stub.respond = []struct {
		status int
		body   map[string]any
	}{
		{http.StatusBadGateway, map[string]any{"error": "upstream"}},
	}

	client := NewClient(srv.URL)
	lost := make(chan struct{})
	r := newEnterpriseLeaseRenewer(client, "rt-1", "task-1", EnterpriseLeaseData{
		GrantID:        "g-1",
		LeaseToken:     "lease-1",
		LeaseExpiresAt: time.Now().Add(-time.Second).UTC().Format(time.RFC3339),
	}, 15*time.Millisecond, func() { close(lost) }, nil)
	r.start(context.Background())
	defer r.stop()

	// The first tick sees the lease already expired: fail closed without
	// calling the renew endpoint at all.
	select {
	case <-lost:
	case <-time.After(5 * time.Second):
		t.Fatal("expired lease was not reported lost")
	}
	if got := stub.calls.Load(); got != 0 {
		t.Fatalf("renew endpoint was called %d times for an expired lease", got)
	}
}

func TestEnterpriseLeaseRenewerStopExitsQuietly(t *testing.T) {
	stub, srv := newLeaseRenewStub(t)
	stub.respond = []struct {
		status int
		body   map[string]any
	}{
		{http.StatusOK, leaseBody("g-1", "lease-2", time.Now().Add(time.Hour))},
	}

	client := NewClient(srv.URL)
	r := newEnterpriseLeaseRenewer(client, "rt-1", "task-1", EnterpriseLeaseData{
		GrantID:        "g-1",
		LeaseToken:     "lease-1",
		LeaseExpiresAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339),
	}, time.Hour, func() { t.Error("stop must not fire onLost") }, nil)
	r.start(context.Background())
	r.stop()

	// A stopped renewer makes no further calls; give the (hour-long) ticker
	// no chance to fire and assert nothing was sent.
	if got := stub.calls.Load(); got != 0 {
		t.Fatalf("stopped renewer called the endpoint %d times", got)
	}
}

func TestStartEnterpriseLeaseRenewalSkipsNonEnterpriseTasks(t *testing.T) {
	d := New(Config{ServerBaseURL: "http://127.0.0.1:1", HeartbeatInterval: time.Hour}, nil)
	if got := d.startEnterpriseLeaseRenewal(Task{ID: "t"}, func() {}, nil); got != nil {
		t.Fatalf("personal task got a renewer: %+v", got)
	}
	if got := d.startEnterpriseLeaseRenewal(Task{ID: "t", Enterprise: true}, func() {}, nil); got != nil {
		t.Fatalf("enterprise task without lease got a renewer: %+v", got)
	}
	if got := d.startEnterpriseLeaseRenewal(Task{
		ID:         "t",
		Enterprise: true,
		EnterpriseLease: &EnterpriseLeaseData{
			GrantID:    "g",
			LeaseToken: "tok",
		},
	}, func() {}, nil); got == nil {
		t.Fatal("enterprise task with a lease got no renewer")
	} else {
		got.stop()
	}
}
