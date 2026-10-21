package daemon

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"sync"
	"time"
)

// Enterprise lease renewal (TASK-C02 / BND-110).
//
// A claimed enterprise task carries a server-minted platform lease with a
// 30s TTL and a 15s renewal grace window on the platform side. While the
// task runs, the daemon renews that lease through the server every
// enterpriseLeaseRenewInterval. Renewal presents the current lease token as
// X-Enterprise-Lease; the platform rotates the token on each successful
// renewal, so the loop always presents the newest one.
//
// Failure semantics are fail-closed: a terminal refusal (401 LEASE_EXPIRED,
// 403 ENTITLEMENT_REVOKED) stops the task immediately, and a lease that
// reaches its expiry unrenewed (e.g. the platform stayed unreachable through
// the whole TTL) stops it then. "Stops the task" means cancelling the run
// context — the agent process is killed, so no new cloud calls can happen
// without a live lease.

// enterpriseLeaseRenewInterval is how often a running enterprise task's
// lease is renewed. The 10s tick keeps the lease alive across two missed
// beats before the 30s TTL runs out.
const enterpriseLeaseRenewInterval = 10 * time.Second

// enterpriseLeaseRenewer drives one task's renewal loop. Construct with
// newEnterpriseLeaseRenewer, run start, and always stop() at the task's
// terminal state so the goroutine never outlives the run.
type enterpriseLeaseRenewer struct {
	client   *Client
	runtimeID string
	taskID    string
	interval  time.Duration
	logger    *slog.Logger
	// onLost fires exactly once when the lease becomes unrecoverable
	// (terminal refusal or expiry without a successful renewal). It cancels
	// the run context at the call site.
	onLost func()

	mu        sync.Mutex
	token     string
	expiresAt time.Time
	lostErr   error

	stopCh chan struct{}
	doneCh chan struct{}
}

// newEnterpriseLeaseRenewer parses the claim-issued lease. An unparseable
// expiry degrades to "renew or lose it at the first failure": expiresAt zero
// is treated as already-expired so the first renewal error is terminal.
func newEnterpriseLeaseRenewer(client *Client, runtimeID, taskID string, lease EnterpriseLeaseData, interval time.Duration, onLost func(), logger *slog.Logger) *enterpriseLeaseRenewer {
	if logger == nil {
		logger = slog.Default()
	}
	r := &enterpriseLeaseRenewer{
		client:    client,
		runtimeID: runtimeID,
		taskID:    taskID,
		interval:  interval,
		logger:    logger.With("task_id", taskID),
		onLost:    onLost,
		token:     lease.LeaseToken,
		stopCh:    make(chan struct{}),
		doneCh:    make(chan struct{}),
	}
	if ts, err := time.Parse(time.RFC3339, lease.LeaseExpiresAt); err == nil {
		r.expiresAt = ts
	} else {
		r.logger.Warn("enterprise lease expiry unparseable; first renewal failure is terminal",
			"lease_expires_at", lease.LeaseExpiresAt, "error", err)
	}
	return r
}

func (r *enterpriseLeaseRenewer) start(ctx context.Context) {
	go r.loop(ctx)
}

func (r *enterpriseLeaseRenewer) stop() {
	close(r.stopCh)
	<-r.doneCh
}

// lost reports the terminal lease failure, nil while the lease is healthy.
func (r *enterpriseLeaseRenewer) lost() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.lostErr
}

func (r *enterpriseLeaseRenewer) loop(ctx context.Context) {
	defer close(r.doneCh)
	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()
	for {
		select {
		case <-r.stopCh:
			return
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !r.renewOnce(ctx) {
				return
			}
		}
	}
}

// renewOnce performs one renewal tick. It returns false when the loop must
// stop: the lease was lost (onLost fired) or the renewer was stopped.
func (r *enterpriseLeaseRenewer) renewOnce(ctx context.Context) bool {
	r.mu.Lock()
	token := r.token
	expiresAt := r.expiresAt
	r.mu.Unlock()

	// Fail closed at expiry: a lease past its TTL proves nothing about the
	// subject's current entitlement, so an unrenewed expired lease stops the
	// task even when the renew transport error looked transient.
	if expiresAt.IsZero() || !time.Now().Before(expiresAt) {
		r.markLost(errors.New("enterprise lease expired without renewal"))
		return false
	}

	renewed, err := r.client.RenewEnterpriseLease(ctx, r.runtimeID, r.taskID, token)
	if err == nil {
		r.mu.Lock()
		r.token = renewed.LeaseToken
		if ts, perr := time.Parse(time.RFC3339, renewed.LeaseExpiresAt); perr == nil {
			r.expiresAt = ts
		} else {
			// A missing/unparseable expiry on a successful renewal must not
			// resurrect an already-expired lease; assume the platform TTL.
			r.expiresAt = time.Now().Add(30 * time.Second)
		}
		r.mu.Unlock()
		return true
	}

	if isTerminalLeaseRenewError(err) {
		r.markLost(err)
		return false
	}
	r.logger.Warn("enterprise lease renewal failed; retrying until lease expiry", "error", err)
	select {
	case <-r.stopCh:
		return false
	case <-ctx.Done():
		return false
	default:
		return true
	}
}

// isTerminalLeaseRenewError reports whether a renewal failure ends the task
// now rather than retrying until the lease TTL: the server surfaced the
// platform's 401 LEASE_EXPIRED or 403 ENTITLEMENT_REVOKED.
func isTerminalLeaseRenewError(err error) bool {
	var reqErr *requestError
	if !errors.As(err, &reqErr) {
		return false
	}
	return reqErr.StatusCode == http.StatusUnauthorized || reqErr.StatusCode == http.StatusForbidden
}

func (r *enterpriseLeaseRenewer) markLost(err error) {
	r.mu.Lock()
	if r.lostErr != nil {
		r.mu.Unlock()
		return
	}
	r.lostErr = err
	r.mu.Unlock()
	r.logger.Warn("enterprise lease lost; stopping task", "error", err)
	if r.onLost != nil {
		r.onLost()
	}
}

// startEnterpriseLeaseRenewal starts the renewal loop for a claimed
// enterprise task. runCancel is the run-context cancel: losing the lease
// kills the run so no new cloud calls happen without a live lease. Personal
// tasks and enterprise tasks without lease material (a server predating
// enterprise_lease) get no loop — nil is returned and the caller must not
// stop() it. The loop outlives runCtx (renewals ride the daemon lifecycle
// context, so cancelling the run cannot strand an in-flight renewal).
func (d *Daemon) startEnterpriseLeaseRenewal(task Task, runCancel context.CancelFunc, taskLog *slog.Logger) *enterpriseLeaseRenewer {
	if !task.Enterprise || task.EnterpriseLease == nil {
		return nil
	}
	if task.EnterpriseLease.LeaseToken == "" || task.EnterpriseLease.GrantID == "" {
		taskLog.Warn("enterprise task claimed without lease material; no renewal loop", "task_id", task.ID)
		return nil
	}
	renewer := newEnterpriseLeaseRenewer(d.client, task.RuntimeID, task.ID, *task.EnterpriseLease,
		enterpriseLeaseRenewInterval, runCancel, taskLog)
	renewer.start(d.recoveryContext())
	return renewer
}
