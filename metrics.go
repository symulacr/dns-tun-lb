package main

import (
	"context"
	"net"
	"sync"
	"time"

	"sync/atomic"

	"github.com/prometheus/client_golang/prometheus"
)

// Defensive bound to prevent memory DoS from unbounded map growth.
const defaultMaxSessions = 100000

// backendLabelID returns the label value for backend_id, substituting "unnamed" for empty IDs.
func backendLabelID(backend BackendConfig) string {
	if backend.ID == "" {
		return "unnamed"
	}
	return backend.ID
}

// metricKey builds a lookup key using NUL separators and a stack buffer.
func metricKey(protocol, pool, domain string, backend BackendConfig) string {
	var keyBuf [256]byte
	n := copy(keyBuf[:], protocol)
	n += copy(keyBuf[n:], "\x00")
	n += copy(keyBuf[n:], pool)
	n += copy(keyBuf[n:], "\x00")
	n += copy(keyBuf[n:], domain)
	n += copy(keyBuf[n:], "\x00")
	n += copy(keyBuf[n:], backendLabelID(backend))
	return string(keyBuf[:n])
}

// sessionKey avoids string concatenation allocations on the hot path.
type sessionKey struct {
	protocol string
	pool     string
	domain   string
	backend  string
	sid      [8]byte
}

// sessionTracker tracks approximate active sessions per backend with a TTL.
// Bounded by maxSessions; evicts oldest entry when at capacity on new insert.
type sessionTracker struct {
	mu          sync.Mutex
	sessions    map[sessionKey]time.Time
	ttl         time.Duration
	maxSessions int
	backends    map[string]*resolvedBackendMetrics
}

func newSessionTracker(ttl time.Duration) *sessionTracker {
	return &sessionTracker{
		sessions:    make(map[sessionKey]time.Time),
		ttl:         ttl,
		maxSessions: defaultMaxSessions,
	}
}

// When at maxSessions and the key is new, evicts the oldest entry first.
// Returns true if the session already existed (update), false if new.
func (t *sessionTracker) add(key sessionKey, lastSeen time.Time) bool {
	t.mu.Lock()
	defer t.mu.Unlock()

	_, existed := t.sessions[key]

	if !existed && len(t.sessions) >= t.maxSessions {
		// Evict oldest entry to stay within bound.
		var oldestKey sessionKey
		var oldestTime time.Time
		for k, v := range t.sessions {
			if oldestKey == (sessionKey{}) || v.Before(oldestTime) {
				oldestKey = k
				oldestTime = v
			}
		}
		if oldestKey != (sessionKey{}) {
			delete(t.sessions, oldestKey)
		}
	}

	t.sessions[key] = lastSeen
	return existed
}

func (t *sessionTracker) observeSession(protocol, pool, domain string, backend BackendConfig, sid []byte, bm *resolvedBackendMetrics) {
	if len(sid) == 0 {
		return
	}
	var sk sessionKey
	sk.protocol = protocol
	sk.pool = pool
	sk.domain = domain
	sk.backend = backend.ID
	copy(sk.sid[:], sid)
	now := time.Now()

	existed := t.add(sk, now)

	if !existed {
		if bm != nil {
			bm.sessionsTotal.Add(1)
			bm.sessionsActive.Inc()
		}
	}
}

// prune removes entries idle past the TTL and decrements active gauges.
// Deletions are batched to bound lock hold time per call (at most 100 per invocation).
func (t *sessionTracker) prune() {
	now := time.Now()
	t.mu.Lock()

	toDelete := make([]sessionKey, 0, 100)
	for key, last := range t.sessions {
		if now.Sub(last) > t.ttl {
			toDelete = append(toDelete, key)
			if len(toDelete) >= 100 {
				break
			}
		}
	}
	for _, key := range toDelete {
		backendSessionsActive.With(map[string]string{
			"protocol":   key.protocol,
			"pool":       key.pool,
			"domain":     key.domain,
			"backend_id": key.backend,
		}).Dec()
		delete(t.sessions, key)
	}
	t.mu.Unlock()
}
// flushMetrics flushes all backends' atomic counters to their Prometheus handles.
func (st *sessionTracker) flushMetrics() {
	for _, bm := range st.backends {
		bm.flushToPrometheus()
	}
}

// startJanitor runs prune + flush in a single goroutine.
func (st *sessionTracker) startJanitor(ctx context.Context, interval time.Duration) {
	if st == nil {
		return
	}
	flushTicker := time.NewTicker(15 * time.Second)
	pruneTicker := time.NewTicker(interval)
	defer flushTicker.Stop()
	defer pruneTicker.Stop()
	go func() {
		for {
			select {
			case <-flushTicker.C:
				st.flushMetrics()
			case <-pruneTicker.C:
				st.prune()
			case <-ctx.Done():
				return
			}
		}
	}()
}

// startMinimalMetrics serves a JSON health endpoint without Prometheus overhead.
func startMinimalMetrics(addr string) {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		logErrorf("metrics listen failed", "error", err)
		return
	}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				conn.SetDeadline(time.Now().Add(5 * time.Second))
				buf := make([]byte, 256)
				n, _ := conn.Read(buf)
				if n > 0 {
					conn.Write([]byte("HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n\r\n{\"status\":\"ok\"}\n"))
				}
			}(c)
		}
	}()
}


var (
	dnsRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "dns_lb_requests_total",
			Help: "Total incoming DNS requests, by protocol.",
		},
		[]string{"protocol"},
	)
	dnsRoutedRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "dns_lb_routed_requests_total",
			Help: "Total DNS requests routed to tunnel backends, by protocol and pool.",
		},
		[]string{"protocol", "pool"},
	)
	dnsForwardedRequestsTotal = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "dns_lb_forwarded_requests_total",
			Help: "Total DNS requests forwarded to upstream resolvers (non-tunnel).",
		},
	)
	dnsDroppedRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "dns_lb_dropped_requests_total",
			Help: "Total DNS requests dropped at the load balancer, by reason.",
		},
		[]string{"reason"},
	)
	frontendBytesIn = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "dns_lb_frontend_bytes_in_total",
			Help: "Total bytes received on the frontend UDP socket.",
		},
	)
	frontendBytesOut = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "dns_lb_frontend_bytes_out_total",
			Help: "Total bytes sent on the frontend UDP socket.",
		},
	)
	frontendPacketsIn = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "dns_lb_frontend_packets_in_total",
			Help: "Total UDP packets received on the frontend.",
		},
	)
	frontendPacketsOut = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "dns_lb_frontend_packets_out_total",
			Help: "Total UDP packets sent on the frontend.",
		},
	)
	frontendPacketsDropped = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "dns_lb_frontend_packets_dropped_total",
			Help: "Total UDP packets dropped due to backpressure (worker pool full).",
		},
	)
	parseErrorsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "dns_lb_parse_errors_total",
			Help: "Total DNS unpack or parse errors, by stage.",
		},
		[]string{"stage"},
	)
	unsupportedQueriesTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "dns_lb_unsupported_queries_total",
			Help: "Total non-TXT queries that matched a tunnel pool (by QTYPE); not forwarded to pool.",
		},
		[]string{"qtype"},
	)
	backendBytesSent = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "dns_lb_backend_bytes_sent_total",
			Help: "Total bytes sent to backends, by protocol/pool/domain/backend.",
		},
		[]string{"protocol", "pool", "domain", "backend_id"},
	)
	backendBytesReceived = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "dns_lb_backend_bytes_received_total",
			Help: "Total bytes received from backends, by protocol/pool/domain/backend.",
		},
		[]string{"protocol", "pool", "domain", "backend_id"},
	)
	backendPacketsSent = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "dns_lb_backend_packets_sent_total",
			Help: "Total packets sent to backends, by protocol/pool/domain/backend.",
		},
		[]string{"protocol", "pool", "domain", "backend_id"},
	)
	backendPacketsReceived = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "dns_lb_backend_packets_received_total",
			Help: "Total packets received from backends, by protocol/pool/domain/backend.",
		},
		[]string{"protocol", "pool", "domain", "backend_id"},
	)
	backendRequestsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "dns_lb_backend_requests_total",
			Help: "Total DNS requests routed to backends, by protocol/pool/domain/backend.",
		},
		[]string{"protocol", "pool", "domain", "backend_id"},
	)
	backendErrorsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "dns_lb_backend_errors_total",
			Help: "Total backend errors, by protocol/pool/domain/backend/stage.",
		},
		[]string{"protocol", "pool", "domain", "backend_id", "stage"},
	)
	backendSessionsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "dns_lb_backend_sessions_total",
			Help: "Total distinct sessions observed per backend, by protocol/pool/domain/backend.",
		},
		[]string{"protocol", "pool", "domain", "backend_id"},
	)
	backendSessionsActive = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "dns_lb_backend_sessions_active",
			Help: "Approximate number of active sessions per backend, by protocol/pool/domain/backend.",
		},
		[]string{"protocol", "pool", "domain", "backend_id"},
	)
)

// reg is a custom Prometheus registry that excludes the GoCollector and
// ProcessCollector (auto-registered by the default registry, adding ~2.3 MB
// of metrics state). Runtime metrics remain available via pprof.
var reg = prometheus.NewRegistry()

// labelsForBackend builds the common label set for per-backend metrics.
func labelsForBackend(protocol, pool, domain string, backend BackendConfig) prometheus.Labels {
	return prometheus.Labels{
		"protocol":   protocol,
		"pool":       pool,
		"domain":     domain,
		"backend_id": backendLabelID(backend),
	}
}

// resolvedBackendMetrics holds per-backend metric state with atomic hot path.
type resolvedBackendMetrics struct {
	// Hot path: atomic counters (no Prometheus mutex overhead)
	requestsTotal   atomic.Uint64
	bytesSent       atomic.Uint64
	bytesReceived   atomic.Uint64
	packetsSent     atomic.Uint64
	packetsReceived atomic.Uint64
	sessionsTotal   atomic.Uint64

	// Cold path: Prometheus handles (for scraping / periodic flush)
	promRequestsTotal   prometheus.Counter
	promBytesSent       prometheus.Counter
	promBytesReceived   prometheus.Counter
	promPacketsSent     prometheus.Counter
	promPacketsReceived prometheus.Counter
	promSessionsTotal   prometheus.Counter

	// Per-protocol: Prometheus (rarely called, not hot-path enough to warrant atomic)
	requestsDNSTT      prometheus.Counter
	requestsSlipstream prometheus.Counter
	requestsNoizdns    prometheus.Counter

	// Labeled at call time: stays Prometheus
	errorsTotal    *prometheus.CounterVec
	sessionsActive prometheus.Gauge
}

// flushToPrometheus reads current atomic counter values and adds them to the
// corresponding Prometheus counters, then resets the atomics to zero.
func (bm *resolvedBackendMetrics) flushToPrometheus() {
	if val := bm.requestsTotal.Swap(0); val > 0 {
		bm.promRequestsTotal.Add(float64(val))
	}
	if val := bm.bytesSent.Swap(0); val > 0 {
		bm.promBytesSent.Add(float64(val))
	}
	if val := bm.bytesReceived.Swap(0); val > 0 {
		bm.promBytesReceived.Add(float64(val))
	}
	if val := bm.packetsSent.Swap(0); val > 0 {
		bm.promPacketsSent.Add(float64(val))
	}
	if val := bm.packetsReceived.Swap(0); val > 0 {
		bm.promPacketsReceived.Add(float64(val))
	}
	if val := bm.sessionsTotal.Swap(0); val > 0 {
		bm.promSessionsTotal.Add(float64(val))
	}
}

func init() {
	reg.MustRegister(
		dnsRequestsTotal,
		dnsRoutedRequestsTotal,
		dnsForwardedRequestsTotal,
		dnsDroppedRequestsTotal,
		frontendBytesIn,
		frontendBytesOut,
		frontendPacketsDropped,
		frontendPacketsIn,
		frontendPacketsOut,
		parseErrorsTotal,
		unsupportedQueriesTotal,
		backendBytesSent,
		backendBytesReceived,
		backendPacketsSent,
		backendPacketsReceived,
		backendRequestsTotal,
		backendErrorsTotal,
		backendSessionsTotal,
		backendSessionsActive,
	)
}
