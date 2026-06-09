package main

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// backendPool is a named set of backends for one domain suffix.
type backendPool struct {
	protocol     string
	name         string
	domainSuffix string
	ring         *hashRing
	backends     []BackendConfig
}

type server struct {
	// HOT — accessed on every packet
	conn           net.PacketConn
	reuseConns     []net.PacketConn
	udpConn        *net.UDPConn
	pools          []backendPool
	workCh         chan packetJob
	backendConns   map[string]*net.UDPConn
	backendMetrics map[string]*resolvedBackendMetrics
	limiter        chan struct{}

	// COLD — setup/shutdown only
	cfg                 *Config
	sessionTracker      *sessionTracker
	forwardAddr         *net.UDPAddr
	// HOT — accessed on every packet
	direct              bool
	poolBypassThreshold int
	activeCount         uint64
	workerWg            sync.WaitGroup
	// Dynamic pool
	poolMin    int32
	poolMax    int32
	poolCur    atomic.Int32
	poolAuto   bool
	workChCap  int
	poolMu     sync.Mutex
	workerStop []chan struct{}
}

// buildPoolSlice appends pools from cfgs, deduplicating by domain suffix.
func buildPoolSlice(pools []backendPool, cfgs []PoolConfig, protocol string, conn net.PacketConn, seenSuffix map[string]string) ([]backendPool, error) {
	for _, p := range cfgs {
		if strings.TrimSpace(p.DomainSuffix) == "" {
			conn.Close()
			return nil, fmt.Errorf("%s pool %q has empty domain_suffix", protocol, p.Name)
		}
		if len(p.Backends) == 0 {
			continue
		}
		for _, b := range p.Backends {
			if b.ID == "" {
				conn.Close()
				return nil, fmt.Errorf("%s pool %q: backend has empty id", protocol, p.Name)
			}
		}
		for i := range p.Backends {
			addr, err := net.ResolveUDPAddr("udp", p.Backends[i].Address)
			if err != nil {
				conn.Close()
				return nil, fmt.Errorf("pool %q: resolve %s: %w", p.Name, p.Backends[i].Address, err)
			}
			p.Backends[i].parsedAddr = addr
		}
		suffixKey := strings.ToLower(strings.TrimSpace(p.DomainSuffix))
		if prev := seenSuffix[suffixKey]; prev != "" {
			conn.Close()
			return nil, fmt.Errorf("duplicate domain_suffix %q: already used by %s (%s pool %q)", p.DomainSuffix, prev, protocol, p.Name)
		}
		seenSuffix[suffixKey] = protocol + " pool " + p.Name
		ring := newHashRing(p.Backends, 0)
		pools = append(pools, backendPool{
			protocol:     protocol,
			name:         p.Name,
			domainSuffix: suffixKey,
			backends:     p.Backends,
			ring:         ring,
		})
	}
	return pools, nil
}

func closeAllConns(conns []net.PacketConn) {
	for _, c := range conns {
		c.Close()
	}
}

func newServer(cfg *Config) (*server, error) {
	var err error
	if strings.TrimSpace(cfg.Global.ListenAddress) == "" {
		return nil, fmt.Errorf("global.listen_address is required and cannot be empty")
	}
	const recvBufSize = 4 << 20 // 4 MiB
	reuse := cfg.Global.ReusePort
	if reuse < 0 {
		return nil, fmt.Errorf("global.reuse_port must be >= 0")
	}
	if reuse == 0 {
		reuse = 1
	}
	lc := net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var sockErr error
			c.Control(func(fd uintptr) {
				sockErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_RCVBUF, recvBufSize)
				if sockErr != nil {
					return
				}
				if reuse > 0 {
					if err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, unix.SO_REUSEPORT, 1); err != nil {
						logDebugf("reuseport not available")
					}
					if err := syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); err != nil {
						logDebugf("reuseaddr not available")
					}
				}
				if err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_BUSY_POLL, 50); err != nil {
					logDebugf("busy poll not available")
				}
			})
			return sockErr
		},
	}
	conns := make([]net.PacketConn, reuse)
	for i := range conns {
		conns[i], err = lc.ListenPacket(context.Background(), "udp", cfg.Global.ListenAddress)
		if err != nil {
			for j := 0; j < i; j++ {
				conns[j].Close()
			}
			return nil, err
		}
	}
	conn := conns[0]

	var udpConn *net.UDPConn
	if uc, ok := conn.(*net.UDPConn); ok {
		udpConn = uc
	}

	var forwardAddr *net.UDPAddr
	if cfg.Global.DefaultDNSBehavior.Mode == DefaultDNSModeForward {
		if cfg.Global.DefaultDNSBehavior.ForwardResolver == "" {
			closeAllConns(conns)
			return nil, fmt.Errorf("default_dns_behavior.mode is 'forward' but forward_resolver is empty")
		}
		forwardAddr, err = net.ResolveUDPAddr("udp", cfg.Global.DefaultDNSBehavior.ForwardResolver)
		if err != nil {
			closeAllConns(conns)
			return nil, err
		}
	}

	var pools []backendPool
	seenSuffix := make(map[string]string)
	pools, err = buildPoolSlice(pools, cfg.Protocols.Dnstt.Pools, "dnstt", conn, seenSuffix)
	if err != nil {
		return nil, err
	}
	for _, p := range cfg.Protocols.Slipstream.Pools {
		if len(p.Backends) == 0 {
			continue
		}
		seenLbID := make(map[uint8]string)
		for _, b := range p.Backends {
			if b.LbID == nil {
				closeAllConns(conns)
				return nil, fmt.Errorf("slipstream pool %q backend %q missing required lb_id", p.Name, b.ID)
			}
			if prev := seenLbID[*b.LbID]; prev != "" {
				closeAllConns(conns)
				return nil, fmt.Errorf("slipstream pool %q duplicate lb_id %d (backends %q and %q)", p.Name, *b.LbID, prev, b.ID)
			}
			seenLbID[*b.LbID] = b.ID
		}
	}
	pools, err = buildPoolSlice(pools, cfg.Protocols.Slipstream.Pools, "slipstream", conn, seenSuffix)
	if err != nil { return nil, err }
	pools, err = buildPoolSlice(pools, cfg.Protocols.Noizdns.Pools, "noizdns", conn, seenSuffix)
	if err != nil { return nil, err }

	var limiter chan struct{}
	if cfg.Global.MaxConcurrent > 0 {
		limiter = make(chan struct{}, cfg.Global.MaxConcurrent)
	}
	backendConns := make(map[string]*net.UDPConn)
	for _, p := range pools {
		for _, b := range p.backends {
			if b.parsedAddr == nil {
				continue
			}
			addrKey := b.Address
			if _, exists := backendConns[addrKey]; exists {
				continue
			}
			conn, err := dialUDPWithBuf(nil, b.parsedAddr, sendBufSize)
			if err != nil {
				logDebugf("persistent conn", "addr", addrKey, "error", err)
				continue
			}
			backendConns[addrKey] = conn
		}
	}

	backendMetricsMap := make(map[string]*resolvedBackendMetrics)
	for _, p := range pools {
		for _, b := range p.backends {
			key := metricKey(p.protocol, p.name, p.domainSuffix, b)
			labels := labelsForBackend(p.protocol, p.name, p.domainSuffix, b)
			bm := &resolvedBackendMetrics{
				promRequestsTotal:   backendRequestsTotal.With(labels),
				errorsTotal:         backendErrorsTotal,
				promBytesSent:       backendBytesSent.With(labels),
				promBytesReceived:   backendBytesReceived.With(labels),
				promPacketsSent:     backendPacketsSent.With(labels),
				promPacketsReceived: backendPacketsReceived.With(labels),
				promSessionsTotal:   backendSessionsTotal.With(labels),
				sessionsActive:      backendSessionsActive.With(labels),
			}
			// Pre-resolve per-protocol counters (avoids WithLabelValues alloc).
			switch p.protocol {
			case "dnstt":
				bm.requestsDNSTT = dnsRequestsTotal.WithLabelValues("dnstt")
			case "slipstream":
				bm.requestsSlipstream = dnsRequestsTotal.WithLabelValues("slipstream")
			case "noizdns":
				bm.requestsNoizdns = dnsRequestsTotal.WithLabelValues("noizdns")
			}
			backendMetricsMap[key] = bm
		}
	}

	workChBuf := cfg.Global.MaxConcurrent
	if workChBuf <= 0 { workChBuf = 1024 }

	return &server{
		cfg:             cfg,
		conn:            conn,
		reuseConns:      conns,
		udpConn:         udpConn,
		pools:           pools,
		forwardAddr:     forwardAddr,
		sessionTracker:  newSessionTracker(10 * time.Minute),
		workCh:              make(chan packetJob, workChBuf),
		direct:              cfg.Global.Direct,
		poolBypassThreshold: cfg.Global.PoolBypassThreshold,
		limiter:         limiter,
		backendConns:    backendConns,
		backendMetrics:  backendMetricsMap,
	}, nil
}

func longestMatchingPool(qname string, pools []backendPool) *backendPool {
	var best *backendPool
	for i := range pools {
		p := &pools[i]
		if !hasSuffixDomain(qname, p.domainSuffix) {
			continue
		}
		if best == nil || len(p.domainSuffix) > len(best.domainSuffix) {
			best = p
		}
	}
	return best
}

// packetJob is a unit of work sent from the receive loop to the worker pool.
type packetJob struct {
	pkt     []byte
	addr    net.Addr
	poolBuf *[]byte // returned to pool after processing
}

// workerState holds per-goroutine state; each worker owns its backend connections.
type workerState struct {
	idx          int
	backendConns map[string]*net.UDPConn
}

func (s *server) startWorkers(initial int) {
	s.poolMin = int32(initial)
	s.poolMax = int32(initial * 5)
	s.poolCur.Store(0) // spawnWorker handles count
	s.workChCap = cap(s.workCh)
	s.poolMu.Lock()
	s.workerStop = make([]chan struct{}, 0, initial)
	s.poolMu.Unlock()

	for i := 0; i < initial; i++ {
		s.spawnWorker()
	}
}

func (s *server) spawnWorker() {
	ws := &workerState{
		idx:          int(s.poolCur.Load()),
		backendConns: make(map[string]*net.UDPConn),
	}
	stopCh := make(chan struct{})

	s.poolMu.Lock()
	s.workerStop = append(s.workerStop, stopCh)
	s.poolMu.Unlock()

	s.poolCur.Add(1)
	s.workerWg.Add(1)

	go func() {
		defer s.workerWg.Done()
		defer recoverAndLogPanic()
		defer func() {
			for _, c := range ws.backendConns {
				c.Close()
			}
		}()
		for {
			select {
			case <-stopCh:
				return
			case job, ok := <-s.workCh:
				if !ok {
					return
				}
				s.handlePacket(job.pkt, job.addr, ws)
				if job.poolBuf != nil {
					packetPool.Put(job.poolBuf)
				}
			}
		}
	}()
}

func (s *server) removeWorkers(n int) {
	s.poolMu.Lock()
	defer s.poolMu.Unlock()

	for i := 0; i < n && len(s.workerStop) > 0; i++ {
		close(s.workerStop[len(s.workerStop)-1])
		s.workerStop = s.workerStop[:len(s.workerStop)-1]
		s.poolCur.Add(-1)
	}
}

func (s *server) autoScale(done <-chan struct{}) {
	const interval = 100 * time.Millisecond
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	var lowCount int

	for {
		select {
		case <-done:
			return
		case <-ticker.C:
			fillRate := float64(len(s.workCh)) / float64(s.workChCap)

			min := s.poolMin
			max := s.poolMax
			cur := s.poolCur.Load()

			switch {
			case fillRate >= 0.8 && cur < max:
				toAdd := int32(2)
				if cur+toAdd > max {
					toAdd = max - cur
				}
				for i := int32(0); i < toAdd; i++ {
					s.spawnWorker()
				}
				lowCount = 0
			case fillRate < 0.2:
				lowCount++
				if lowCount >= 300 {
					lowCount = 0
					if cur > min {
						toRemove := int32(2)
						if cur-toRemove < min {
							toRemove = cur - min
						}
						s.removeWorkers(int(toRemove))
					}
				}
			default:
				lowCount = 0
			}
		}
	}
}
