package main

import (
	"context"
	"errors"
	"flag"
	"net"
	"os"
	"os/signal"
	"runtime"
	"runtime/debug"
	"sync"
	"syscall"
	"time"

	"github.com/miekg/dns"
)

// packetPool reuses 4096-byte buffers to avoid per-packet heap allocations.
// Stores *[]byte to avoid sync.Pool.Put boxing allocation (SA6002).
var packetPool = sync.Pool{
	New: func() any { b := make([]byte, 4096); return &b },
}

// msgPool reuses dns.Msg structs for fallback DNS parsing.
var msgPool = sync.Pool{
	New: func() any { return new(dns.Msg) },
}

// maxBackendResponseSize caps DNS response size (4096 covers EDNS0).
const maxBackendResponseSize = 4096

// dnsTypeTXT is the DNS RR type for TXT (RFC 1035 §3.2.3).
const dnsTypeTXT uint16 = 16

var errBackendFailed = errors.New("backend failed")

// maxDNSNameLen is the maximum domain name length per RFC 1035 §2.3.4.
const maxDNSNameLen = 255
const batchReadSize = 16 // packets per recvmmsg call, 16 sufficient for 8k pps at minimum memory

func (s *server) serve() error {
	defer s.conn.Close()
	defer func() {
		for _, c := range s.backendConns {
			c.Close()
		}
	}()

	s.startWorkers(runtime.GOMAXPROCS(0))
	defer s.workerWg.Wait()
	defer func() {
		close(s.workCh)
	}()

	scaleDone := make(chan struct{})
	defer close(scaleDone)
	go s.autoScale(scaleDone)

	// Start extra REUSEPORT listener goroutines.
	var extraWg sync.WaitGroup
	for i := 1; i < len(s.reuseConns); i++ {
		extraWg.Add(1)
		go func(conn net.PacketConn) {
			defer extraWg.Done()
			if err := s.serveConn(conn); err != nil {
				logDebugf("extra listener error", "error", err)
			}
		}(s.reuseConns[i])
	}

	err := s.serveConn(s.conn)

	// Close extra listeners to unblock their serve loops.
	for i := 1; i < len(s.reuseConns); i++ {
		s.reuseConns[i].Close()
	}
	extraWg.Wait()
	return err
}

// serveSingleConn is the single-read fallback for non-UDP or failed batch reads.
func (s *server) serveSingleConn(conn net.PacketConn) error {
	buf := make([]byte, 4096)
	// Set read deadline if the underlying connection supports it.
	if deadlineConn, ok := conn.(interface{ SetReadDeadline(time.Time) error }); ok {
		deadlineConn.SetReadDeadline(time.Now().Add(30 * time.Second))
	}
	for {
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			return err
		}
		frontendPacketsIn.Inc()
		frontendBytesIn.Add(float64(n))
		pb := packetPool.Get().(*[]byte)
		packet := (*pb)[:n]
		copy(packet, buf[:n])

		s.dispatchPacket(packet, addr, pb)
	}
}

func main() {
	debug.SetGCPercent(400)

	configPath := flag.String("config", "lb.yaml", "path to YAML config")
	flag.Parse()

	cfg, err := LoadConfig(*configPath)
	if err != nil { logErrorf("load config", "error", err); os.Exit(1) }

	if err := cfg.Validate(); err != nil { logErrorf("config validation", "error", err); os.Exit(1) }

	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	logInfof("gc", "heap_alloc_mib", ms.HeapAlloc>>20, "sys_mib", ms.Sys>>20, "num_gc", ms.NumGC)
	if cfg.Global.MetricsListen != "" {
		startMinimalMetrics(cfg.Global.MetricsListen)
	}

	s, err := newServer(cfg)
	if err != nil { logErrorf("init server", "error", err); os.Exit(1) }

	logInfof("listening", "addr", cfg.Global.ListenAddress)
	logInfof("configured pools", "count", len(s.pools))
	for _, p := range s.pools {
		logDebugf("pool", "protocol", p.protocol, "name", p.name, "suffix", p.domainSuffix, "backends", len(p.backends))
	}

	s.sessionTracker.backends = s.backendMetrics
	s.sessionTracker.startJanitor(context.Background(), s.sessionTracker.ttl/2)

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		logInfof("signal", "shutting down")
		for _, c := range s.reuseConns {
			c.Close()
		}
	}()

	if err := s.serve(); err != nil {
		if errors.Is(err, net.ErrClosed) {
			logInfof("serve", "shutdown complete")
		} else {
			logErrorf("serve error", "error", err)
			os.Exit(1)
		}
	}
}
