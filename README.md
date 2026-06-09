## dns-tun-lb

A UDP load balancer for DNS tunneling protocols. Supports dnstt, slipstream, and noizdns.

It listens on a UDP port, parses incoming DNS queries, and routes them to tunnel backends based on domain suffix matching. Session IDs are extracted per-protocol for consistent hash ring routing. Queries that don't match any pool get forwarded to a recursive resolver or dropped.

The parser does no heap allocations. It handles 7,500+ packets per second with less than 0.1% CPU spent on garbage collection.

### Benchmark: original vs optimized

Tested on Go 1.26, same machine, same echo server backend.

| Metric | Original | Optimized | Δ |
|--------|----------|-----------|---|
| DNS parse (ns/op) | 215 | 18 | 12× faster |
| Domain match (ns/op) | 300 | 7 | 43× faster |
| Hash ring choose (ns/op) | 120 | 27 | 4.4× faster |
| Hot path allocs/packet | 8-12 | 0 | no allocs |
| Throughput (pps, 1k) | 717 | 1,000 | 1.4× |
| Throughput (pps, 10k) | 7,112 | 7,490 | 1.05× |
| GC CPU | ~2% | <0.1% | 20× less |
| Idle RSS | 9.0 MB | 7.0 MB | 22% less |
| Goroutine leak | yes (under load) | none (proven 5 min) | fixed |
| Binary size | 11 MB | 6.3 MB | 43% smaller |

All hot-path benchmarks show 0 allocations per packet. Simulation tested at 1,000 and 10,000 pps sustained with 100% success rate and zero packet errors.

### Build and run

Requires Go 1.26+.

```bash
go build -o dns-tun-lb .
./dns-tun-lb -config lb.yaml
```

### Configuration

```yaml
global:
  listen_address: "0.0.0.0:53"
  metrics_listen: ":2112"
  read_timeout: "10s"
  max_concurrent: 0
  direct: false
  default_dns_behavior:
    mode: "forward"
    forward_resolver: "9.9.9.9:53"

protocols:
  dnstt:
    pools:
      - name: "dnstt-main"
        domain_suffix: "t.example.com"
        backends:
          - id: "dnstt-1"
            address: "10.0.0.11:5300"
  slipstream:
    pools:
      - name: "slipstream-main"
        domain_suffix: "s.example.com"
        backends:
          - id: "slipstream-1"
            address: "10.0.0.21:5300"
            lb_id: 0
  noizdns:
    pools:
      - name: "noizdns-main"
        domain_suffix: "n.example.com"
        backends:
          - id: "noizdns-1"
            address: "10.0.0.31:5300"

logging:
  level: "info"
```

-config defaults to lb.yaml. metrics_listen serves Prometheus at /metrics. max_concurrent caps in-flight packets (0 = no limit). direct skips the worker pool. Slipstream backends need lb_id (0-255).

### Routing

1. Find the longest matching pool by `domain_suffix`.
2. Extract session ID: dnstt = 8-byte ClientID; slipstream = QUIC connection ID; noizdns = first 8 bytes of decoded payload.
3. Route by QUIC-LB CID (slipstream) or consistent hash ring. Same session always hits the same backend.

### Source

| File | Lines | Purpose |
|------|-------|---------|
| main.go | 155 | Entry point, serve loop |
| dns.go | 325 | DNS parsing, forwarding |
| server.go | 404 | Server, worker pool, auto-scale |
| qname.go | 243 | Protocol extraction |
| metrics_common.go | 190 | Session tracker, metrics |
| metrics_prometheus.go | 227 | Prometheus metrics |
| config.go | 136 | Config, validation |
| hash.go | 71 | Hash ring |
| net.go + net_full.go | 103 | UDP helpers, batch reads |
| logutil_slog.go | 46 | Logging |
| Total | 1,900 | |

### License

MIT
