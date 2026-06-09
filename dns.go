package main

import (
	"encoding/binary"
	"hash/maphash"
	"net"
	"strconv"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/miekg/dns"
)

// parseDNSQuestion extracts QNAME/QTYPE from a raw DNS packet without allocating.
// Handles compression pointers (RFC 1035 §4.1.4) with separate sequential offset.
func parseDNSQuestion(packet []byte, buf *[256]byte) (qname string, qtype uint16, ok bool) {
	const headerLen = 12
	if len(packet) < headerLen+5 { // 12 header + 1B min QNAME + 2B QTYPE + 2B QCLASS
		return "", 0, false
	}
	// QR bit must be 0 (query, not a response)
	if packet[2]&0x80 != 0 {
		return "", 0, false
	}
	// OPCODE must be 0 (standard query)
	if packet[2]&0x78 != 0 {
		return "", 0, false
	}
	// QDCOUNT must be > 0 (at least one question)
	if binary.BigEndian.Uint16(packet[4:6]) == 0 {
		return "", 0, false
	}

	n := 0

	off := headerLen   // label read position (may jump via compression pointer)
	seqOff := off      // sequential position (tracks QTYPE/QCLASS location)
	pointerSeen := false
	ptrCount := 0

	for {
		if off >= len(packet) {
			return "", 0, false
		}
		labelLen := packet[off]

		if labelLen == 0 {
			// Root label — end of QNAME.
			// Only update seqOff if no compression pointer was followed;
			// when a pointer was seen, seqOff was already set at the pointer.
			if !pointerSeen {
				seqOff = off + 1
			}
			break
		}

		if labelLen&0xC0 == 0x40 {
			// Extended label type (0x40-0xBF) — not supported by this parser
			return "", 0, false
		}

		if labelLen&0xC0 == 0xC0 {
			// Compression pointer: 2 bytes, lower 14 bits = offset into packet.
			if off+2 > len(packet) {
				return "", 0, false
			}
			ptr := int(binary.BigEndian.Uint16(packet[off:off+2])) & 0x3FFF
			if ptr >= off {
				return "", 0, false // must point backwards to prevent loops
			}
			if packet[ptr]&0xC0 != 0 {
				return "", 0, false // RFC 9267 §3: pointer target must be a valid label start
			}
			ptrCount++
			if ptrCount > 5 {
				return "", 0, false
			}
			seqOff = off + 2    // QTYPE/QCLASS are after the 2-byte pointer
			off = ptr           // continue reading labels from pointer target
			pointerSeen = true
			continue
		}

		if labelLen > 63 {
			return "", 0, false
		}
		off++
		if off+int(labelLen) > len(packet) {
			return "", 0, false
		}
		if n > 0 {
			if n >= len(buf) {
				return "", 0, false
			}
			buf[n] = '.'
			n++
		}
		if n+int(labelLen) > len(buf) {
			return "", 0, false
		}
		copy(buf[n:n+int(labelLen)], packet[off:off+int(labelLen)])
		n += int(labelLen)
		off += int(labelLen)
		if n > maxDNSNameLen {
			return "", 0, false
		}
	}

	// QTYPE (2B) + QCLASS (2B) at seqOff.
	if seqOff+4 > len(packet) {
		return "", 0, false
	}
	qtype = binary.BigEndian.Uint16(packet[seqOff : seqOff+2])
	// Trailing dot matches dns.Msg convention.
	if n > 0 && n < len(buf) {
		buf[n] = '.'
		n++
	}
	qname = unsafe.String(unsafe.SliceData(buf[:n]), n)
	return qname, qtype, true
}

func (s *server) dispatchPacket(packet []byte, addr net.Addr, poolBuf *[]byte) {
	// Direct mode: goroutine-per-packet, no worker pool.
	if s.direct {
		packetPool.Put(poolBuf)
		s.handlePacket(packet, addr, nil)
		return
	}

	// Pool bypass: below threshold concurrency, spawn a goroutine directly.
	if s.poolBypassThreshold > 0 {
		cur := atomic.AddUint64(&s.activeCount, 1)
		if cur <= uint64(s.poolBypassThreshold) {
			packetPool.Put(poolBuf)
			go func() {
				defer atomic.AddUint64(&s.activeCount, ^uint64(0))
				s.handlePacket(packet, addr, nil)
			}()
			return
		}
		atomic.AddUint64(&s.activeCount, ^uint64(0)) // undo increment
	}

	select {
	case s.workCh <- packetJob{pkt: packet, addr: addr, poolBuf: poolBuf}:
	default:
		packetPool.Put(poolBuf)
		frontendPacketsDropped.Inc()
	}
}

func (s *server) handlePacket(packet []byte, src net.Addr, ws *workerState) {
	if s.limiter != nil {
		select {
		case s.limiter <- struct{}{}:
			defer func() { <-s.limiter }()
		default:
			dnsDroppedRequestsTotal.WithLabelValues("rate_limit").Inc()
			logDebugf("rate limit: dropping packet")
			return
		}
	}
	defer recoverAndLogPanic()
	var qbuf [256]byte
	qname, qtype, ok := parseDNSQuestion(packet, &qbuf)
	if !ok {
		msg := msgPool.Get().(*dns.Msg)
		if err := msg.Unpack(packet); err == nil && len(msg.Question) > 0 {
			qname = msg.Question[0].Name
			qtype = msg.Question[0].Qtype
			ok = true
		}
		msgPool.Put(msg)
	}
	if !ok {
		parseErrorsTotal.WithLabelValues("dns_unpack").Inc()
		dnsRequestsTotal.WithLabelValues("other").Inc()
		s.forwardOrDrop(packet, src)
		return
	}

	pool := longestMatchingPool(qname, s.pools)
	if pool != nil {
		var sid [8]byte
		var haveSession bool

		var backend BackendConfig
		// For non-TXT, we still route to backend but mark as unsupported.
		if qtype != dnsTypeTXT {
			unsupportedQueriesTotal.WithLabelValues(strconv.FormatUint(uint64(qtype), 10)).Inc()
		} else {
			switch pool.protocol {
			case "dnstt":
				sid, haveSession = extractSessionID(qname, pool.domainSuffix, "dnstt")
			case "slipstream":
				var decBuf [160]byte
				n, decOK := decodeQnamePrefixPayloadBytes(unsafeStringToBytes(qname), pool.domainSuffix, decBuf[:])
				if decOK && n >= 7 {
					payload := decBuf[:n]
					sid, haveSession = extractSlipstreamSessionIDFromPayload(payload)
					if sid != [8]byte{} {
						serverID, srvOK, _ := decodeSlipstreamQUICLBServerIDFromPayload(payload)
						if srvOK {
							for i := range pool.backends {
								b := &pool.backends[i]
								if *b.LbID == serverID {
									backend = *b
									break
								}
							}
						}
					}
				}
			case "noizdns":
				sid, haveSession = extractSessionID(qname, pool.domainSuffix, "noizdns")
			default:
				haveSession = false
			}
			if !haveSession {
				binary.LittleEndian.PutUint64(sid[:], maphash.Bytes(pool.ring.seed, unsafeStringToBytes(qname)))
			}
		}

		if backend.ID == "" && backend.Address == "" {
			if chosen, ok := pool.ring.choose(pool.protocol, pool.domainSuffix, sid[:]); ok {
				backend = chosen
			}
		}

		dnsRoutedRequestsTotal.WithLabelValues(pool.protocol, pool.name).Inc()
		bm := s.backendMetrics[metricKey(pool.protocol, pool.name, pool.domainSuffix, backend)]
		if bm != nil {
			bm.requestsTotal.Add(1)
			// Per-protocol counter — pre-resolved, avoids WithLabelValues alloc.
			switch pool.protocol {
			case "dnstt":
				bm.requestsDNSTT.Inc()
			case "slipstream":
				bm.requestsSlipstream.Inc()
			case "noizdns":
				bm.requestsNoizdns.Inc()
			default:
				dnsRequestsTotal.WithLabelValues(pool.protocol).Inc()
			}
		} else {
			dnsRequestsTotal.WithLabelValues(pool.protocol).Inc()
		}
		if qtype == dnsTypeTXT && sid != [8]byte{} { logDebugf("session", "protocol", pool.protocol, "sid", sid, "backend", backend.ID, "addr", backend.Address) } else { logDebugf("query", "protocol", pool.protocol, "qtype", qtype, "qname", qname, "backend", backend.ID, "addr", backend.Address) }
		ok := s.forwardToBackend(packet, src, pool.protocol, pool.name, pool.domainSuffix, backend, bm, ws)
		if ok { s.sessionTracker.observeSession(pool.protocol, pool.name, pool.domainSuffix, backend, sid[:], bm) }
		return
	}

	dnsRequestsTotal.WithLabelValues("other").Inc()
	s.forwardOrDrop(packet, src)
}

func (s *server) forwardOrDrop(packet []byte, src net.Addr) {
	if s.forwardAddr == nil {
		dnsDroppedRequestsTotal.WithLabelValues("no_forwarder").Inc()
		return
	}
	// Forward to default resolver — fresh dial per request to avoid race.
	resolverConn, err := net.DialUDP("udp", nil, s.forwardAddr)
	if err != nil { logErrorf("forward dial", "error", err); dnsDroppedRequestsTotal.WithLabelValues("forward_dial_error").Inc(); return }
	defer resolverConn.Close()

	dnsForwardedRequestsTotal.Inc()

	deadline := time.Now().Add(s.cfg.parsedReadTimeout)
	resolverConn.SetWriteDeadline(deadline)
	resolverConn.SetReadDeadline(deadline)
	resp, err := udpExchange(resolverConn, packet)
	if err != nil { logErrorf("forward exchange", "error", err); dnsDroppedRequestsTotal.WithLabelValues("forward_exchange_error").Inc(); return }
	n := len(resp)
	if _, err := s.udpConn.WriteTo(resp[:n], src); err != nil { logErrorf("forward reply", "error", err); dnsDroppedRequestsTotal.WithLabelValues("forward_reply_error").Inc(); return }
	frontendPacketsOut.Inc()
	frontendBytesOut.Add(float64(n))
}

func (s *server) forwardToBackend(packet []byte, src net.Addr, protocol, pool, domain string, backend BackendConfig, bm *resolvedBackendMetrics, ws *workerState) bool {
	var conn *net.UDPConn
	var ok bool
	if ws != nil {
		conn, ok = ws.backendConns[backend.Address]
	} else {
		conn, ok = s.backendConns[backend.Address]
	}
	if !ok {
		var err error
		conn, err = dialUDPWithBuf(nil, backend.parsedAddr, sendBufSize)
		if err != nil { logErrorf("dial backend", "backend", backend.ID, "addr", backend.Address, "error", err); if bm != nil { bm.errorsTotal.WithLabelValues(protocol, pool, domain, backendLabelID(backend), "dial").Inc() }; return false }
		if ws != nil {
			ws.backendConns[backend.Address] = conn
		} else {
			defer conn.Close()
		}
	}

	deadline := time.Now().Add(s.cfg.parsedReadTimeout)
	conn.SetWriteDeadline(deadline)
	conn.SetReadDeadline(deadline)

	if bm != nil { bm.packetsSent.Add(1); bm.bytesSent.Add(uint64(len(packet))) }

	if s.cfg.Global.FireAndForget {
		if _, err := conn.Write(packet); err != nil {
			logErrorf("write backend", "backend", backend.ID, "addr", backend.Address, "error", err)
			if bm != nil { bm.errorsTotal.WithLabelValues(protocol, pool, domain, backendLabelID(backend), "write").Inc() }
			return false
		}
		return true
	}

	resp, err := udpExchange(conn, packet)
	if err != nil { logErrorf("xchange backend", "backend", backend.ID, "addr", backend.Address, "error", err); if bm != nil { bm.errorsTotal.WithLabelValues(protocol, pool, domain, backendLabelID(backend), "xchange").Inc() }; return false }
	n := len(resp)
	if bm != nil { bm.packetsReceived.Add(1); bm.bytesReceived.Add(uint64(n)) }
	if _, err := s.udpConn.WriteTo(resp[:n], src); err != nil { logErrorf("reply backend", "backend", backend.ID, "addr", backend.Address, "error", err); dnsDroppedRequestsTotal.WithLabelValues("backend_reply_error").Inc(); return false }
	frontendPacketsOut.Inc()
	frontendBytesOut.Add(float64(n))
	return true
}
