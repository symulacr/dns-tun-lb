package main

import (
	"context"
	"errors"
	"net"
	"syscall"
	"time"

	"golang.org/x/net/ipv4"
)

const sendBufSize = 4 << 20 // 4 MiB

// dialUDPWithBuf creates a UDP connection with SO_SNDBUF set before connect.
func dialUDPWithBuf(_, raddr *net.UDPAddr, bufSize int) (*net.UDPConn, error) {
	dialer := net.Dialer{
		Control: func(network, address string, c syscall.RawConn) error {
			var err error
			c.Control(func(fd uintptr) {
				err = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_SNDBUF, bufSize)
			})
			return err
		},
	}
	conn, err := dialer.DialContext(context.Background(), "udp", raddr.String())
	if err != nil {
		return nil, err
	}
	return conn.(*net.UDPConn), nil
}

// udpExchange sends a DNS packet to a UDP endpoint and returns the response.
func udpExchange(conn *net.UDPConn, packet []byte) ([]byte, error) {
	if _, err := conn.Write(packet); err != nil {
		return nil, errors.Join(errBackendFailed, err)
	}
	pb := packetPool.Get().(*[]byte)
	n, err := conn.Read(*pb)
	if err != nil {
		packetPool.Put(pb)
		return nil, errors.Join(errBackendFailed, err)
	}
	// Cap response size to prevent amplification attacks and limit memory usage.
	if n > maxBackendResponseSize {
		logDebugf("backend response truncated", "size", n, "max", maxBackendResponseSize)
		n = maxBackendResponseSize
	}
	resp := make([]byte, n)
	copy(resp, (*pb)[:n])
	packetPool.Put(pb)
	return resp, nil
}



// serveConn runs the batch-read loop on conn. Falls back to single reads for non-UDPConn.
func (s *server) serveConn(conn net.PacketConn) error {
	uc, ok := conn.(*net.UDPConn)
	if !ok {
		return s.serveSingleConn(conn)
	}

	if err := uc.SetReadBuffer(4 << 20); err != nil {
		logDebugf("set read buffer", "error", err)
	}

	pc := ipv4.NewPacketConn(uc)

	// Pre-allocate batch buffers — reused every iteration.
	msgs := make([]ipv4.Message, batchReadSize)
	for i := range msgs {
		msgs[i].Buffers = [][]byte{make([]byte, 4096)}
	}

	uc.SetReadDeadline(time.Now().Add(30 * time.Second))
	for {
		count, err := pc.ReadBatch(msgs, 0x1000) // MSG_WAITFORONE
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			return err
		}
		for i := 0; i < count; i++ {
			msg := &msgs[i]
			n := msg.N
			addr := msg.Addr

			frontendPacketsIn.Inc()
			frontendBytesIn.Add(float64(n))

			pb := packetPool.Get().(*[]byte)
			packet := (*pb)[:n]
			copy(packet, msg.Buffers[0][:n])

			s.dispatchPacket(packet, addr, pb)
		}
	}
}
