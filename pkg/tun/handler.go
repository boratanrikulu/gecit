//go:build (darwin || windows) && with_gvisor

package tun

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	gecitdns "github.com/boratanrikulu/gecit/pkg/dns"
	"github.com/boratanrikulu/gecit/pkg/fake"
	"github.com/boratanrikulu/gecit/pkg/rawsock"
	"github.com/boratanrikulu/gecit/pkg/seqtrack"
	singtun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sirupsen/logrus"
)

type handler struct {
	mgr *Manager
}

func (h *handler) PrepareConnection(
	_ string, _ M.Socksaddr, _ M.Socksaddr,
	_ singtun.DirectRouteContext, _ time.Duration,
) (singtun.DirectRouteDestination, error) {
	return nil, nil
}

func (h *handler) NewConnectionEx(
	ctx context.Context,
	conn net.Conn,
	source M.Socksaddr,
	destination M.Socksaddr,
	onClose N.CloseHandlerFunc,
) {
	if onClose != nil {
		defer onClose(nil)
	}
	if conn == nil || !destination.IsValid() {
		return
	}
	defer func() { _ = conn.Close() }()

	dstPort := destination.Port
	addr := net.JoinHostPort(destination.AddrString(), fmt.Sprint(dstPort))
	dst := resolveDst(addr, destination.AddrString(), dstPort)

	serverConn, err := h.mgr.dialServer("tcp", addr, 5*time.Second)
	if err != nil {
		h.mgr.logger.WithError(err).WithField("dst", dst).Debug("dial failed")
		return
	}
	defer func() { _ = serverConn.Close() }()

	if !h.mgr.targetPorts[dstPort] {
		pipe(conn, serverConn)
		return
	}

	h.injectAndForward(conn, serverConn, dst)
}

func (h *handler) injectAndForward(appConn, serverConn net.Conn, dst string) {
	if err := appConn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		h.mgr.logger.WithError(err).Debug("set client read deadline failed")
		return
	}
	clientHello := make([]byte, 16384)
	n, err := appConn.Read(clientHello)
	if err != nil {
		return
	}
	clientHello = clientHello[:n]
	if err := appConn.SetReadDeadline(time.Time{}); err != nil {
		h.mgr.logger.WithError(err).Debug("clear client read deadline failed")
		return
	}

	// Extract real destination from SNI — more reliable than DNS cache.
	if sni := fake.ParseSNI(clientHello); sni != "" {
		if remoteTCP, ok := serverConn.RemoteAddr().(*net.TCPAddr); ok {
			dst = fmt.Sprintf("%s:%d", sni, remoteTCP.Port)
		}
	}

	seq, ack := seqtrack.GetSeqAck(serverConn)

	serverTCP, ok1 := serverConn.LocalAddr().(*net.TCPAddr)
	remoteTCP, ok2 := serverConn.RemoteAddr().(*net.TCPAddr)
	if !ok1 || !ok2 {
		return
	}
	srcPort, err := tcpPort(serverTCP.Port)
	if err != nil {
		h.mgr.logger.WithError(err).Debug("invalid local TCP port")
		return
	}
	dstPort, err := tcpPort(remoteTCP.Port)
	if err != nil {
		h.mgr.logger.WithError(err).Debug("invalid remote TCP port")
		return
	}

	connInfo := rawsock.ConnInfo{
		SrcIP: serverTCP.IP, DstIP: remoteTCP.IP,
		SrcPort: srcPort, DstPort: dstPort,
		Seq: seq, Ack: ack,
	}

	if connInfo.SrcIP.To4() == nil || connInfo.DstIP.To4() == nil {
		h.mgr.logger.WithField("dst", dst).Warn("skipping non-IPv4 fake injection")
		forwardClientHello(appConn, serverConn, clientHello)
		return
	}
	if !h.mgr.cfg.AllowPrivateTargets && rawsock.IsUnsafeTarget(connInfo.DstIP) {
		h.mgr.logger.WithField("dst", dst).Warn("skipping fake injection to private/local target")
		forwardClientHello(appConn, serverConn, clientHello)
		return
	}

	for i := 0; i < 3; i++ {
		if err := h.mgr.rawSock.SendFake(connInfo, fake.TLSClientHello, h.mgr.cfg.FakeTTL); err != nil {
			h.mgr.logger.WithError(err).Warn("SendFake failed")
			break
		}
	}
	h.mgr.logger.WithFields(logrus.Fields{
		"dst": dst, "seq": seq, "ack": ack, "ttl": h.mgr.cfg.FakeTTL,
	}).Info("fake ClientHellos injected")

	// Let fakes reach DPI before the real ClientHello.
	time.Sleep(2 * time.Millisecond)

	if _, err := serverConn.Write(clientHello); err != nil {
		return
	}

	pipe(appConn, serverConn)
}

func forwardClientHello(appConn, serverConn net.Conn, clientHello []byte) {
	if _, err := serverConn.Write(clientHello); err != nil {
		return
	}
	pipe(appConn, serverConn)
}

func (h *handler) NewPacketConnectionEx(
	ctx context.Context,
	conn N.PacketConn,
	source M.Socksaddr,
	destination M.Socksaddr,
	onClose N.CloseHandlerFunc,
) {
	if onClose != nil {
		defer onClose(nil)
	}
	if conn == nil || !destination.IsValid() {
		return
	}
	defer func() { _ = conn.Close() }()

	type udpFlow struct {
		conn net.Conn
		dst  M.Socksaddr
	}

	var (
		mu    sync.Mutex
		flows = make(map[string]udpFlow)
	)
	defer func() {
		mu.Lock()
		defer mu.Unlock()
		for _, f := range flows {
			_ = f.conn.Close()
		}
	}()

	getFlow := func(dst M.Socksaddr) (udpFlow, error) {
		key := dst.String()
		mu.Lock()
		if f, ok := flows[key]; ok {
			mu.Unlock()
			return f, nil
		}
		mu.Unlock()

		addr := net.JoinHostPort(dst.AddrString(), fmt.Sprint(dst.Port))
		realConn, err := h.mgr.dialServer("udp", addr, 5*time.Second)
		if err != nil {
			return udpFlow{}, err
		}
		f := udpFlow{conn: realConn, dst: dst}

		mu.Lock()
		if existing, ok := flows[key]; ok {
			mu.Unlock()
			_ = realConn.Close()
			return existing, nil
		}
		flows[key] = f
		mu.Unlock()

		go func() {
			rawBuf := make([]byte, 65535)
			for {
				if err := realConn.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
					return
				}
				n, err := realConn.Read(rawBuf)
				if err != nil {
					return
				}
				if err := conn.WritePacket(buf.As(rawBuf[:n]), dst); err != nil {
					return
				}
			}
		}()
		return f, nil
	}

	for {
		b := buf.NewSize(65535)
		if err := conn.SetReadDeadline(time.Now().Add(30 * time.Second)); err != nil {
			b.Release()
			break
		}
		packetDst, err := conn.ReadPacket(b)
		if err != nil {
			b.Release()
			break
		}
		if !packetDst.IsValid() {
			packetDst = destination
		}
		flow, err := getFlow(packetDst)
		if err == nil {
			_, err = flow.conn.Write(b.Bytes())
		}
		b.Release()
		if err != nil {
			break
		}
	}
}

func resolveDst(addr, ip string, port uint16) string {
	if dns := gecitdns.GetDNSServer(); dns != nil {
		if domain := dns.PopDomain(ip); domain != "" {
			return fmt.Sprintf("%s:%d", domain, port)
		}
	}
	return addr
}

func tcpPort(port int) (uint16, error) {
	if port <= 0 || port > 65535 {
		return 0, fmt.Errorf("port out of range: %d", port)
	}
	return uint16(port), nil // #nosec G115 -- range checked above.
}

const idleTimeout = 5 * time.Minute

func pipe(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	cp := func(dst, src net.Conn) {
		defer wg.Done()
		// Idle timeout: if no data flows for idleTimeout, close both sides.
		// Prevents goroutine/fd accumulation from idle connections.
		buf := make([]byte, 32*1024)
		for {
			if err := src.SetReadDeadline(time.Now().Add(idleTimeout)); err != nil {
				break
			}
			n, err := src.Read(buf)
			if n > 0 {
				if _, wErr := dst.Write(buf[:n]); wErr != nil {
					break
				}
			}
			if err != nil {
				break
			}
		}
		_ = a.SetDeadline(time.Now())
		_ = b.SetDeadline(time.Now())
	}
	go cp(b, a)
	go cp(a, b)
	wg.Wait()
}
