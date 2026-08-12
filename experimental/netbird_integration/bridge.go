//go:build with_netbird

package netbird_integration

import (
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

// BridgeTCPInfo describes an active TCP bridge.
type BridgeTCPInfo struct {
	Port   int
	Target string
	Active bool
}

// bridgeListener holds a running TCP bridge: it listens on a port inside
// the netbird overlay (netstack) and forwards every accepted connection
// to a local target (e.g. 127.0.0.1:8022 for Termux sshd).
//
// This is the missing "inbound" half of the userspace-netstack data path:
// netstack accepts TCP handshakes but has no way to deliver connections to
// processes listening on the host kernel stack. Bridging explicitly wires
// an overlay port to a host port. Verified on-device (2026-08-10): a peer
// connection from mipad to a probe listener was accepted and data flowed.
type bridgeListener struct {
	port     int
	target   string
	listener net.Listener
	done     chan struct{}
	wg       sync.WaitGroup
}

var (
	bridgeMu        sync.Mutex
	bridgeListeners = make(map[int]*bridgeListener)
)

// BridgeTCP listens on the given port inside the netbird overlay and
// forwards every accepted TCP connection to target (host:port).
// Idempotent per port: calling twice with the same port returns the
// existing bridge. Returns an error if the netbird engine is not running.
func BridgeTCP(port int, target string) (*BridgeTCPInfo, error) {
	client := GetClient()
	if client == nil {
		return nil, fmt.Errorf("netbird client not started")
	}

	bridgeMu.Lock()
	if bl, ok := bridgeListeners[port]; ok {
		bridgeMu.Unlock()
		return &BridgeTCPInfo{Port: bl.port, Target: bl.target, Active: true}, nil
	}
	bridgeMu.Unlock()

	listener, err := client.ListenTCP(net.JoinHostPort("", strconv.Itoa(port)))
	if err != nil {
		return nil, fmt.Errorf("netbird listen tcp :%d: %w", port, err)
	}

	bl := &bridgeListener{
		port:     port,
		target:   target,
		listener: listener,
		done:     make(chan struct{}),
	}
	bl.wg.Add(1)
	go bl.acceptLoop()

	bridgeMu.Lock()
	bridgeListeners[port] = bl
	bridgeMu.Unlock()

	log.Infof("netbird bridge: listening on overlay :%d → %s", port, target)
	return &BridgeTCPInfo{Port: port, Target: target, Active: true}, nil
}

// StopBridge stops the bridge for the given overlay port.
func StopBridge(port int) error {
	bridgeMu.Lock()
	bl, ok := bridgeListeners[port]
	if ok {
		delete(bridgeListeners, port)
	}
	bridgeMu.Unlock()
	if !ok {
		return nil
	}
	close(bl.done)
	_ = bl.listener.Close()
	bl.wg.Wait()
	log.Infof("netbird bridge: stopped overlay :%d", port)
	return nil
}

// StopAllBridges stops every active bridge.
func StopAllBridges() {
	bridgeMu.Lock()
	ports := make([]int, 0, len(bridgeListeners))
	for p := range bridgeListeners {
		ports = append(ports, p)
	}
	bridgeMu.Unlock()
	for _, p := range ports {
		_ = StopBridge(p)
	}
}

func (bl *bridgeListener) acceptLoop() {
	defer bl.wg.Done()
	lastAccept := time.Now()
	for {
		conn, err := bl.listener.Accept()
		if err != nil {
			select {
			case <-bl.done:
				return
			default:
			}
			log.Warnf("netbird bridge :%d accept: %v", bl.port, err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		gap := time.Since(lastAccept)
		lastAccept = time.Now()
		if gap > 500*time.Millisecond {
			log.Warnf("netbird bridge :%d ACCEPT GAP: %v since last accept", bl.port, gap.Round(time.Millisecond))
		}
		bl.wg.Add(1)
		go bl.handleConn(conn)
	}
}

func (bl *bridgeListener) handleConn(conn net.Conn) {
	defer bl.wg.Done()
	defer conn.Close()

	t0 := time.Now()
	upstream, err := net.DialTimeout("tcp", bl.target, 10*time.Second)
	if err != nil {
		log.Warnf("netbird bridge :%d → %s dial: %v", bl.port, bl.target, err)
		return
	}
	defer upstream.Close()
	tDial := time.Since(t0)

	// Timing instrumentation: record when each direction's first byte
	// arrives. SSH banner waits on the sshd→client direction; a large gap
	// between tFirstC2S and tFirstS2C pinpoints the slow hop.
	var (
		mu       sync.Mutex
		firstC2S time.Time
		firstS2C time.Time
		bytesC2S int64
		bytesS2C int64
	)
	tFirstArrived := func(p *time.Time) {
		mu.Lock()
		defer mu.Unlock()
		if p.IsZero() {
			*p = time.Now()
		}
	}

	// Standard TCP proxy: pump both directions independently and let the
	// connection live until BOTH sides are done. Do NOT tear down on the
	// first direction's EOF — a transient read error/EOF on one side would
	// otherwise kill an otherwise healthy SSH session (observed: 2s
	// forced-close timer produced ~2.15s SSH spikes matching TCP RTO).
	copyDone := make(chan struct{}, 2)
	go func() {
		n, _ := io.Copy(upstream, &firstByteReader{src: conn, onFirst: func() {
			tFirstArrived(&firstC2S)
		}})
		mu.Lock()
		bytesC2S = n
		mu.Unlock()
		if tcp, ok := upstream.(*net.TCPConn); ok {
			_ = tcp.CloseWrite() // propagate half-close to sshd
		}
		copyDone <- struct{}{}
	}()
	go func() {
		// Wrap reads from upstream so we can timestamp the first sshd byte.
		n, _ := io.Copy(conn, &firstByteReader{src: upstream, onFirst: func() {
			tFirstArrived(&firstS2C)
		}})
		mu.Lock()
		bytesS2C = n
		mu.Unlock()
		if tcp, ok := conn.(*net.TCPConn); ok {
			_ = tcp.CloseWrite() // propagate half-close back to client
		}
		copyDone <- struct{}{}
	}()

	// Wait for both directions, or the bridge being stopped.
	for i := 0; i < 2; i++ {
		select {
		case <-copyDone:
		case <-bl.done:
			return
		}
	}
	mu.Lock()
	bC2S, bS2C := bytesC2S, bytesS2C
	firstC2ST, firstS2CT := firstC2S, firstS2C
	mu.Unlock()
	elapsed := time.Since(t0)
	log.Infof("netbird bridge :%d conn done: dial=%v elapsed=%v c2s=%dB s2c=%dB firstC2S=+%v firstS2C=+%v",
		bl.port, tDial.Round(time.Millisecond), elapsed.Round(time.Millisecond),
		bC2S, bS2C,
		firstC2ST.Sub(t0).Round(time.Millisecond),
		firstS2CT.Sub(t0).Round(time.Millisecond))
}

// firstByteReader timestamps the first successful Read from src.
type firstByteReader struct {
	src     io.Reader
	onFirst func()
	once    sync.Once
}

func (r *firstByteReader) Read(p []byte) (int, error) {
	n, err := r.src.Read(p)
	if n > 0 {
		r.once.Do(r.onFirst)
	}
	return n, err
}
