// experimental/monitor/timingconn.go
package monitor

import (
	"net"
	"sync/atomic"
	"time"
)

// TimingConn wraps a net.Conn to estimate TLS handshake time for DIRECT outbound
// connections, where the TLS handshake is performed by the client application
// itself (sing-box only passes raw bytes through).
//
// What it measures:
//   - firstWrite = time of the first Write call (≈ the app's ClientHello going out)
//   - firstRead  = time of the first Read that returns data (≈ the server's first
//     response arriving: ServerHello, or application data for TLS 1.3 0-RTT)
//   - recorded value = firstRead - firstWrite, i.e. roughly ONE network round-trip
//
// It is NOT the full TLS handshake duration: certificate exchange, key exchange,
// verification and Finished messages (typically 2-3 RTTs in total) are not
// covered. Treat this metric as "direct-connection first-byte RTT", not "TLS
// handshake time". (For proxy outbounds, the full handshake including cert
// exchange is measured in common/tls/client.go instead.)
//
// Caveats:
//   - The first Read may return non-TLS data (e.g. a plain-HTTP response), so
//     this fires for any direct traffic, TLS or not.
//   - No record is produced when the connection dies before any Write/Read
//     (idle keep-alive, RST before data), or when the connection carries no
//     data at all — missing TLS timing for a direct connection therefore does
//     NOT imply a failed TCP handshake.
type TimingConn struct {
	net.Conn
	firstWrite  atomic.Int64 // UnixNano of first Write call
	firstRead   atomic.Int64 // UnixNano of first Read that returns data
	recorded    atomic.Bool  // ensure we only record once
	remoteAddr  string
	connID      string
	domain      string
	outbound    string
}

// WrapWithTiming wraps a connection for TLS handshake timing.
// Only used for direct outbound connections where sing-box doesn't do TLS.
func WrapWithTiming(conn net.Conn, connID, domain, outbound string) *TimingConn {
	return &TimingConn{
		Conn:       conn,
		remoteAddr: conn.RemoteAddr().String(),
		connID:     connID,
		domain:     domain,
		outbound:   outbound,
	}
}

func (c *TimingConn) Write(b []byte) (int, error) {
	if c.firstWrite.Load() == 0 {
		c.firstWrite.Store(time.Now().UnixNano())
	}
	return c.Conn.Write(b)
}

func (c *TimingConn) Read(b []byte) (int, error) {
	n, err := c.Conn.Read(b)
	if err == nil && n > 0 && c.firstRead.Load() == 0 {
		now := time.Now().UnixNano()
		c.firstRead.Store(now)
		// Record TLS timing once: time from first write to first read
		go c.recordTLS()
	}
	return n, err
}

func (c *TimingConn) recordTLS() {
	if !c.recorded.CompareAndSwap(false, true) {
		return
	}
	firstWrite := c.firstWrite.Load()
	firstRead := c.firstRead.Load()
	if firstWrite == 0 || firstRead == 0 {
		return
	}
	tlsUs := (firstRead - firstWrite) / 1000 // nanoseconds to microseconds
	if tlsUs <= 0 {
		return
	}
	mc := Get()
	if mc == nil {
		return
	}
	mc.RecordTLS(TLSRecord{
		Remote:     c.remoteAddr,
		ConnID:     c.connID,
		Domain:     c.domain,
		Outbound:   c.outbound,
		LatencyUs:  tlsUs,
	})
}
