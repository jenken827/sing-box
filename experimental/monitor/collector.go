// experimental/monitor/collector.go
package monitor

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
)

type Collector struct {
	mu      sync.RWMutex
	dnsBuf  *RingBuffer[DNSRecord]
	connBuf *RingBuffer[ConnectionRecord]
	db      *Database
	connMap map[string]*ConnectionRecord // remote addr → pending connection
	eventCB func(string)                 // callback to push JSON to Android
}

var globalCollector *Collector

func NewCollector(dbPath string) (*Collector, error) {
	dir := filepath.Dir(dbPath)
	os.MkdirAll(dir, 0755)

	db, err := NewDatabase(dbPath)
	if err != nil {
		return nil, err
	}

	c := &Collector{
		dnsBuf:  NewRingBuffer[DNSRecord](500),
		connBuf: NewRingBuffer[ConnectionRecord](200),
		db:      db,
		connMap: make(map[string]*ConnectionRecord),
	}
	globalCollector = c
	return c, nil
}

func Get() *Collector {
	return globalCollector
}

func (c *Collector) SetEventCallback(cb func(string)) {
	c.eventCB = cb
}

func (c *Collector) pushJSON(v any) {
	if c.eventCB == nil {
		return
	}
	b, err := json.Marshal(v)
	if err != nil {
		return
	}
	c.eventCB(string(b))
}

// ---- DNS ----

func (c *Collector) RecordDNS(r DNSRecord) {
	r.Timestamp = nowMs()
	c.mu.Lock()
	c.dnsBuf.Push(r)
	c.mu.Unlock()

	// Async SQLite write (non-blocking)
	if c.db != nil {
		c.db.WriteDNS(&r)
	}

	ev := Event{Type: "dns", Timestamp: r.Timestamp, DNS: &r}
	c.pushJSON(ev)
}

func (c *Collector) RecordDNSRejected(domain string) {
	c.RecordDNS(DNSRecord{
		Domain:     domain,
		QType:      "A",
		Status:     "REFUSED",
		IsRejected: true,
	})
}

// ---- TCP ----

func (c *Collector) RecordTCP(r TCPRecord) {
	r.Timestamp = nowMs()

	// Use ConnID if available (per-connection), fallback to Remote (per-address)
	key := r.Remote
	if r.ConnID != "" {
		key = r.ConnID
	}

	// Only track in connMap for latency matching — SQLite is populated by traffic_sync
	c.mu.Lock()
	conn, exists := c.connMap[key]
	if !exists {
		conn = &ConnectionRecord{
			ID:           key,
			Domain:       r.Domain,
			DestIP:       r.Remote,
			Outbound:     r.Outbound,
			TCPLatencyUs: r.LatencyUs,
			StartTime:    r.Timestamp,
			Error:        r.Error,
		}
		if r.ProcessPath != "" {
			conn.ProcessPath = r.ProcessPath
		}
		c.connMap[key] = conn
	} else {
		conn.TCPLatencyUs = r.LatencyUs
		if r.Domain != "" {
			conn.Domain = r.Domain
		}
		if r.Outbound != "" {
			conn.Outbound = r.Outbound
		}
		if r.ProcessPath != "" {
			conn.ProcessPath = r.ProcessPath
		}
		if r.Error != "" {
			conn.Error = r.Error
		}
	}
	c.mu.Unlock()

	// Sync latency to SQLite (per-connection INSERT, traffic_sync upserts same row by conn_id)
	if c.db != nil {
		c.db.WriteLatency(key, r.Remote, r.Domain, r.Outbound, r.LatencyUs, 0, r.ProcessPath, r.Error)
	}

	ev := Event{Type: "tcp", Timestamp: r.Timestamp}
	b, _ := json.Marshal(r)
	ev.Message = string(b)
	c.pushJSON(ev)
}

// ---- TLS ----

func (c *Collector) RecordTLS(r TLSRecord) {
	r.Timestamp = nowMs()

	// Use ConnID if available (per-connection), fallback to Remote (per-address)
	key := r.Remote
	if r.ConnID != "" {
		key = r.ConnID
	}

	// Find matching connection by key (same ConnID as TCP hook)
	c.mu.Lock()
	conn, exists := c.connMap[key]
	if exists {
		conn.TLSLatencyUs = r.LatencyUs
		conn.Host = r.ServerName
		conn.TLSVersion = r.Version
		if r.Domain != "" {
			conn.Domain = r.Domain
		}
		if r.Outbound != "" {
			conn.Outbound = r.Outbound
		}
		if r.Error != "" {
			conn.Error = r.Error
		}
		// Sync latency + host to SQLite
		if c.db != nil {
			c.db.WriteLatency(key, r.Remote, r.Domain, r.Outbound, 0, r.LatencyUs, r.ProcessPath, r.Error)
			c.db.WriteConnectionMeta(key, r.ServerName, "")
		}
	} else {
		// TCP hook not fired yet or came from a different path — track standalone
		conn = &ConnectionRecord{
			ID:           key,
			Domain:       r.Domain,
			DestIP:       r.Remote,
			Outbound:     r.Outbound,
			Host:         r.ServerName,
			TLSLatencyUs: r.LatencyUs,
			TLSVersion:   r.Version,
			StartTime:    r.Timestamp,
			Error:        r.Error,
		}
		if r.ProcessPath != "" {
			conn.ProcessPath = r.ProcessPath
		}
		c.connMap[key] = conn
		if c.db != nil {
			c.db.WriteLatency(key, r.Remote, r.Domain, r.Outbound, 0, r.LatencyUs, r.ProcessPath, r.Error)
			c.db.WriteConnectionMeta(key, r.ServerName, "")
		}
	}
	c.mu.Unlock()

	ev := Event{Type: "tls", Timestamp: r.Timestamp}
	b, _ := json.Marshal(r)
	ev.Message = string(b)
	c.pushJSON(ev)
}

// ---- Connection ----

func (c *Collector) RecordConnection(r ConnectionRecord) {
	r.StartTime = nowMs()

	// Use the same key scheme as RecordTCP/RecordTLS (ConnID), so per-connection
	// TCP/TLS latency hooks can merge into this entry. Fallback to DestIP when
	// no ConnID is available.
	key := r.ID
	if key == "" {
		key = r.DestIP
	}

	c.mu.Lock()
	// Merge with existing connMap entry (from RecordTCP) if present
	if existing, ok := c.connMap[key]; ok {
		if existing.Host == "" {
			existing.Host = r.Host
		}
		if existing.Outbound == "" {
			existing.Outbound = r.Outbound
		}
		if existing.StartTime == 0 {
			existing.StartTime = r.StartTime
		}
		c.connBuf.Push(*existing)
		c.mu.Unlock()
		// Update existing SQLite row with metadata (not INSERT)
		if c.db != nil {
			c.db.UpdateConnectionMeta(key, r.Host, r.Outbound)
		}
		ev := Event{Type: "connection", Timestamp: r.StartTime, Connection: existing}
		c.pushJSON(ev)
		return
	}
	// No TCP hook entry yet — create new
	r.ID = key
	c.connMap[key] = &r
	c.connBuf.Push(r)
	c.mu.Unlock()

	if c.db != nil {
		c.db.WriteConnection(&r)
	}

	ev := Event{Type: "connection", Timestamp: r.StartTime, Connection: &r}
	c.pushJSON(ev)
}

func (c *Collector) CloseConnection(id string, durationMs int64, upload, download int64) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Update in buffer
	for i := range c.connBuf.Size() {
		idx := (c.connBuf.head + i) % c.connBuf.cap
		rec := &c.connBuf.buf[idx]
		if rec.ID == id {
			now := nowMs()
			rec.EndTime = &now
			dur := durationMs
			rec.DurationMs = &dur
			rec.UploadBytes = upload
			rec.DownloadBytes = download
			rec.Closed = true

			// Async SQLite write (UPDATE)
			if c.db != nil {
				c.db.WriteConnectionClosed(rec)
			}

			ev := Event{Type: "connection_closed", Timestamp: *rec.EndTime, Connection: rec}
			c.pushJSON(ev)
			break
		}
	}
}

// CloseConnByDest marks connection closed by dest_ip key (called from route/conn.go).
func (c *Collector) CloseConnByDest(destKey string) {
	c.mu.Lock()
	conn, exists := c.connMap[destKey]
	if exists {
		conn.Closed = true
		now := nowMs()
		conn.EndTime = &now
		dur := now - conn.StartTime
		conn.DurationMs = &dur
		if c.db != nil {
			c.db.WriteConnectionClosed(conn)
		}
	}
	c.mu.Unlock()

	// Also try to find and close by looking at connMap values
	if !exists {
		c.mu.Lock()
		for _, conn := range c.connMap {
			if conn.Host == destKey || (conn.Host == "" && conn.DestIP == destKey) {
				conn.Closed = true
					now := nowMs()
					conn.EndTime = &now
					dur := now - conn.StartTime
					conn.DurationMs = &dur
				if c.db != nil {
					c.db.WriteConnectionClosed(conn)
				}
				break
			}
		}
		c.mu.Unlock()
	}

	// Always try to mark closed in SQLite by dest_ip
	if c.db != nil {
		c.db.WriteConnectionClosedByDest(destKey)
	}
}

// ---- Query methods ----

func (c *Collector) GetDNSHistory(limit int) []DNSRecord {
	return c.dnsBuf.Last(limit)
}

func (c *Collector) GetConnectionHistory(limit int) []ConnectionRecord {
	return c.connBuf.Last(limit)
}

// ---- SQLite-backed history queries (for HTTP API) ----

func (c *Collector) QueryDNS(since int64, limit int) ([]DNSRecord, error) {
	if c.db == nil {
		return nil, nil
	}
	return c.db.QueryDNS(since, limit)
}

func (c *Collector) QueryConnections(since int64, limit int) ([]ConnectionRecord, error) {
	if c.db == nil {
		return nil, nil
	}
	return c.db.QueryConnections(since, limit)
}

func (c *Collector) QueryStats() (int64, int64, error) {
	if c.db == nil {
		return 0, 0, nil
	}
	return c.db.QueryStats()
}

func (c *Collector) DroppedRecords() int64 {
	if c.db == nil {
		return 0
	}
	return c.db.DroppedRecords()
}

// Close shuts down the database writer. Call on service shutdown.
func (c *Collector) Close() error {
	if c.db != nil {
		return c.db.Close()
	}
	return nil
}

// TrafficRecord holds per-connection traffic at a point in time.
type TrafficRecord struct {
	ConnID      string
	DestIP      string
	Upload      int64
	Download    int64
	Outbound    string
	Host        string
	Domain      string
	ProcessPath string
}

// SyncTraffic bulk-updates upload/download for active connections.
// Called periodically from Clash API snapshot.
func (c *Collector) SyncTraffic(records []TrafficRecord) {
	if c.db == nil || len(records) == 0 {
		return
	}
	c.db.SyncTraffic(records)
}
