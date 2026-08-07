// experimental/libbox/monitor_bridge.go
package libbox

import (
	"encoding/json"

	"github.com/sagernet/sing-box/experimental/monitor"
)

// MonitorService bridges monitor.Collector to gomobile-friendly API
type MonitorService struct {
	collector *monitor.Collector
}

func NewMonitorService(dbPath string) (*MonitorService, error) {
	c, err := monitor.NewCollector(dbPath)
	if err != nil {
		return nil, err
	}
	return &MonitorService{collector: c}, nil
}

// SetEventCallback sets a callback that receives JSON event strings.
// The callback is called from Go goroutines, the Android side should post to main thread.
func (m *MonitorService) SetEventCallback(cb EventCallback) {
	if m.collector == nil {
		return
	}
	m.collector.SetEventCallback(func(json string) {
		cb.SendEvent(json)
	})
}

// ---- Query methods (return JSON strings) ----

func (m *MonitorService) GetDNSHistory(limit int) string {
	if m.collector == nil {
		return "[]"
	}
	records, err := m.collector.QueryDNS(0, limit)
	if err != nil {
		return "[]"
	}
	b, _ := json.Marshal(records)
	return string(b)
}

func (m *MonitorService) GetConnectionHistory(limit int) string {
	if m.collector == nil {
		return "[]"
	}
	// Query the SQLite DB — the authoritative store. RecordTCP only writes
	// SQLite (connBuf/ringbuf is never pushed), so reading connBuf would
	// always return [] even though connections ARE recorded.
	records, err := m.collector.QueryConnections(0, limit)
	if err != nil {
		return "[]"
	}
	b, _ := json.Marshal(records)
	return string(b)
}

// ---- Alert rules (stub: always empty until implemented) ----

func (m *MonitorService) AddAlertRule(json string) int64 {
	if m.collector == nil {
		return 0
	}
	return 0
}

func (m *MonitorService) DeleteAlertRule(ruleID int64) {
	if m.collector == nil {
		return
	}
}

func (m *MonitorService) GetAlertRules() string {
	return "[]"
}

// EventCallback is implemented by Android/Kotlin to receive event JSON
type EventCallback interface {
	SendEvent(json string) error
}
