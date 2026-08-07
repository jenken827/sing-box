// experimental/monitor/types.go
package monitor

import "time"

type DNSRecord struct {
	Timestamp  int64    `json:"timestamp"`
	Domain     string   `json:"domain"`
	QType      string   `json:"qtype"`
	Transport  string   `json:"transport"`
	LatencyUs  int64    `json:"latency_us"`
	Status     string   `json:"status"`
	Answers    []string `json:"answers"`
	TTL        uint32   `json:"ttl"`
	IsRejected bool     `json:"is_rejected"`
}

type TCPRecord struct {
	Timestamp   int64  `json:"timestamp"`
	Remote      string `json:"remote"`
	ConnID      string `json:"conn_id,omitempty"`
	Domain      string `json:"domain,omitempty"`
	Outbound    string `json:"outbound,omitempty"`
	LatencyUs   int64  `json:"latency_us"`
	Error       string `json:"error,omitempty"`
	ProcessPath string `json:"process_path,omitempty"`
}

type TLSRecord struct {
	Timestamp   int64  `json:"timestamp"`
	Remote      string `json:"remote"`
	ConnID      string `json:"conn_id,omitempty"`
	Domain      string `json:"domain,omitempty"`
	Outbound    string `json:"outbound,omitempty"`
	ServerName  string `json:"server_name"`
	LatencyUs   int64  `json:"latency_us"`
	Version     string `json:"version,omitempty"`
	CipherSuite string `json:"cipher_suite,omitempty"`
	Error       string `json:"error,omitempty"`
	ProcessPath string `json:"process_path,omitempty"`
}

type ConnectionRecord struct {
	ID            string `json:"id"`
	DNSQueryID    string `json:"dns_query_id,omitempty"`
	Host          string `json:"host,omitempty"`
	Domain        string `json:"domain,omitempty"`
	DestIP        string `json:"dest_ip"`
	DestPort      int    `json:"dest_port"`
	SourceIP      string `json:"source_ip,omitempty"`
	Rule          string `json:"rule"`
	Outbound      string `json:"outbound"`
	Chain         string `json:"chain,omitempty"`
	TCPLatencyUs  int64  `json:"tcp_latency_us"`
	TLSLatencyUs  int64  `json:"tls_latency_us"`
	DNSLatencyUs  *int64 `json:"dns_latency_us,omitempty"`
	TLSVersion    string `json:"tls_version,omitempty"`
	CipherSuite   string `json:"cipher_suite,omitempty"`
	UploadBytes   int64  `json:"upload_bytes"`
	DownloadBytes int64  `json:"download_bytes"`
	StartTime     int64  `json:"start_time"`
	EndTime       *int64 `json:"end_time,omitempty"`
	DurationMs    *int64 `json:"duration_ms,omitempty"`
	Error         string `json:"error,omitempty"`
	Closed        bool   `json:"closed"`
	ProcessPath   string `json:"process_path,omitempty"`
}

// Event is the unified JSON event sent to Flutter
type Event struct {
	Type      string `json:"type"`
	Timestamp int64  `json:"timestamp"`
	// Only one of these is set, depending on Type
	DNS        *DNSRecord        `json:"dns,omitempty"`
	Connection *ConnectionRecord `json:"connection,omitempty"`
	Status     string            `json:"status,omitempty"`
	Message    string            `json:"message,omitempty"`
}

func nowMs() int64 {
	return time.Now().UnixMilli()
}
