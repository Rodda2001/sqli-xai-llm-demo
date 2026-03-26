// Package main implements the FileSense log agent.
//
// The agent tails a MySQL general query log, parses each SQL query event,
// optionally enriches it with reverse-DNS and GeoIP metadata, then POSTs it
// to the FileSense ingest API.
//
// Usage:
//
//	./agent -file /var/log/mysql/general.log -endpoint http://localhost:9000/api/ingest
//	./agent -simulate                          # send canned test queries
//	./agent -simulate -debug -geoip            # verbose demo with geo enrichment
package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/fsnotify/fsnotify"
)

// ---------------------------------------------------------------------------
// Constants and defaults
// ---------------------------------------------------------------------------

const defaultEndpoint = "http://localhost:9000/api/ingest"

// ---------------------------------------------------------------------------
// Loggers — each stream has its own prefix so log levels are scannable.
// ---------------------------------------------------------------------------

var (
	debugLog = log.New(os.Stderr, "[DEBUG] ", log.Ltime|log.Lmicroseconds)
	infoLog  = log.New(os.Stdout, "[INFO]  ", log.Ltime|log.Lmicroseconds)
	errLog   = log.New(os.Stderr, "[ERROR] ", log.Ltime|log.Lmicroseconds)
)

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

// config holds all runtime settings derived from CLI flags.
type config struct {
	logFile          string
	endpoint         string
	simulate         bool
	simulateInterval time.Duration
	debug            bool
	geoip            bool
	httpTimeout      time.Duration
}

// dbg writes a debug message only when debug mode is active.
func (c *config) dbg(format string, args ...any) {
	if c.debug {
		debugLog.Printf(format, args...)
	}
}

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

// IngestPayload is the JSON body sent to the ingest endpoint.
type IngestPayload struct {
	Query      string `json:"query"`
	SourceIP   string `json:"source_ip"`
	SourceHost string `json:"source_host"`
}

// GeoInfo holds optional geographic metadata fetched from ip-api.com.
type GeoInfo struct {
	Country string `json:"country"`
	City    string `json:"city"`
	ISP     string `json:"isp"`
}

// ---------------------------------------------------------------------------
// Connection map — maps MySQL thread ID → client IP/hostname.
//
// MySQL general log records the source host in the "Connect" event, not in
// each "Query" event.  We track thread_id → host so that when a Query line
// arrives we can look up which client issued it.
// ---------------------------------------------------------------------------

type connectionMap struct {
	mu   sync.RWMutex
	data map[string]string
}

func newConnectionMap() *connectionMap {
	return &connectionMap{data: make(map[string]string)}
}

func (c *connectionMap) set(threadID, host string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.data[threadID] = host
}

func (c *connectionMap) get(threadID string) (string, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	v, ok := c.data[threadID]
	return v, ok
}

// ---------------------------------------------------------------------------
// Log parsing
//
// MySQL general query log format (space-separated columns):
//
//	2024-01-15T10:30:45.123456Z    8 Connect    root@192.168.1.100 on db using TCP/IP
//	2024-01-15T10:30:45.123456Z    8 Query      SELECT * FROM users WHERE id=1
//
// Columns: timestamp  thread_id  command_type  argument
// ---------------------------------------------------------------------------

var (
	// queryRe captures (thread_id, sql_text) from a Query line.
	queryRe = regexp.MustCompile(`^\S+\s+(\d+)\s+Query\s+(.+)$`)

	// connectRe captures (thread_id, client_host_or_ip) from a Connect line.
	// The host portion follows the '@' in "user@host".
	connectRe = regexp.MustCompile(`^\S+\s+(\d+)\s+Connect\s+\S+@(\S+)`)
)

// parseLine examines a single log line and returns an IngestPayload when the
// line contains a Query event.  Connect lines are used to update the
// connection map.  All other lines are silently ignored.
func parseLine(line string, conns *connectionMap, cfg *config) (IngestPayload, bool) {
	line = strings.TrimSpace(line)
	if line == "" {
		return IngestPayload{}, false
	}

	// --- Connect line: record thread → source host mapping. ---
	if m := connectRe.FindStringSubmatch(line); m != nil {
		threadID, host := m[1], m[2]
		conns.set(threadID, host)
		cfg.dbg("connect  thread=%s host=%s", threadID, host)
		return IngestPayload{}, false
	}

	// --- Query line: build a payload. ---
	m := queryRe.FindStringSubmatch(line)
	if m == nil {
		return IngestPayload{}, false
	}

	threadID := m[1]
	query := strings.TrimSpace(m[2])

	sourceIP := "unknown"
	if host, ok := conns.get(threadID); ok {
		sourceIP = host
	}

	cfg.dbg("query    thread=%s ip=%s sql=%q", threadID, sourceIP, query)
	return IngestPayload{Query: query, SourceIP: sourceIP}, true
}

// ---------------------------------------------------------------------------
// Network helpers
// ---------------------------------------------------------------------------

// resolveHost performs a reverse-DNS lookup on ip and returns the first
// hostname.  Falls back to the original IP string on any error.
func resolveHost(ip string) string {
	hosts, err := net.LookupAddr(ip)
	if err != nil || len(hosts) == 0 {
		return ip
	}
	// net.LookupAddr returns FQDNs ending with a '.'; strip it.
	return strings.TrimSuffix(hosts[0], ".")
}

// fetchGeoInfo calls the ip-api.com free JSON API to fetch geographic
// metadata for ip.  Returns nil on any error so callers degrade gracefully.
func fetchGeoInfo(client *http.Client, ip string) *GeoInfo {
	url := fmt.Sprintf("http://ip-api.com/json/%s?fields=country,city,isp", ip)
	resp, err := client.Get(url)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	var info GeoInfo
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil
	}
	return &info
}

// postQuery marshals payload as JSON and POSTs it to endpoint.
func postQuery(client *http.Client, endpoint string, payload IngestPayload, cfg *config) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("marshal payload: %w", err)
	}

	cfg.dbg("POST %s  body=%s", endpoint, body)

	resp, err := client.Post(endpoint, "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("POST %s: %w", endpoint, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("ingest returned HTTP %d", resp.StatusCode)
	}

	cfg.dbg("ingest OK  status=%d", resp.StatusCode)
	return nil
}

// ---------------------------------------------------------------------------
// File tailer
// ---------------------------------------------------------------------------

// tailFile seeks to the end of cfg.logFile, then watches for fsnotify Write
// events and forwards each new complete line to lines.  Handles log rotation
// (Rename/Remove events) by re-opening the file after a short delay.
//
// Returns when stop is closed or an unrecoverable error occurs.
func tailFile(cfg *config, lines chan<- string, stop <-chan struct{}) error {
	f, err := os.Open(cfg.logFile)
	if err != nil {
		return fmt.Errorf("open %q: %w", cfg.logFile, err)
	}
	defer f.Close()

	// Seek to end: we only care about new content appended after startup.
	if _, err := f.Seek(0, io.SeekEnd); err != nil {
		return fmt.Errorf("seek to end: %w", err)
	}

	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("create watcher: %w", err)
	}
	defer watcher.Close()

	if err := watcher.Add(cfg.logFile); err != nil {
		return fmt.Errorf("watch %q: %w", cfg.logFile, err)
	}

	infoLog.Printf("tailing %s", cfg.logFile)

	reader := bufio.NewReader(f)

	for {
		select {
		case <-stop:
			infoLog.Println("tailer stopping")
			return nil

		case event, ok := <-watcher.Events:
			if !ok {
				return fmt.Errorf("watcher events channel closed unexpectedly")
			}
			cfg.dbg("fsnotify event: %s", event)

			// New data appended — drain all available complete lines.
			if event.Has(fsnotify.Write) {
				for {
					line, err := reader.ReadString('\n')
					if len(line) > 0 {
						lines <- strings.TrimRight(line, "\r\n")
					}
					if err == io.EOF {
						break // No more data right now; wait for the next event.
					}
					if err != nil {
						errLog.Printf("read error: %v", err)
						break
					}
				}
			}

			// Log rotation: the file was renamed/removed by a rotation tool.
			// Wait briefly for the new file to be created, then re-open it.
			if event.Has(fsnotify.Rename) || event.Has(fsnotify.Remove) {
				infoLog.Println("log file rotated — waiting for new file")
				f.Close()
				time.Sleep(500 * time.Millisecond)

				newF, err := os.Open(cfg.logFile)
				if err != nil {
					errLog.Printf("re-open after rotation: %v", err)
					continue
				}
				f = newF
				reader = bufio.NewReader(f)
				if err := watcher.Add(cfg.logFile); err != nil {
					errLog.Printf("re-watch after rotation: %v", err)
				}
			}

		case err, ok := <-watcher.Errors:
			if !ok {
				return fmt.Errorf("watcher errors channel closed unexpectedly")
			}
			errLog.Printf("watcher error: %v", err)
		}
	}
}

// ---------------------------------------------------------------------------
// Simulate mode
// ---------------------------------------------------------------------------

// simulate emits a stream of realistic MySQL general-log lines (including
// Connect entries so the connection map is populated) at the configured
// interval.  It is intended for demos and integration testing.
func simulate(cfg *config, lines chan<- string, stop <-chan struct{}) {
	// Connect lines establish the thread → IP mapping.
	connects := []string{
		"2024-01-15T10:30:45.000000Z    1 Connect    root@192.168.1.100 on testdb using TCP/IP",
		"2024-01-15T10:30:45.100000Z    2 Connect    app@10.0.0.50 on appdb using TCP/IP",
		"2024-01-15T10:30:45.200000Z    3 Connect    admin@172.16.0.25 on admindb using TCP/IP",
	}

	// Query lines — a mix of benign and injection attempts.
	queries := []string{
		"2024-01-15T10:30:46.000000Z    1 Query    SELECT * FROM users WHERE id=1",
		"2024-01-15T10:30:46.100000Z    2 Query    SELECT username, password FROM accounts WHERE username='admin' OR '1'='1'",
		"2024-01-15T10:30:46.200000Z    1 Query    INSERT INTO orders (product_id, qty) VALUES (42, 3)",
		"2024-01-15T10:30:46.300000Z    3 Query    DROP TABLE users; --",
		"2024-01-15T10:30:46.400000Z    2 Query    SELECT * FROM products WHERE id=1 UNION SELECT table_name,2,3,4 FROM information_schema.tables",
		"2024-01-15T10:30:46.500000Z    1 Query    UPDATE users SET email='test@example.com' WHERE id=5",
		"2024-01-15T10:30:46.600000Z    3 Query    SELECT * FROM users WHERE name='' OR 1=1 --",
		"2024-01-15T10:30:46.700000Z    2 Query    SELECT * FROM orders WHERE customer_id=7",
		"2024-01-15T10:30:46.800000Z    1 Query    SHOW DATABASES",
		"2024-01-15T10:30:46.900000Z    3 Query    SELECT @@version; SELECT * FROM mysql.user",
	}

	infoLog.Println("simulate mode — sending test queries")

	// Emit all Connect lines immediately so thread IDs resolve before queries arrive.
	for _, line := range connects {
		select {
		case <-stop:
			return
		case lines <- line:
			cfg.dbg("simulate connect: %s", line)
		}
	}

	ticker := time.NewTicker(cfg.simulateInterval)
	defer ticker.Stop()

	idx := 0
	for {
		select {
		case <-stop:
			return
		case <-ticker.C:
			line := queries[idx%len(queries)]
			cfg.dbg("simulate query[%d]: %s", idx, line)
			lines <- line
			idx++
		}
	}
}

// ---------------------------------------------------------------------------
// Main processing loop
// ---------------------------------------------------------------------------

// run wires together the line source, parser, enrichment, and ingest pipeline.
func run(cfg *config) error {
	client := &http.Client{Timeout: cfg.httpTimeout}
	conns := newConnectionMap()
	lines := make(chan string, 256)
	stop := make(chan struct{})

	// Graceful shutdown on SIGINT / SIGTERM.
	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		sig := <-sigs
		infoLog.Printf("received %s — shutting down", sig)
		close(stop)
	}()

	// Start the line source in its own goroutine.
	var sourceErr error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(lines) // Signal the processing loop to drain and exit.

		if cfg.simulate {
			simulate(cfg, lines, stop)
		} else {
			if err := tailFile(cfg, lines, stop); err != nil {
				sourceErr = err
				errLog.Printf("tailer: %v", err)
			}
		}
	}()

	// Process lines as they arrive.
	for line := range lines {
		payload, ok := parseLine(line, conns, cfg)
		if !ok {
			continue
		}

		// Resolve source hostname via reverse DNS.
		payload.SourceHost = resolveHost(payload.SourceIP)
		cfg.dbg("resolve  %s -> %s", payload.SourceIP, payload.SourceHost)

		// Optional GeoIP enrichment — logged at DEBUG level only.
		if cfg.geoip {
			if geo := fetchGeoInfo(client, payload.SourceIP); geo != nil {
				cfg.dbg("geoip    %s -> country=%q city=%q isp=%q",
					payload.SourceIP, geo.Country, geo.City, geo.ISP)
			}
		}

		if err := postQuery(client, cfg.endpoint, payload, cfg); err != nil {
			errLog.Printf("ingest failed  ip=%s query=%q  err=%v",
				payload.SourceIP, payload.Query, err)
		} else {
			infoLog.Printf("ingested  ip=%-15s host=%s  query=%q",
				payload.SourceIP, payload.SourceHost, payload.Query)
		}
	}

	wg.Wait()
	return sourceErr
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

func main() {
	cfg := &config{}

	flag.StringVar(&cfg.logFile, "file", "/var/log/mysql/general.log",
		"Path to the MySQL general query log file to tail")
	flag.StringVar(&cfg.endpoint, "endpoint", defaultEndpoint,
		"FileSense ingest API endpoint URL")
	flag.BoolVar(&cfg.simulate, "simulate", false,
		"Send pre-defined test queries instead of tailing a real log file")
	flag.DurationVar(&cfg.simulateInterval, "simulate-interval", time.Second,
		"Interval between simulated query events (e.g. 500ms, 2s)")
	flag.BoolVar(&cfg.debug, "debug", false,
		"Enable verbose debug logging to stderr")
	flag.BoolVar(&cfg.geoip, "geoip", false,
		"Enrich events with GeoIP metadata via ip-api.com (requires outbound HTTP)")
	flag.DurationVar(&cfg.httpTimeout, "http-timeout", 5*time.Second,
		"HTTP client timeout for ingest POSTs and GeoIP requests")
	flag.Parse()

	if !cfg.simulate && cfg.logFile == "" {
		fmt.Fprintln(os.Stderr, "error: -file is required unless -simulate is set")
		os.Exit(1)
	}

	infoLog.Printf("FileSense agent starting  endpoint=%s simulate=%v debug=%v geoip=%v",
		cfg.endpoint, cfg.simulate, cfg.debug, cfg.geoip)

	if err := run(cfg); err != nil {
		errLog.Printf("fatal: %v", err)
		os.Exit(1)
	}
}
