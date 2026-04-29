package main

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

// ScanResult holds the result of scanning a single IP address.
type ScanResult struct {
	IP          string    `json:"ip"`
	Port        int       `json:"port"`
	TLSVersion  string    `json:"tls_version"`
	ServerName  string    `json:"server_name,omitempty"`
	Fingerprint string    `json:"fingerprint,omitempty"`
	Country     string    `json:"country,omitempty"`
	ASN         string    `json:"asn,omitempty"`
	RealityOK   bool      `json:"reality_ok"`
	LatencyMs   int64     `json:"latency_ms"`
	ScannedAt   time.Time `json:"scanned_at"`
	Error       string    `json:"error,omitempty"`
}

// ResultWriter handles writing scan results to output destinations.
type ResultWriter struct {
	mu       sync.Mutex
	file     *os.File
	encoder  *json.Encoder
	count    int
	filePath string
}

// NewResultWriter creates a new ResultWriter that writes JSON lines to the given file path.
// If filePath is empty, results are written to stdout.
func NewResultWriter(filePath string) (*ResultWriter, error) {
	rw := &ResultWriter{
		filePath: filePath,
	}

	if filePath == "" {
		rw.file = os.Stdout
	} else {
		f, err := os.OpenFile(filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return nil, fmt.Errorf("failed to open output file %s: %w", filePath, err)
		}
		rw.file = f
	}

	rw.encoder = json.NewEncoder(rw.file)
	rw.encoder.SetEscapeHTML(false)
	return rw, nil
}

// Write serializes a ScanResult as a JSON line and writes it to the output destination.
func (rw *ResultWriter) Write(result *ScanResult) error {
	rw.mu.Lock()
	defer rw.mu.Unlock()

	if err := rw.encoder.Encode(result); err != nil {
		return fmt.Errorf("failed to write result for %s: %w", result.IP, err)
	}
	rw.count++
	return nil
}

// Count returns the total number of results written.
func (rw *ResultWriter) Count() int {
	rw.mu.Lock()
	defer rw.mu.Unlock()
	return rw.count
}

// Close flushes and closes the underlying file if it is not stdout.
func (rw *ResultWriter) Close() error {
	rw.mu.Lock()
	defer rw.mu.Unlock()

	if rw.file != nil && rw.file != os.Stdout {
		return rw.file.Close()
	}
	return nil
}

// Summary prints a human-readable scan summary to stderr.
func (rw *ResultWriter) Summary(total int, duration time.Duration) {
	rw.mu.Lock()
	defer rw.mu.Unlock()

	fmt.Fprintf(os.Stderr, "\n--- Scan Summary ---\n")
	fmt.Fprintf(os.Stderr, "Total IPs scanned : %d\n", total)
	fmt.Fprintf(os.Stderr, "Reality-compatible: %d\n", rw.count)
	fmt.Fprintf(os.Stderr, "Duration          : %s\n", duration.Round(time.Millisecond))
	if rw.filePath != "" {
		fmt.Fprintf(os.Stderr, "Results written to: %s\n", rw.filePath)
	}
}
