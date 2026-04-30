package main

import (
	"crypto/tls"
	"fmt"
	"net"
	"time"
)

// ScanResult holds the result of a TLS scan for a single host.
type ScanResult struct {
	IP          string
	Port        string
	ServerName  string
	Version     uint16
	CipherSuite uint16
	Cert        *CertInfo
	SupportsH2  bool
	Error       error
}

// CertInfo holds relevant certificate details.
type CertInfo struct {
	Subject    string
	Issuer     string
	NotBefore  time.Time
	NotAfter   time.Time
	SANs       []string
	IsCA       bool
}

// Scanner performs TLS scanning operations.
type Scanner struct {
	Timeout    time.Duration
	ServerName string
	Port       string
}

// NewScanner creates a new Scanner with sensible defaults.
func NewScanner(serverName, port string, timeout time.Duration) *Scanner {
	if timeout == 0 {
		// Increased default timeout from 5s to 10s to reduce false negatives
		// on slower or geographically distant hosts.
		timeout = 10 * time.Second
	}
	if port == "" {
		port = "443"
	}
	return &Scanner{
		Timeout:    timeout,
		ServerName: serverName,
		Port:       port,
	}
}

// Scan performs a TLS handshake against the given IP and returns a ScanResult.
func (s *Scanner) Scan(ip string) *ScanResult {
	result := &ScanResult{
		IP:         ip,
		Port:       s.Port,
		ServerName: s.ServerName,
	}

	addr := net.JoinHostPort(ip, s.Port)

	dialer := &net.Dialer{
		Timeout: s.Timeout,
	}

	tlsCfg := &tls.Config{
		ServerName:         s.ServerName,
		InsecureSkipVerify: false, //nolint:gosec // intentional for scanning
		MinVersion:         tls.VersionTLS12,
		NextProtos:         []string{"h2", "http/1.1"},
	}

	conn, err := tls.DialWithDialer(dialer, "tcp", addr, tlsCfg)
	if err != nil {
		result.Error = fmt.Errorf("dial %s: %w", addr, err)
		return result
	}
	defer conn.Close()

	state := conn.ConnectionState()
	result.Version = state.Version
	result.CipherSuite = state.CipherSuite
	result.SupportsH2 = state.NegotiatedProtocol == "h2"

	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		result.Cert = &CertInfo{
			Subject:   cert.Subject.String(),
			Issuer:    cert.Issuer.String(),
			NotBefore: cert.NotBefore,
			NotAfter:  cert.NotAfter,
			SANs:      cert.DNSNames,
			IsCA:      cert.IsCA,
		}
	}

	return result
}

// TLSVersionName returns a human-readable TLS version string.
func TLSVersionName(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return fmt.Sprintf("Unknown(0x%04x)", version)
	}
}
