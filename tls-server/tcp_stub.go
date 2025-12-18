//go:build nolibpcap || (!linux && !darwin && !windows)
// +build nolibpcap !linux,!darwin,!windows

package main

import (
	"log"
	"time"
)

// Stub implementations when libpcap is not available

// TCPIPFingerprint represents TCP/IP layer fingerprint (stub)
type TCPIPFingerprint struct {
	TTL          int           `json:"ttl"`
	InitialTTL   int           `json:"initial_ttl"`
	IPVersion    int           `json:"ip_version"`
	IPFlags      string        `json:"ip_flags"`
	WindowSize   int           `json:"window_size"`
	MSS          int           `json:"mss"`
	WindowScale  int           `json:"window_scale"`
	Options      []TCPOption   `json:"options"`
	OptionsStr   string        `json:"options_str"`
	Timestamp    *TCPTimestamp `json:"timestamp,omitempty"`
	Signature    string        `json:"signature"`
	InferredOS   string        `json:"inferred_os"`
	OSConfidence string        `json:"os_confidence"`
	Anomalies    []string      `json:"anomalies,omitempty"`
}

type TCPOption struct {
	Kind  int    `json:"kind"`
	Name  string `json:"name"`
	Value int    `json:"value,omitempty"`
}

type TCPTimestamp struct {
	TSval  uint32 `json:"tsval"`
	TSecr  uint32 `json:"tsecr"`
	Uptime string `json:"uptime,omitempty"`
}

// StartTCPCapture is a stub that always returns nil (disabled)
func StartTCPCapture(iface string, port int) error {
	log.Printf("[TCP] TCP fingerprinting not available (built without libpcap support)")
	return nil
}

// GetTCPFingerprint always returns nil (disabled)
func GetTCPFingerprint(ip string) *TCPIPFingerprint {
	return nil
}

// CheckConsistency returns nil (disabled)
func CheckConsistency(tcpFp *TCPIPFingerprint, userAgent string) []string {
	return nil
}

// CleanupOldFingerprints is a no-op stub
func CleanupOldFingerprints(maxAge time.Duration) {
	// No-op
}
