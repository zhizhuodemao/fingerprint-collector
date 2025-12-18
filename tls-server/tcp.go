//go:build !nolibpcap && (linux || darwin || windows)
// +build !nolibpcap
// +build linux darwin windows

package main

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

// TCPIPFingerprint represents TCP/IP layer fingerprint
type TCPIPFingerprint struct {
	// IP layer
	TTL        int    `json:"ttl"`         // Observed TTL
	InitialTTL int    `json:"initial_ttl"` // Inferred initial TTL (64/128/255)
	IPVersion  int    `json:"ip_version"`  // 4 or 6
	IPFlags    string `json:"ip_flags"`    // DF, MF, etc.

	// TCP layer
	WindowSize  int `json:"window_size"`  // TCP initial window size
	MSS         int `json:"mss"`          // Maximum Segment Size
	WindowScale int `json:"window_scale"` // Window Scale factor

	// TCP Options
	Options    []TCPOption `json:"options"`     // Full options list
	OptionsStr string      `json:"options_str"` // Options signature: "M1460,S,T,N,W7"

	// TCP Timestamp (for uptime inference)
	Timestamp *TCPTimestamp `json:"timestamp,omitempty"`

	// Fingerprint hash
	Signature string `json:"signature"` // Full fingerprint hash

	// Inference results
	InferredOS   string `json:"inferred_os"`   // Windows/Linux/macOS/iOS/Android
	OSConfidence string `json:"os_confidence"` // high/medium/low

	// Consistency check results
	Anomalies []string `json:"anomalies,omitempty"`
}

// TCPOption represents a single TCP option
type TCPOption struct {
	Kind  int    `json:"kind"`            // Option type: 2=MSS, 3=WScale, 4=SACK, 8=Timestamp
	Name  string `json:"name"`            // Option name
	Value int    `json:"value,omitempty"` // Option value
}

// TCPTimestamp represents TCP timestamp option values
type TCPTimestamp struct {
	TSval  uint32 `json:"tsval"`            // Sender timestamp
	TSecr  uint32 `json:"tsecr"`            // Echo reply timestamp
	Uptime string `json:"uptime,omitempty"` // Inferred system uptime
}

// Global storage: IP -> TCP fingerprint
var tcpFingerprintStore = make(map[string]*TCPIPFingerprint)
var tcpStoreMutex sync.RWMutex

// TCP option kind constants
const (
	TCPOptionKindEndList    = 0
	TCPOptionKindNOP        = 1
	TCPOptionKindMSS        = 2
	TCPOptionKindWScale     = 3
	TCPOptionKindSACKPerm   = 4
	TCPOptionKindSACK       = 5
	TCPOptionKindTimestamp  = 8
)

// StartTCPCapture starts the TCP packet capture goroutine
func StartTCPCapture(iface string, port int) error {
	// Find available interfaces if not specified
	if iface == "" {
		interfaces := findCaptureInterfaces()
		if len(interfaces) == 0 {
			log.Printf("[TCP] Warning: No suitable network interface found, TCP fingerprinting disabled")
			return nil
		}
		// Start capture on all found interfaces
		for _, ifaceName := range interfaces {
			if err := startCaptureOnInterface(ifaceName, port); err != nil {
				log.Printf("[TCP] Warning: Failed to start capture on %s: %v", ifaceName, err)
			}
		}
		return nil
	}

	// Use specified interface
	return startCaptureOnInterface(iface, port)
}

// startCaptureOnInterface starts packet capture on a single interface
func startCaptureOnInterface(iface string, port int) error {
	// BPF filter: only capture SYN packets to our port
	filter := fmt.Sprintf("tcp dst port %d and tcp[tcpflags] & tcp-syn != 0 and tcp[tcpflags] & tcp-ack == 0", port)

	handle, err := pcap.OpenLive(iface, 1600, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("failed to open interface %s: %v", iface, err)
	}

	if err := handle.SetBPFFilter(filter); err != nil {
		handle.Close()
		return fmt.Errorf("failed to set BPF filter: %v", err)
	}

	log.Printf("[TCP] Capturing SYN packets on interface %s, port %d", iface, port)

	go func() {
		defer handle.Close()
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		for packet := range packetSource.Packets() {
			processTCPPacket(packet)
		}
	}()

	return nil
}

// findCaptureInterfaces finds suitable network interfaces for packet capture
// Returns both regular interfaces and loopback for localhost testing
func findCaptureInterfaces() []string {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Printf("[TCP] Error finding devices: %v", err)
		return nil
	}

	var interfaces []string
	var loopback string

	for _, device := range devices {
		// Skip interfaces without addresses (usually not useful)
		if len(device.Addresses) == 0 {
			continue
		}

		// Identify loopback interface
		if strings.Contains(device.Name, "lo") {
			loopback = device.Name
			continue
		}

		// Add regular interface
		interfaces = append(interfaces, device.Name)
	}

	// Add loopback interface for localhost testing (important!)
	if loopback != "" {
		interfaces = append(interfaces, loopback)
	}

	return interfaces
}

// findDefaultInterface finds a suitable network interface for packet capture (legacy)
func findDefaultInterface() string {
	interfaces := findCaptureInterfaces()
	if len(interfaces) > 0 {
		return interfaces[0]
	}
	return ""
}

// processTCPPacket processes a captured TCP packet
func processTCPPacket(packet gopacket.Packet) {
	// Parse IP layer
	var srcIP string
	var ttl int
	var ipVersion int
	var ipFlags string

	if ipv4Layer := packet.Layer(layers.LayerTypeIPv4); ipv4Layer != nil {
		ip := ipv4Layer.(*layers.IPv4)
		srcIP = ip.SrcIP.String()
		ttl = int(ip.TTL)
		ipVersion = 4
		ipFlags = formatIPv4Flags(ip.Flags)
	} else if ipv6Layer := packet.Layer(layers.LayerTypeIPv6); ipv6Layer != nil {
		ip := ipv6Layer.(*layers.IPv6)
		srcIP = ip.SrcIP.String()
		ttl = int(ip.HopLimit)
		ipVersion = 6
		ipFlags = ""
	} else {
		return
	}

	// Parse TCP layer
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return
	}
	tcp := tcpLayer.(*layers.TCP)

	// Only process SYN packets (not SYN-ACK)
	if !tcp.SYN || tcp.ACK {
		return
	}

	fp := &TCPIPFingerprint{
		TTL:        ttl,
		InitialTTL: guessInitialTTL(ttl),
		IPVersion:  ipVersion,
		IPFlags:    ipFlags,
		WindowSize: int(tcp.Window),
	}

	// Parse TCP options
	fp.Options, fp.OptionsStr, fp.MSS, fp.WindowScale, fp.Timestamp = parseTCPOptions(tcp.Options)

	// Infer operating system
	fp.InferredOS, fp.OSConfidence = inferOS(fp)

	// Generate signature hash
	fp.Signature = generateSignature(fp)

	// Store fingerprint
	tcpStoreMutex.Lock()
	tcpFingerprintStore[srcIP] = fp
	tcpStoreMutex.Unlock()

	log.Printf("[TCP] SYN from %s: TTL=%d(%d), Win=%d, Options=%s, OS=%s",
		srcIP, ttl, fp.InitialTTL, fp.WindowSize, fp.OptionsStr, fp.InferredOS)
}

// formatIPv4Flags formats IPv4 flags to string
func formatIPv4Flags(flags layers.IPv4Flag) string {
	var parts []string
	if flags&layers.IPv4DontFragment != 0 {
		parts = append(parts, "DF")
	}
	if flags&layers.IPv4MoreFragments != 0 {
		parts = append(parts, "MF")
	}
	if len(parts) == 0 {
		return "none"
	}
	return strings.Join(parts, ",")
}

// guessInitialTTL guesses the initial TTL based on observed TTL
func guessInitialTTL(ttl int) int {
	// Common initial TTL values:
	// Windows: 128
	// Linux/macOS/iOS/Android: 64
	// Some network devices: 255
	// Some older systems: 32

	if ttl <= 32 {
		return 32
	} else if ttl <= 64 {
		return 64
	} else if ttl <= 128 {
		return 128
	}
	return 255
}

// parseTCPOptions parses TCP options and returns structured data
func parseTCPOptions(opts []layers.TCPOption) ([]TCPOption, string, int, int, *TCPTimestamp) {
	var options []TCPOption
	var optStrs []string
	var mss int
	var wscale int
	var timestamp *TCPTimestamp

	for _, opt := range opts {
		tcpOpt := TCPOption{
			Kind: int(opt.OptionType),
		}

		switch opt.OptionType {
		case TCPOptionKindEndList:
			// End of options list
			continue

		case TCPOptionKindNOP:
			tcpOpt.Name = "NOP"
			optStrs = append(optStrs, "N")

		case TCPOptionKindMSS:
			tcpOpt.Name = "MSS"
			if len(opt.OptionData) >= 2 {
				mss = int(opt.OptionData[0])<<8 | int(opt.OptionData[1])
				tcpOpt.Value = mss
			}
			optStrs = append(optStrs, fmt.Sprintf("M%d", mss))

		case TCPOptionKindWScale:
			tcpOpt.Name = "WScale"
			if len(opt.OptionData) >= 1 {
				wscale = int(opt.OptionData[0])
				tcpOpt.Value = wscale
			}
			optStrs = append(optStrs, fmt.Sprintf("W%d", wscale))

		case TCPOptionKindSACKPerm:
			tcpOpt.Name = "SACK_PERM"
			optStrs = append(optStrs, "S")

		case TCPOptionKindSACK:
			tcpOpt.Name = "SACK"
			optStrs = append(optStrs, "K")

		case TCPOptionKindTimestamp:
			tcpOpt.Name = "Timestamp"
			if len(opt.OptionData) >= 8 {
				tsval := uint32(opt.OptionData[0])<<24 | uint32(opt.OptionData[1])<<16 |
					uint32(opt.OptionData[2])<<8 | uint32(opt.OptionData[3])
				tsecr := uint32(opt.OptionData[4])<<24 | uint32(opt.OptionData[5])<<16 |
					uint32(opt.OptionData[6])<<8 | uint32(opt.OptionData[7])
				tcpOpt.Value = int(tsval)
				timestamp = &TCPTimestamp{
					TSval:  tsval,
					TSecr:  tsecr,
					Uptime: estimateUptime(tsval),
				}
			}
			optStrs = append(optStrs, "T")

		default:
			tcpOpt.Name = fmt.Sprintf("Unknown(%d)", opt.OptionType)
			optStrs = append(optStrs, fmt.Sprintf("U%d", opt.OptionType))
		}

		options = append(options, tcpOpt)
	}

	return options, strings.Join(optStrs, ","), mss, wscale, timestamp
}

// estimateUptime estimates system uptime from TCP timestamp
func estimateUptime(tsval uint32) string {
	// TCP timestamp typically increments at 1000Hz (1ms) on Linux
	// and 100Hz (10ms) on some other systems
	// We assume 1000Hz as a rough estimate

	// This is a very rough estimate - actual tick rate varies by OS
	seconds := tsval / 1000
	if seconds == 0 {
		return ""
	}

	days := seconds / 86400
	hours := (seconds % 86400) / 3600
	minutes := (seconds % 3600) / 60

	if days > 0 {
		return fmt.Sprintf("%dd %dh %dm", days, hours, minutes)
	} else if hours > 0 {
		return fmt.Sprintf("%dh %dm", hours, minutes)
	} else if minutes > 0 {
		return fmt.Sprintf("%dm", minutes)
	}
	return fmt.Sprintf("%ds", seconds)
}

// inferOS infers operating system from TCP/IP fingerprint
func inferOS(fp *TCPIPFingerprint) (string, string) {
	// Check for TCP Timestamp option
	hasTimestamp := fp.Timestamp != nil

	switch fp.InitialTTL {
	case 128:
		// Windows typically uses TTL 128 and usually doesn't send TCP Timestamp
		if !hasTimestamp {
			return "Windows", "high"
		}
		// Windows with timestamp is unusual but possible
		return "Windows", "medium"

	case 64:
		// Linux, macOS, iOS, Android all use TTL 64
		// Differentiate based on other characteristics

		// macOS/iOS often has window size 65535
		if fp.WindowSize == 65535 {
			return "macOS/iOS", "medium"
		}

		// Android typically has smaller window sizes
		if fp.WindowSize < 20000 && hasTimestamp {
			return "Android", "low"
		}

		// Linux typically has larger window sizes and timestamp
		if fp.WindowSize > 20000 && hasTimestamp {
			return "Linux", "medium"
		}

		return "Linux/Unix", "low"

	case 255:
		// Network devices (routers, etc.)
		return "Network Device", "medium"

	case 32:
		// Some older or embedded systems
		return "Embedded/Old", "low"
	}

	return "Unknown", "low"
}

// generateSignature generates a hash signature for the TCP fingerprint
func generateSignature(fp *TCPIPFingerprint) string {
	// Format similar to p0f: version:ttl:olen:mss,opts:win,scale:flags
	sigStr := fmt.Sprintf("%d:%d:%s:%d:%s",
		fp.IPVersion,
		fp.InitialTTL,
		fp.OptionsStr,
		fp.WindowSize,
		fp.IPFlags,
	)

	hash := md5.Sum([]byte(sigStr))
	return hex.EncodeToString(hash[:])
}

// GetTCPFingerprint retrieves TCP fingerprint for an IP address
func GetTCPFingerprint(ip string) *TCPIPFingerprint {
	tcpStoreMutex.RLock()
	defer tcpStoreMutex.RUnlock()
	return tcpFingerprintStore[ip]
}

// CheckConsistency checks for anomalies between TCP fingerprint and User-Agent
func CheckConsistency(tcpFp *TCPIPFingerprint, userAgent string) []string {
	if tcpFp == nil {
		return nil
	}

	var anomalies []string

	// Parse claimed OS from User-Agent
	claimedOS := parseOSFromUA(userAgent)

	// 1. TTL vs User-Agent OS check
	if claimedOS != "" && !osMatches(claimedOS, tcpFp.InferredOS) {
		anomalies = append(anomalies,
			fmt.Sprintf("OS_MISMATCH: UA claims %s, TCP fingerprint suggests %s",
				claimedOS, tcpFp.InferredOS))
	}

	// 2. TCP Timestamp vs Windows check
	if strings.Contains(strings.ToLower(claimedOS), "windows") && tcpFp.Timestamp != nil {
		anomalies = append(anomalies,
			"TCP_TIMESTAMP_ANOMALY: Windows typically doesn't send TCP Timestamp option")
	}

	// 3. Default window size check (possible bot/script)
	if tcpFp.WindowSize == 65535 && !strings.Contains(tcpFp.InferredOS, "macOS") && !strings.Contains(tcpFp.InferredOS, "iOS") {
		anomalies = append(anomalies,
			"DEFAULT_WINDOW: Using default TCP window size 65535, possible bot/script")
	}

	// 4. Short uptime check (possible container/VM)
	if tcpFp.Timestamp != nil && tcpFp.Timestamp.TSval > 0 {
		uptimeSeconds := tcpFp.Timestamp.TSval / 1000
		if uptimeSeconds < 600 { // Less than 10 minutes
			anomalies = append(anomalies,
				fmt.Sprintf("SHORT_UPTIME: System uptime ~%s, possibly a newly started container/VM",
					tcpFp.Timestamp.Uptime))
		}
	}

	// 5. Missing options check
	if len(tcpFp.Options) < 3 {
		anomalies = append(anomalies,
			"MINIMAL_OPTIONS: Very few TCP options, unusual for modern browsers")
	}

	return anomalies
}

// parseOSFromUA extracts OS information from User-Agent string
func parseOSFromUA(ua string) string {
	ua = strings.ToLower(ua)
	switch {
	case strings.Contains(ua, "windows"):
		return "Windows"
	case strings.Contains(ua, "macintosh") || strings.Contains(ua, "mac os"):
		return "macOS"
	case strings.Contains(ua, "iphone") || strings.Contains(ua, "ipad"):
		return "iOS"
	case strings.Contains(ua, "android"):
		return "Android"
	case strings.Contains(ua, "linux"):
		return "Linux"
	case strings.Contains(ua, "cros"):
		return "ChromeOS"
	}
	return ""
}

// osMatches checks if claimed OS matches inferred OS
func osMatches(claimed, inferred string) bool {
	claimed = strings.ToLower(claimed)
	inferred = strings.ToLower(inferred)

	// Exact match
	if strings.Contains(inferred, claimed) || strings.Contains(claimed, inferred) {
		return true
	}

	// Windows check - TTL 128 systems
	if claimed == "windows" && strings.Contains(inferred, "windows") {
		return true
	}

	// macOS/iOS check - both use TTL 64
	if (claimed == "macos" || claimed == "ios") &&
		(strings.Contains(inferred, "macos") || strings.Contains(inferred, "ios")) {
		return true
	}

	// Linux/Android check - both use TTL 64
	if (claimed == "linux" || claimed == "android") &&
		(strings.Contains(inferred, "linux") || strings.Contains(inferred, "android") || strings.Contains(inferred, "unix")) {
		return true
	}

	return false
}

// CleanupOldFingerprints removes fingerprints older than the specified duration
func CleanupOldFingerprints(maxAge time.Duration) {
	// Note: This is a simplified cleanup. In production, you'd want to
	// track timestamps for each fingerprint entry.
	ticker := time.NewTicker(maxAge)
	go func() {
		for range ticker.C {
			tcpStoreMutex.Lock()
			// Clear all fingerprints periodically
			// In production, implement proper timestamp-based cleanup
			if len(tcpFingerprintStore) > 10000 {
				tcpFingerprintStore = make(map[string]*TCPIPFingerprint)
				log.Printf("[TCP] Cleared fingerprint store (exceeded 10000 entries)")
			}
			tcpStoreMutex.Unlock()
		}
	}()
}
