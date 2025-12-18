package main

import (
	"fmt"
	"strings"
)

// AnalysisResult contains the complete network fingerprint analysis
type AnalysisResult struct {
	Summary          *AnalysisSummary       `json:"summary"`
	TLSAnalysis      *TLSAnalysis           `json:"tls_analysis"`
	HTTP2Analysis    *HTTP2Analysis         `json:"http2_analysis,omitempty"`
	TCPAnalysis      *TCPAnalysis           `json:"tcp_analysis,omitempty"`
	ConsistencyCheck *ConsistencyAnalysis   `json:"consistency_check"`
	SecurityAdvice   *SecurityAdvice        `json:"security_advice"`
	RawFingerprint   *CombinedFingerprint   `json:"raw_fingerprint"`
}

// AnalysisSummary provides a high-level overview
type AnalysisSummary struct {
	RiskLevel       string   `json:"risk_level"`        // low, medium, high
	Uniqueness      string   `json:"uniqueness"`        // common, uncommon, rare, unique
	DetectedClient  string   `json:"detected_client"`   // Chrome, Firefox, curl, Python, etc.
	DetectedOS      string   `json:"detected_os"`       // Windows, macOS, Linux, etc.
	IsBot           bool     `json:"is_bot"`            // Likely automated client
	IsSpoofed       bool     `json:"is_spoofed"`        // Fingerprint appears manipulated
	Warnings        []string `json:"warnings,omitempty"`
}

// TLSAnalysis analyzes TLS fingerprint
type TLSAnalysis struct {
	Protocol        string   `json:"protocol"`          // TLS 1.2, TLS 1.3
	ClientType      string   `json:"client_type"`       // Browser, Library, Bot
	ClientName      string   `json:"client_name"`       // Chrome, Firefox, curl, etc.
	ClientVersion   string   `json:"client_version,omitempty"`
	JA3Popularity   string   `json:"ja3_popularity"`    // Common, Rare, Unknown
	JA4Popularity   string   `json:"ja4_popularity"`
	CipherStrength  string   `json:"cipher_strength"`   // Strong, Medium, Weak
	Observations    []string `json:"observations"`
}

// HTTP2Analysis analyzes HTTP/2 fingerprint
type HTTP2Analysis struct {
	Detected        bool     `json:"detected"`
	ClientMatch     string   `json:"client_match,omitempty"`  // Matches Chrome/Firefox/etc.
	IsImpersonator  bool     `json:"is_impersonator"`         // Detected as curl-impersonate or similar
	ImpersonatorType string  `json:"impersonator_type,omitempty"` // curl-impersonate, tls-client, etc.
	Observations    []string `json:"observations"`
}

// TCPAnalysis analyzes TCP/IP fingerprint
type TCPAnalysis struct {
	Detected       bool     `json:"detected"`
	InferredOS     string   `json:"inferred_os,omitempty"`
	OSConfidence   string   `json:"os_confidence,omitempty"`
	TTLAnalysis    string   `json:"ttl_analysis,omitempty"`
	Observations   []string `json:"observations"`
}

// ConsistencyAnalysis checks cross-layer consistency
type ConsistencyAnalysis struct {
	Passed     bool     `json:"passed"`
	Score      int      `json:"score"`        // 0-100
	Anomalies  []string `json:"anomalies,omitempty"`
	Details    []string `json:"details"`
}

// SecurityAdvice provides recommendations
type SecurityAdvice struct {
	OverallRisk    string           `json:"overall_risk"`      // low, medium, high
	ForDefenders   []AdviceItem     `json:"for_defenders"`     // If you're defending against bots
	ForPentesters  []AdviceItem     `json:"for_pentesters"`    // If you're testing/attacking
	Recommendations []string        `json:"recommendations"`
}

// AdviceItem is a single piece of advice
type AdviceItem struct {
	Category    string `json:"category"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Priority    string `json:"priority"` // high, medium, low
}

// Known JA3 hashes for common clients
var knownJA3Hashes = map[string]string{
	"e7d705a3286e19ea42f587b344ee6865": "Chrome (Windows)",
	"b32309a26951912be7dba376398abc3b": "Chrome (macOS)",
	"cd08e31494f9531f560d64c695473da9": "Firefox",
	"3b5074b1b5d032e5620f69f9f700ff0e": "Safari",
	"9e10692f1b7f78228b2d4e424db3a98c": "Python Requests",
	"eb5de76a6b5b6cdd6c2249b96be74c51": "Python urllib",
	"6734f37431670b3ab4292b8f60f29984": "curl",
	"3d58c55c3e8c19a0c0f0e8d8f8f8f8f8": "Go HTTP Client",
	"e3bb8f1cd407701c585e7a84c578b26e": "Node.js",
}

// Known JA4 prefixes for client identification
var knownJA4Prefixes = map[string]string{
	"t13d": "TLS 1.3 with domain SNI (Browser)",
	"t13i": "TLS 1.3 without SNI (Library/Bot)",
	"t12d": "TLS 1.2 with domain SNI",
	"t12i": "TLS 1.2 without SNI (Library/Bot)",
}

// AnalyzeFingerprint performs comprehensive analysis
func AnalyzeFingerprint(fp *CombinedFingerprint, clientIP string, userAgent string) *AnalysisResult {
	result := &AnalysisResult{
		Summary:          &AnalysisSummary{},
		TLSAnalysis:      &TLSAnalysis{},
		ConsistencyCheck: &ConsistencyAnalysis{},
		SecurityAdvice:   &SecurityAdvice{},
		RawFingerprint:   fp,
	}

	if fp == nil || fp.TLS == nil {
		result.Summary.RiskLevel = "unknown"
		result.Summary.Warnings = append(result.Summary.Warnings, "No TLS fingerprint available")
		return result
	}

	// Analyze TLS
	analyzeTLS(fp.TLS, result, userAgent)

	// Analyze HTTP/2
	if fp.HTTP2 != nil {
		result.HTTP2Analysis = analyzeHTTP2(fp.HTTP2)
	}

	// Analyze TCP/IP
	if fp.TCP != nil {
		result.TCPAnalysis = analyzeTCP(fp.TCP)
	}

	// Cross-layer consistency check
	analyzeConsistency(fp, result, userAgent)

	// Generate summary
	generateSummary(result, userAgent)

	// Generate security advice
	generateSecurityAdvice(result)

	return result
}

func analyzeTLS(tls *TLSFingerprint, result *AnalysisResult, userAgent string) {
	analysis := result.TLSAnalysis

	// Determine TLS version
	if strings.Contains(tls.TLSVersionNegotiated, "1.3") {
		analysis.Protocol = "TLS 1.3"
		analysis.Observations = append(analysis.Observations, "Using modern TLS 1.3 - good security")
	} else if strings.Contains(tls.TLSVersionNegotiated, "1.2") {
		analysis.Protocol = "TLS 1.2"
		analysis.Observations = append(analysis.Observations, "Using TLS 1.2 - acceptable security")
	} else {
		analysis.Protocol = tls.TLSVersionNegotiated
		analysis.Observations = append(analysis.Observations, "Using older TLS version - potential security concern")
	}

	// Check JA3 hash against known clients
	if clientName, ok := knownJA3Hashes[tls.JA3Hash]; ok {
		analysis.ClientName = clientName
		analysis.JA3Popularity = "Known"
		analysis.Observations = append(analysis.Observations, fmt.Sprintf("JA3 matches known client: %s", clientName))
	} else {
		analysis.JA3Popularity = "Unknown"
		analysis.Observations = append(analysis.Observations, "JA3 hash not in common client database - could be modified or uncommon client")
	}

	// Analyze JA4
	if len(tls.JA4) >= 4 {
		prefix := tls.JA4[:4]
		if desc, ok := knownJA4Prefixes[prefix]; ok {
			analysis.JA4Popularity = desc
		}
	}

	// Determine client type based on various signals
	analysis.ClientType = detectClientType(tls, userAgent)

	// Analyze cipher strength
	analysis.CipherStrength = analyzeCipherStrength(tls.Ciphers)

	// Check for suspicious patterns
	if len(tls.ALPN) == 0 {
		analysis.Observations = append(analysis.Observations, "No ALPN extension - unusual for modern browsers")
	}

	if tls.SNI == "" {
		analysis.Observations = append(analysis.Observations, "No SNI (Server Name Indication) - often indicates non-browser client or IP-direct access")
	}

	// Check cipher suite count
	if len(tls.Ciphers) < 5 {
		analysis.Observations = append(analysis.Observations, "Very few cipher suites offered - possibly a limited/custom client")
	} else if len(tls.Ciphers) > 30 {
		analysis.Observations = append(analysis.Observations, "Many cipher suites offered - typical of browsers")
	}
}

func analyzeHTTP2(http2 *HTTP2Fingerprint) *HTTP2Analysis {
	analysis := &HTTP2Analysis{
		Detected: true,
	}

	// Known HTTP/2 fingerprints (exact match)
	knownHTTP2 := map[string]string{
		"1:65536;3:1000;4:6291456;6:262144|15663105|0|m,a,s,p":    "Chrome",
		"1:65536;4:131072;5:16384|12517377|3:0:0:201,5:0:0:101,7:0:0:1,9:0:7:1,11:0:3:1,13:0:0:241|m,p,a,s": "Firefox",
		"1:65536;4:65535;3:100|0|0|m,s,p,a": "Safari",
	}

	if clientName, ok := knownHTTP2[http2.Akamai]; ok {
		analysis.ClientMatch = clientName
		analysis.Observations = append(analysis.Observations, fmt.Sprintf("HTTP/2 fingerprint matches %s", clientName))
	} else {
		analysis.Observations = append(analysis.Observations, "HTTP/2 fingerprint doesn't match common browsers")
	}

	// ===== curl-impersonate / Impersonator Detection =====
	impersonatorSignals := 0
	var impersonatorReasons []string

	// Signal 1: pseudo_header_order missing :path
	// Real Chrome sends "m,a,s,p", curl-impersonate sends "m,a,s"
	if http2.PseudoHeaderOrder != "" {
		if !strings.Contains(http2.PseudoHeaderOrder, "p") {
			impersonatorSignals += 2
			impersonatorReasons = append(impersonatorReasons, "pseudo_header_order missing ':path' - curl-impersonate signature")
		}
	}

	// Signal 2: Explicit ENABLE_PUSH=0 (id=2)
	// Real Chrome doesn't send this setting explicitly
	hasEnablePush := false
	hasMaxConcurrentStreams := false
	for _, setting := range http2.Settings {
		if setting.ID == 2 { // ENABLE_PUSH
			hasEnablePush = true
			if setting.Value == 0 {
				impersonatorSignals++
				impersonatorReasons = append(impersonatorReasons, "explicit ENABLE_PUSH=0 - uncommon for real browsers")
			}
		}
		if setting.ID == 3 { // MAX_CONCURRENT_STREAMS
			hasMaxConcurrentStreams = true
		}
		if setting.Name == "INITIAL_WINDOW_SIZE" && setting.Value == 6291456 {
			analysis.Observations = append(analysis.Observations, "Window size matches Chrome default")
		}
	}

	// Signal 3: Missing MAX_CONCURRENT_STREAMS (id=3)
	// Real Chrome sends "3:1000", curl-impersonate often omits it
	if !hasMaxConcurrentStreams && hasEnablePush {
		impersonatorSignals++
		impersonatorReasons = append(impersonatorReasons, "missing MAX_CONCURRENT_STREAMS but has ENABLE_PUSH - curl-impersonate pattern")
	}

	// Signal 4: Has Chrome-like settings but doesn't match exactly
	// Check if it looks like Chrome but isn't
	if strings.Contains(http2.Akamai, "1:65536") &&
	   strings.Contains(http2.Akamai, "4:6291456") &&
	   strings.Contains(http2.Akamai, "15663105") {
		// Looks like Chrome but doesn't match exactly
		if analysis.ClientMatch != "Chrome" {
			impersonatorSignals++
			impersonatorReasons = append(impersonatorReasons, "Chrome-like HTTP/2 settings but fingerprint doesn't match exactly")
		}
	}

	// Determine if this is an impersonator
	if impersonatorSignals >= 2 {
		analysis.IsImpersonator = true
		analysis.ImpersonatorType = "curl-impersonate/curl_cffi"
		analysis.Observations = append(analysis.Observations,
			fmt.Sprintf("⚠️ Detected as browser impersonator (confidence: %d signals)", impersonatorSignals))
		for _, reason := range impersonatorReasons {
			analysis.Observations = append(analysis.Observations, fmt.Sprintf("  → %s", reason))
		}
	} else if impersonatorSignals == 1 {
		analysis.Observations = append(analysis.Observations,
			fmt.Sprintf("Possible impersonator (1 signal): %s", strings.Join(impersonatorReasons, ", ")))
	}

	return analysis
}

func analyzeTCP(tcp *TCPIPFingerprint) *TCPAnalysis {
	analysis := &TCPAnalysis{
		Detected:     true,
		InferredOS:   tcp.InferredOS,
		OSConfidence: tcp.OSConfidence,
	}

	// Analyze TTL
	if tcp.TTL > 0 {
		analysis.TTLAnalysis = fmt.Sprintf("Observed TTL: %d, Initial TTL estimate: %d", tcp.TTL, tcp.InitialTTL)

		switch tcp.InitialTTL {
		case 64:
			analysis.Observations = append(analysis.Observations, "TTL suggests Linux/macOS/Unix system")
		case 128:
			analysis.Observations = append(analysis.Observations, "TTL suggests Windows system")
		case 255:
			analysis.Observations = append(analysis.Observations, "TTL suggests network device or specialized system")
		}
	}

	// Check for anomalies
	if len(tcp.Anomalies) > 0 {
		analysis.Observations = append(analysis.Observations, fmt.Sprintf("Detected %d anomalies in TCP fingerprint", len(tcp.Anomalies)))
		for _, a := range tcp.Anomalies {
			analysis.Observations = append(analysis.Observations, fmt.Sprintf("  - %s", a))
		}
	}

	// Analyze TCP options
	if tcp.OptionsStr != "" {
		analysis.Observations = append(analysis.Observations, fmt.Sprintf("TCP options pattern: %s", tcp.OptionsStr))
	}

	// Check timestamp for uptime estimation
	if tcp.Timestamp != nil && tcp.Timestamp.Uptime != "" {
		analysis.Observations = append(analysis.Observations, fmt.Sprintf("Estimated system uptime: %s", tcp.Timestamp.Uptime))
	}

	return analysis
}

func analyzeConsistency(fp *CombinedFingerprint, result *AnalysisResult, userAgent string) {
	check := result.ConsistencyCheck
	check.Score = 100

	// Check 1: TLS vs User-Agent consistency
	if userAgent != "" {
		uaLower := strings.ToLower(userAgent)
		tlsClient := strings.ToLower(result.TLSAnalysis.ClientName)

		if strings.Contains(uaLower, "chrome") && !strings.Contains(tlsClient, "chrome") && tlsClient != "" {
			check.Anomalies = append(check.Anomalies, "User-Agent claims Chrome but TLS fingerprint doesn't match")
			check.Score -= 30
		}
		if strings.Contains(uaLower, "firefox") && !strings.Contains(tlsClient, "firefox") && tlsClient != "" {
			check.Anomalies = append(check.Anomalies, "User-Agent claims Firefox but TLS fingerprint doesn't match")
			check.Score -= 30
		}
	}

	// Check 2: TLS vs HTTP/2 consistency
	if fp.HTTP2 != nil && result.HTTP2Analysis != nil {
		tlsClient := strings.ToLower(result.TLSAnalysis.ClientName)
		http2Client := strings.ToLower(result.HTTP2Analysis.ClientMatch)

		if tlsClient != "" && http2Client != "" && !strings.Contains(tlsClient, http2Client) && !strings.Contains(http2Client, tlsClient) {
			check.Anomalies = append(check.Anomalies, fmt.Sprintf("TLS suggests %s but HTTP/2 suggests %s", result.TLSAnalysis.ClientName, result.HTTP2Analysis.ClientMatch))
			check.Score -= 20
		} else if tlsClient != "" && http2Client != "" {
			check.Details = append(check.Details, "TLS and HTTP/2 fingerprints are consistent")
		}
	}

	// Check 3: TCP OS vs User-Agent consistency
	if fp.TCP != nil && userAgent != "" {
		uaLower := strings.ToLower(userAgent)
		tcpOS := strings.ToLower(fp.TCP.InferredOS)

		if strings.Contains(uaLower, "windows") && strings.Contains(tcpOS, "linux") {
			check.Anomalies = append(check.Anomalies, "User-Agent claims Windows but TCP fingerprint suggests Linux")
			check.Score -= 40
		}
		if strings.Contains(uaLower, "mac") && strings.Contains(tcpOS, "windows") {
			check.Anomalies = append(check.Anomalies, "User-Agent claims macOS but TCP fingerprint suggests Windows")
			check.Score -= 40
		}
	}

	// Check 4: TCP anomalies from the collector
	if fp.TCP != nil && len(fp.TCP.Anomalies) > 0 {
		for _, a := range fp.TCP.Anomalies {
			check.Anomalies = append(check.Anomalies, a)
			check.Score -= 10
		}
	}

	// Ensure score doesn't go below 0
	if check.Score < 0 {
		check.Score = 0
	}

	check.Passed = len(check.Anomalies) == 0

	if check.Passed {
		check.Details = append(check.Details, "All cross-layer checks passed")
	}
}

func generateSummary(result *AnalysisResult, userAgent string) {
	summary := result.Summary

	// Determine detected client
	if result.HTTP2Analysis != nil && result.HTTP2Analysis.IsImpersonator {
		// Impersonator detected - override client name
		summary.DetectedClient = fmt.Sprintf("Impersonator (%s)", result.HTTP2Analysis.ImpersonatorType)
	} else if result.TLSAnalysis.ClientName != "" {
		summary.DetectedClient = result.TLSAnalysis.ClientName
	} else {
		summary.DetectedClient = "Unknown"
	}

	// Determine detected OS
	if result.TCPAnalysis != nil && result.TCPAnalysis.InferredOS != "" {
		summary.DetectedOS = result.TCPAnalysis.InferredOS
	} else {
		// Try to infer from User-Agent
		if userAgent != "" {
			uaLower := strings.ToLower(userAgent)
			switch {
			case strings.Contains(uaLower, "windows"):
				summary.DetectedOS = "Windows (from UA)"
			case strings.Contains(uaLower, "mac"):
				summary.DetectedOS = "macOS (from UA)"
			case strings.Contains(uaLower, "linux"):
				summary.DetectedOS = "Linux (from UA)"
			default:
				summary.DetectedOS = "Unknown"
			}
		}
	}

	// Determine uniqueness
	if result.TLSAnalysis.JA3Popularity == "Known" {
		summary.Uniqueness = "common"
	} else {
		summary.Uniqueness = "uncommon"
	}

	// Determine if likely bot
	botSignals := 0

	// Signal 1: TLS client type is Library/Bot
	if result.TLSAnalysis.ClientType == "Library" || result.TLSAnalysis.ClientType == "Bot" {
		botSignals++
	}

	// Signal 2: Consistency check failed
	if result.ConsistencyCheck.Score < 70 {
		botSignals++
	}

	// Signal 3: No SNI
	if result.RawFingerprint.TLS != nil && result.RawFingerprint.TLS.SNI == "" {
		botSignals++
	}

	// Signal 4: HTTP/2 Impersonator detected (strong signal)
	if result.HTTP2Analysis != nil && result.HTTP2Analysis.IsImpersonator {
		botSignals += 2  // Strong signal - counts as 2
	}

	summary.IsBot = botSignals >= 2

	// Determine if spoofed (trying to look like something else)
	summary.IsSpoofed = len(result.ConsistencyCheck.Anomalies) > 0 ||
		(result.HTTP2Analysis != nil && result.HTTP2Analysis.IsImpersonator)

	// Determine risk level
	switch {
	case result.HTTP2Analysis != nil && result.HTTP2Analysis.IsImpersonator:
		// Impersonator always gets medium or higher
		if result.ConsistencyCheck.Score >= 80 {
			summary.RiskLevel = "medium"
		} else {
			summary.RiskLevel = "high"
		}
	case result.ConsistencyCheck.Score >= 90 && !summary.IsBot:
		summary.RiskLevel = "low"
	case result.ConsistencyCheck.Score >= 60:
		summary.RiskLevel = "medium"
	default:
		summary.RiskLevel = "high"
	}

	// Add warnings
	if result.HTTP2Analysis != nil && result.HTTP2Analysis.IsImpersonator {
		summary.Warnings = append(summary.Warnings,
			fmt.Sprintf("🚨 Browser impersonator detected: %s", result.HTTP2Analysis.ImpersonatorType))
	}
	if summary.IsBot {
		summary.Warnings = append(summary.Warnings, "Client appears to be automated (bot/script)")
	}
	if summary.IsSpoofed && !(result.HTTP2Analysis != nil && result.HTTP2Analysis.IsImpersonator) {
		summary.Warnings = append(summary.Warnings, "Fingerprint inconsistencies detected - possible spoofing")
	}
	if result.TLSAnalysis.CipherStrength == "Weak" {
		summary.Warnings = append(summary.Warnings, "Weak cipher suites detected")
	}
}

func generateSecurityAdvice(result *AnalysisResult) {
	advice := result.SecurityAdvice
	advice.OverallRisk = result.Summary.RiskLevel

	// Advice for defenders (anti-bot, security teams)
	advice.ForDefenders = []AdviceItem{
		{
			Category:    "Detection",
			Title:       "TLS Fingerprinting",
			Description: fmt.Sprintf("This client's JA4 fingerprint is: %s. Use this for client identification.", result.RawFingerprint.TLS.JA4),
			Priority:    "high",
		},
	}

	if result.Summary.IsBot {
		advice.ForDefenders = append(advice.ForDefenders, AdviceItem{
			Category:    "Bot Detection",
			Title:       "Likely Automated Client",
			Description: "Multiple signals suggest this is an automated client. Consider blocking or challenging.",
			Priority:    "high",
		})
	}

	if result.HTTP2Analysis != nil && result.HTTP2Analysis.IsImpersonator {
		advice.ForDefenders = append(advice.ForDefenders, AdviceItem{
			Category:    "Impersonator Detection",
			Title:       fmt.Sprintf("Browser Impersonator: %s", result.HTTP2Analysis.ImpersonatorType),
			Description: "This client is using a browser impersonation library (curl-impersonate, curl_cffi, tls-client). HTTP/2 fingerprint reveals impersonation artifacts.",
			Priority:    "critical",
		})
	}

	if result.Summary.IsSpoofed && !(result.HTTP2Analysis != nil && result.HTTP2Analysis.IsImpersonator) {
		advice.ForDefenders = append(advice.ForDefenders, AdviceItem{
			Category:    "Spoofing Detection",
			Title:       "Fingerprint Manipulation Detected",
			Description: "Cross-layer analysis shows inconsistencies. This client may be trying to evade detection.",
			Priority:    "high",
		})
	}

	if result.ConsistencyCheck.Score < 100 {
		advice.ForDefenders = append(advice.ForDefenders, AdviceItem{
			Category:    "Consistency",
			Title:       "Cross-Layer Verification",
			Description: fmt.Sprintf("Consistency score: %d/100. Lower scores indicate potential manipulation.", result.ConsistencyCheck.Score),
			Priority:    "medium",
		})
	}

	// Advice for pentesters/red team
	advice.ForPentesters = []AdviceItem{
		{
			Category:    "Evasion",
			Title:       "Current Detection Risk",
			Description: fmt.Sprintf("Your fingerprint has %s detection risk. Consistency score: %d/100.", result.Summary.RiskLevel, result.ConsistencyCheck.Score),
			Priority:    "high",
		},
	}

	if result.RawFingerprint.TLS.SNI == "" {
		advice.ForPentesters = append(advice.ForPentesters, AdviceItem{
			Category:    "Improvement",
			Title:       "Add SNI",
			Description: "Your client is not sending SNI. This is a common bot indicator. Configure your client to send proper SNI.",
			Priority:    "high",
		})
	}

	if result.TLSAnalysis.JA3Popularity == "Unknown" {
		advice.ForPentesters = append(advice.ForPentesters, AdviceItem{
			Category:    "Improvement",
			Title:       "TLS Fingerprint Stands Out",
			Description: "Your JA3 hash is not common. Consider using a browser impersonation library like 'curl-impersonate' or 'tls-client'.",
			Priority:    "high",
		})
	}

	if len(result.ConsistencyCheck.Anomalies) > 0 {
		advice.ForPentesters = append(advice.ForPentesters, AdviceItem{
			Category:    "Improvement",
			Title:       "Fix Inconsistencies",
			Description: fmt.Sprintf("Detected %d cross-layer anomalies. These can be used to detect your client.", len(result.ConsistencyCheck.Anomalies)),
			Priority:    "high",
		})
	}

	// Impersonator-specific advice for pentesters
	if result.HTTP2Analysis != nil && result.HTTP2Analysis.IsImpersonator {
		advice.ForPentesters = append(advice.ForPentesters, AdviceItem{
			Category:    "Warning",
			Title:       "Impersonator Detected via HTTP/2",
			Description: "Your curl-impersonate/curl_cffi is detected through HTTP/2 fingerprint. Key issues: (1) pseudo_header_order missing ':path', (2) explicit ENABLE_PUSH=0, (3) missing MAX_CONCURRENT_STREAMS.",
			Priority:    "critical",
		})
		advice.ForPentesters = append(advice.ForPentesters, AdviceItem{
			Category:    "Recommendation",
			Title:       "Use Real Browser Instead",
			Description: "For complete evasion, use Playwright/Puppeteer with stealth plugins, or a real browser with automation. HTTP/2 frame-level fingerprints are hard to fake with libraries.",
			Priority:    "high",
		})
	}

	// General recommendations
	advice.Recommendations = []string{}

	if result.Summary.RiskLevel == "high" {
		advice.Recommendations = append(advice.Recommendations, "High risk of detection - recommend improving fingerprint consistency")
	}

	if result.Summary.IsBot {
		advice.Recommendations = append(advice.Recommendations, "Use browser automation tools (Playwright, Puppeteer) with stealth plugins for better fingerprint")
	}

	if result.TCPAnalysis == nil {
		advice.Recommendations = append(advice.Recommendations, "TCP/IP fingerprint not available - enable with sudo for complete analysis")
	}

	if len(advice.Recommendations) == 0 {
		advice.Recommendations = append(advice.Recommendations, "Fingerprint appears consistent and low-risk")
	}
}

func detectClientType(tls *TLSFingerprint, userAgent string) string {
	// Check for browser characteristics
	browserSignals := 0
	libSignals := 0

	// Browsers typically have many cipher suites
	if len(tls.Ciphers) > 15 {
		browserSignals++
	} else {
		libSignals++
	}

	// Browsers typically have ALPN with h2
	hasH2 := false
	for _, alpn := range tls.ALPN {
		if alpn == "h2" {
			hasH2 = true
			break
		}
	}
	if hasH2 {
		browserSignals++
	} else {
		libSignals++
	}

	// Browsers typically send SNI
	if tls.SNI != "" {
		browserSignals++
	} else {
		libSignals++
	}

	// Check known library fingerprints
	knownLibs := []string{"python", "curl", "go", "node", "java", "urllib"}
	if ua := strings.ToLower(userAgent); ua != "" {
		for _, lib := range knownLibs {
			if strings.Contains(ua, lib) {
				return "Library"
			}
		}
	}

	if browserSignals > libSignals {
		return "Browser"
	} else if libSignals > browserSignals {
		return "Library"
	}
	return "Unknown"
}

func analyzeCipherStrength(ciphers []string) string {
	hasWeak := false
	hasStrong := false

	for _, c := range ciphers {
		cLower := strings.ToLower(c)
		// Weak ciphers
		if strings.Contains(cLower, "rc4") || strings.Contains(cLower, "des") ||
			strings.Contains(cLower, "export") || strings.Contains(cLower, "null") {
			hasWeak = true
		}
		// Strong ciphers
		if strings.Contains(cLower, "aes_256") || strings.Contains(cLower, "chacha20") ||
			strings.Contains(cLower, "gcm") {
			hasStrong = true
		}
	}

	if hasWeak {
		return "Weak"
	}
	if hasStrong {
		return "Strong"
	}
	return "Medium"
}
