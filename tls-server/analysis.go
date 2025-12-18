package main

import (
	"fmt"
	"strings"
)

// SimpleAnalysisResult is the simplified API response
type SimpleAnalysisResult struct {
	// 核心判断
	RiskScore   int    `json:"risk_score"`   // 0-100, 越高越可疑
	RiskLevel   string `json:"risk_level"`   // low, medium, high
	IsBot       bool   `json:"is_bot"`       // 是否是机器人/爬虫
	IsSpoofed   bool   `json:"is_spoofed"`   // 是否伪装

	// 客户端识别
	Client      ClientInfo `json:"client"`

	// 指纹摘要
	Fingerprints FingerprintSummary `json:"fingerprints"`

	// 异常列表 (空=正常)
	Anomalies   []string `json:"anomalies,omitempty"`

	// 完整数据 (可选，用于调试)
	Details     *AnalysisResult `json:"details,omitempty"`
}

// ClientInfo 客户端识别信息
type ClientInfo struct {
	Type     string `json:"type"`              // browser, bot, library, impersonator
	Claimed  string `json:"claimed"`           // UA 声称的: "Chrome 131 on Windows"
	Detected string `json:"detected"`          // 实际检测到的: "curl-impersonate on macOS"
	Match    bool   `json:"match"`             // claimed 和 detected 是否一致
}

// FingerprintSummary 指纹摘要
type FingerprintSummary struct {
	JA3     string `json:"ja3"`               // JA3 hash
	JA4     string `json:"ja4"`               // JA4 fingerprint
	HTTP2   string `json:"http2,omitempty"`   // HTTP/2 Akamai hash
	TCP     string `json:"tcp,omitempty"`     // TCP 签名: "64:65535:M1460,S,T,W7"
	TCPOS   string `json:"tcp_os,omitempty"`  // TCP 推断的 OS
}

// AnalysisResult contains the complete network fingerprint analysis (for details)
type AnalysisResult struct {
	Summary          *AnalysisSummary       `json:"summary"`
	RequestInfo      *RequestInfo           `json:"request_info"`
	TLSAnalysis      *TLSAnalysis           `json:"tls_analysis"`
	HTTP2Analysis    *HTTP2Analysis         `json:"http2_analysis,omitempty"`
	TCPAnalysis      *TCPAnalysis           `json:"tcp_analysis,omitempty"`
	ConsistencyCheck *ConsistencyAnalysis   `json:"consistency_check"`
	SecurityAdvice   *SecurityAdvice        `json:"security_advice"`
	RawFingerprint   *CombinedFingerprint   `json:"raw_fingerprint"`
}

// RequestInfo shows what data was used for analysis
type RequestInfo struct {
	ClientIP        string            `json:"client_ip"`
	UserAgent       string            `json:"user_agent,omitempty"`
	UserAgentParsed *ParsedUserAgent  `json:"user_agent_parsed,omitempty"`
	Headers         map[string]string `json:"headers,omitempty"`
}

// ParsedUserAgent contains parsed User-Agent information
type ParsedUserAgent struct {
	Browser        string `json:"browser,omitempty"`
	BrowserVersion string `json:"browser_version,omitempty"`
	OS             string `json:"os,omitempty"`
	OSVersion      string `json:"os_version,omitempty"`
	Platform       string `json:"platform,omitempty"`    // Desktop, Mobile, Tablet
	IsBot          bool   `json:"is_bot"`
	BotName        string `json:"bot_name,omitempty"`
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

// Note: JA3/JA4/HTTP2 fingerprint databases are loaded from JSON files in ./data/
// See database.go for the loading logic and data structures
// Files: ja3_fingerprints.json, ja4_fingerprints.json, http2_fingerprints.json

// AnalyzeFingerprint performs comprehensive analysis
func AnalyzeFingerprint(fp *CombinedFingerprint, clientIP string, userAgent string) *AnalysisResult {
	result := &AnalysisResult{
		Summary:          &AnalysisSummary{},
		RequestInfo:      &RequestInfo{ClientIP: clientIP},
		TLSAnalysis:      &TLSAnalysis{},
		ConsistencyCheck: &ConsistencyAnalysis{},
		SecurityAdvice:   &SecurityAdvice{},
		RawFingerprint:   fp,
	}

	// Parse and store User-Agent info
	if userAgent != "" {
		result.RequestInfo.UserAgent = userAgent
		result.RequestInfo.UserAgentParsed = parseUserAgent(userAgent)
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

	// Cross-layer consistency check (enhanced)
	analyzeConsistency(fp, result, userAgent)

	// Generate summary
	generateSummary(result, userAgent)

	// Generate security advice
	generateSecurityAdvice(result)

	return result
}

// parseUserAgent extracts browser, OS, and platform info from User-Agent string
func parseUserAgent(ua string) *ParsedUserAgent {
	if ua == "" {
		return nil
	}

	parsed := &ParsedUserAgent{}
	uaLower := strings.ToLower(ua)

	// Detect bots first
	botPatterns := map[string]string{
		"googlebot":   "Googlebot",
		"bingbot":     "Bingbot",
		"slurp":       "Yahoo Slurp",
		"duckduckbot": "DuckDuckBot",
		"baiduspider": "Baiduspider",
		"yandexbot":   "YandexBot",
		"facebookexternalhit": "Facebook",
		"twitterbot":  "Twitterbot",
		"curl/":       "curl",
		"wget/":       "Wget",
		"python-requests": "Python Requests",
		"python-urllib": "Python urllib",
		"go-http-client": "Go HTTP Client",
		"java/":       "Java",
		"apache-httpclient": "Apache HttpClient",
		"okhttp":      "OkHttp",
		"axios":       "Axios",
		"node-fetch":  "Node Fetch",
		"scrapy":      "Scrapy",
		"headless":    "Headless Browser",
		"phantomjs":   "PhantomJS",
		"selenium":    "Selenium",
		"puppeteer":   "Puppeteer",
		"playwright":  "Playwright",
	}

	for pattern, name := range botPatterns {
		if strings.Contains(uaLower, pattern) {
			parsed.IsBot = true
			parsed.BotName = name
			break
		}
	}

	// Detect browser
	switch {
	case strings.Contains(uaLower, "edg/"):
		parsed.Browser = "Edge"
		parsed.BrowserVersion = extractVersion(ua, "Edg/")
	case strings.Contains(uaLower, "opr/") || strings.Contains(uaLower, "opera"):
		parsed.Browser = "Opera"
		parsed.BrowserVersion = extractVersion(ua, "OPR/")
	case strings.Contains(uaLower, "chrome") && !strings.Contains(uaLower, "chromium"):
		parsed.Browser = "Chrome"
		parsed.BrowserVersion = extractVersion(ua, "Chrome/")
	case strings.Contains(uaLower, "firefox"):
		parsed.Browser = "Firefox"
		parsed.BrowserVersion = extractVersion(ua, "Firefox/")
	case strings.Contains(uaLower, "safari") && !strings.Contains(uaLower, "chrome"):
		parsed.Browser = "Safari"
		parsed.BrowserVersion = extractVersion(ua, "Version/")
	case strings.Contains(uaLower, "msie") || strings.Contains(uaLower, "trident"):
		parsed.Browser = "Internet Explorer"
	}

	// Detect OS
	switch {
	case strings.Contains(uaLower, "windows nt 10"):
		parsed.OS = "Windows"
		parsed.OSVersion = "10/11"
	case strings.Contains(uaLower, "windows nt 6.3"):
		parsed.OS = "Windows"
		parsed.OSVersion = "8.1"
	case strings.Contains(uaLower, "windows nt 6.1"):
		parsed.OS = "Windows"
		parsed.OSVersion = "7"
	case strings.Contains(uaLower, "windows"):
		parsed.OS = "Windows"
	case strings.Contains(uaLower, "mac os x"):
		parsed.OS = "macOS"
		// Extract version like "Mac OS X 10_15_7" -> "10.15.7"
		if idx := strings.Index(ua, "Mac OS X "); idx != -1 {
			verStr := ua[idx+9:]
			if endIdx := strings.IndexAny(verStr, ");"); endIdx != -1 {
				parsed.OSVersion = strings.ReplaceAll(verStr[:endIdx], "_", ".")
			}
		}
	case strings.Contains(uaLower, "iphone") || strings.Contains(uaLower, "ipad"):
		parsed.OS = "iOS"
	case strings.Contains(uaLower, "android"):
		parsed.OS = "Android"
		parsed.OSVersion = extractVersion(ua, "Android ")
	case strings.Contains(uaLower, "linux"):
		parsed.OS = "Linux"
	}

	// Detect platform type
	switch {
	case strings.Contains(uaLower, "mobile") || strings.Contains(uaLower, "iphone") || strings.Contains(uaLower, "android"):
		parsed.Platform = "Mobile"
	case strings.Contains(uaLower, "ipad") || strings.Contains(uaLower, "tablet"):
		parsed.Platform = "Tablet"
	default:
		parsed.Platform = "Desktop"
	}

	return parsed
}

// extractVersion extracts version number after a prefix
func extractVersion(ua, prefix string) string {
	idx := strings.Index(ua, prefix)
	if idx == -1 {
		return ""
	}
	start := idx + len(prefix)
	end := start
	for end < len(ua) && (ua[end] == '.' || (ua[end] >= '0' && ua[end] <= '9')) {
		end++
	}
	if end > start {
		return ua[start:end]
	}
	return ""
}

func analyzeTLS(tls *TLSFingerprint, result *AnalysisResult, userAgent string) {
	analysis := result.TLSAnalysis
	db := GetDatabase()

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

	// Check JA3 hash against database
	if clientName, clientType, found := db.LookupJA3(tls.JA3Hash); found {
		analysis.ClientName = clientName
		analysis.JA3Popularity = "Known"
		analysis.Observations = append(analysis.Observations, fmt.Sprintf("JA3 matches known client: %s (type: %s)", clientName, clientType))

		// Special handling for malware
		if clientType == "malware" {
			result.Summary.Warnings = append(result.Summary.Warnings,
				fmt.Sprintf("⚠️ JA3 fingerprint matches known malware: %s", clientName))
		}
	} else {
		analysis.JA3Popularity = "Unknown"
		analysis.Observations = append(analysis.Observations, "JA3 hash not in database - could be modified or uncommon client")
	}

	// Analyze JA4 using database
	if len(tls.JA4) >= 4 {
		if desc, clientType, risk := db.GetJA4Description(tls.JA4); desc != "" {
			analysis.JA4Popularity = fmt.Sprintf("%s (%s)", desc, clientType)
			if risk == "high" {
				analysis.Observations = append(analysis.Observations,
					fmt.Sprintf("JA4 indicates high-risk client type: %s", desc))
			}
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
	db := GetDatabase()

	// Look up HTTP/2 fingerprint in database
	if clientName, isImpersonator, detection := db.LookupHTTP2(http2.Akamai); clientName != "" {
		analysis.ClientMatch = clientName
		analysis.Observations = append(analysis.Observations, fmt.Sprintf("HTTP/2 fingerprint matches %s", clientName))
		if isImpersonator {
			analysis.IsImpersonator = true
			analysis.ImpersonatorType = clientName + " (exact match)"
			if detection != "" {
				analysis.Observations = append(analysis.Observations, fmt.Sprintf("Detection: %s", detection))
			}
		}
	} else {
		analysis.Observations = append(analysis.Observations, "HTTP/2 fingerprint doesn't match database entries")
	}

	// Analyze settings for Chrome default window size
	for _, setting := range http2.Settings {
		if setting.Name == "INITIAL_WINDOW_SIZE" && setting.Value == 6291456 {
			analysis.Observations = append(analysis.Observations, "Window size matches Chrome default")
			break
		}
	}

	// ===== curl-impersonate / Impersonator Detection =====
	// Use database rules for detection

	// Extract pseudo_header_order from akamai string if not set directly
	pseudoOrder := http2.PseudoHeaderOrder
	if pseudoOrder == "" && http2.Akamai != "" {
		// Akamai format: SETTINGS|WINDOW_UPDATE|PRIORITY|pseudo_header_order
		parts := strings.Split(http2.Akamai, "|")
		if len(parts) >= 4 {
			pseudoOrder = parts[3]
		}
	}

	// Check against database detection rules
	if isImpersonator, reasons := db.IsImpersonatorByHTTP2Rules(http2.Akamai, pseudoOrder); isImpersonator {
		analysis.IsImpersonator = true
		analysis.ImpersonatorType = "curl-impersonate/curl_cffi"
		analysis.Observations = append(analysis.Observations,
			fmt.Sprintf("⚠️ Detected as browser impersonator (confidence: %d signals)", len(reasons)))
		for _, reason := range reasons {
			analysis.Observations = append(analysis.Observations, fmt.Sprintf("  → %s", reason))
		}
	} else if len(reasons) > 0 {
		analysis.Observations = append(analysis.Observations,
			fmt.Sprintf("Note: %d potential impersonator signal(s): %s", len(reasons), strings.Join(reasons, "; ")))
	}

	// Additional frame_order check
	if len(http2.FrameOrder) > 0 && pseudoOrder == "" {
		hasHeaders := false
		for _, frame := range http2.FrameOrder {
			if frame == "HEADERS" {
				hasHeaders = true
				break
			}
		}
		if !hasHeaders {
			analysis.Observations = append(analysis.Observations, "No HEADERS frame detected - possible impersonator or parsing issue")
		}
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

	// Get parsed UA info
	parsedUA := result.RequestInfo.UserAgentParsed

	// ============ Layer 1: User-Agent Analysis ============
	if parsedUA != nil {
		// Check if UA claims to be a bot/library
		if parsedUA.IsBot {
			check.Details = append(check.Details,
				fmt.Sprintf("User-Agent identifies as: %s", parsedUA.BotName))
		}

		// Check 1a: UA Browser vs TLS fingerprint
		tlsClient := strings.ToLower(result.TLSAnalysis.ClientName)
		if parsedUA.Browser != "" && tlsClient != "" {
			uaBrowser := strings.ToLower(parsedUA.Browser)
			if !strings.Contains(tlsClient, uaBrowser) && !strings.Contains(uaBrowser, "edge") {
				// Edge uses Chrome's TLS, so that's expected
				check.Anomalies = append(check.Anomalies,
					fmt.Sprintf("UA claims %s but TLS fingerprint matches %s",
						parsedUA.Browser, result.TLSAnalysis.ClientName))
				check.Score -= 25
			} else {
				check.Details = append(check.Details,
					fmt.Sprintf("UA browser (%s) consistent with TLS fingerprint", parsedUA.Browser))
			}
		}

		// Check 1b: UA Browser vs HTTP/2 fingerprint
		if fp.HTTP2 != nil && result.HTTP2Analysis != nil && parsedUA.Browser != "" {
			http2Client := strings.ToLower(result.HTTP2Analysis.ClientMatch)
			uaBrowser := strings.ToLower(parsedUA.Browser)
			if http2Client != "" && !strings.Contains(http2Client, uaBrowser) {
				// Chrome/Edge share HTTP/2 fingerprint
				if !(strings.Contains(uaBrowser, "edge") && strings.Contains(http2Client, "chrome")) {
					check.Anomalies = append(check.Anomalies,
						fmt.Sprintf("UA claims %s but HTTP/2 fingerprint matches %s",
							parsedUA.Browser, result.HTTP2Analysis.ClientMatch))
					check.Score -= 20
				}
			}
		}
	}

	// ============ Layer 2: TLS vs HTTP/2 Consistency ============
	if fp.HTTP2 != nil && result.HTTP2Analysis != nil {
		tlsClient := strings.ToLower(result.TLSAnalysis.ClientName)
		http2Client := strings.ToLower(result.HTTP2Analysis.ClientMatch)

		if tlsClient != "" && http2Client != "" {
			if !strings.Contains(tlsClient, http2Client) && !strings.Contains(http2Client, tlsClient) {
				check.Anomalies = append(check.Anomalies,
					fmt.Sprintf("TLS fingerprint suggests %s but HTTP/2 suggests %s",
						result.TLSAnalysis.ClientName, result.HTTP2Analysis.ClientMatch))
				check.Score -= 20
			} else {
				check.Details = append(check.Details, "TLS and HTTP/2 fingerprints are consistent")
			}
		}

		// Check for impersonator
		if result.HTTP2Analysis.IsImpersonator {
			check.Anomalies = append(check.Anomalies,
				fmt.Sprintf("HTTP/2 fingerprint indicates impersonator: %s", result.HTTP2Analysis.ImpersonatorType))
			check.Score -= 30
		}
	}

	// ============ Layer 3: TCP/IP vs User-Agent OS ============
	if fp.TCP != nil && parsedUA != nil && parsedUA.OS != "" {
		tcpOS := strings.ToLower(fp.TCP.InferredOS)
		uaOS := strings.ToLower(parsedUA.OS)

		// Strategy: Use InferredOS first (it's more accurate as it combines TTL, Window Size, TCP Options)
		// Fall back to TTL-only check if InferredOS is empty or generic
		osMatches := false
		var mismatchReason string

		if tcpOS != "" && tcpOS != "unknown" {
			// We have a specific OS inference from TCP fingerprint
			switch {
			case strings.Contains(uaOS, "windows"):
				// UA claims Windows - TCP should show Windows
				if strings.Contains(tcpOS, "windows") {
					osMatches = true
				} else {
					mismatchReason = fmt.Sprintf("UA claims Windows but TCP fingerprint suggests %s (TTL=%d, WindowSize=%d)",
						fp.TCP.InferredOS, fp.TCP.TTL, fp.TCP.WindowSize)
				}

			case strings.Contains(uaOS, "mac"):
				// UA claims macOS - TCP should show macOS/iOS, NOT Linux
				if strings.Contains(tcpOS, "mac") || strings.Contains(tcpOS, "ios") {
					osMatches = true
				} else if strings.Contains(tcpOS, "linux") {
					// IMPORTANT: macOS and Linux both have TTL=64, but they differ in Window Size
					// macOS typically uses WindowSize=65535, Linux uses smaller values
					mismatchReason = fmt.Sprintf("UA claims macOS but TCP fingerprint suggests Linux (TTL=%d, WindowSize=%d - macOS typically uses 65535)",
						fp.TCP.TTL, fp.TCP.WindowSize)
				} else if strings.Contains(tcpOS, "windows") {
					mismatchReason = fmt.Sprintf("UA claims macOS but TCP fingerprint suggests Windows (TTL=%d)",
						fp.TCP.TTL)
				}

			case strings.Contains(uaOS, "ios"):
				// UA claims iOS
				if strings.Contains(tcpOS, "mac") || strings.Contains(tcpOS, "ios") {
					osMatches = true
				} else {
					mismatchReason = fmt.Sprintf("UA claims iOS but TCP fingerprint suggests %s (TTL=%d)",
						fp.TCP.InferredOS, fp.TCP.TTL)
				}

			case strings.Contains(uaOS, "linux"):
				// UA claims Linux - TCP should show Linux, not macOS or Windows
				if strings.Contains(tcpOS, "linux") || strings.Contains(tcpOS, "unix") {
					osMatches = true
				} else if strings.Contains(tcpOS, "mac") {
					mismatchReason = fmt.Sprintf("UA claims Linux but TCP fingerprint suggests macOS (TTL=%d, WindowSize=%d)",
						fp.TCP.TTL, fp.TCP.WindowSize)
				} else if strings.Contains(tcpOS, "windows") {
					mismatchReason = fmt.Sprintf("UA claims Linux but TCP fingerprint suggests Windows (TTL=%d)",
						fp.TCP.TTL)
				}

			case strings.Contains(uaOS, "android"):
				// Android typically has same fingerprint as Linux
				if strings.Contains(tcpOS, "linux") || strings.Contains(tcpOS, "android") {
					osMatches = true
				} else {
					mismatchReason = fmt.Sprintf("UA claims Android but TCP fingerprint suggests %s (TTL=%d)",
						fp.TCP.InferredOS, fp.TCP.TTL)
				}
			}
		} else {
			// No specific OS inference, fall back to TTL-only check
			switch {
			case strings.Contains(uaOS, "windows"):
				osMatches = fp.TCP.InitialTTL == 128
				if !osMatches {
					mismatchReason = fmt.Sprintf("UA claims Windows but TTL=%d suggests Unix-like OS (expected TTL~128)",
						fp.TCP.TTL)
				}
			case strings.Contains(uaOS, "mac") || strings.Contains(uaOS, "ios") ||
				strings.Contains(uaOS, "linux") || strings.Contains(uaOS, "android"):
				osMatches = fp.TCP.InitialTTL == 64
				if !osMatches && fp.TCP.InitialTTL == 128 {
					mismatchReason = fmt.Sprintf("UA claims %s but TTL=%d suggests Windows (expected TTL~64)",
						parsedUA.OS, fp.TCP.TTL)
				}
			}
		}

		if !osMatches && mismatchReason != "" {
			check.Anomalies = append(check.Anomalies, mismatchReason)
			check.Score -= 35
		} else if tcpOS != "" {
			check.Details = append(check.Details,
				fmt.Sprintf("UA OS (%s) consistent with TCP fingerprint (%s, TTL=%d, WindowSize=%d)",
					parsedUA.OS, fp.TCP.InferredOS, fp.TCP.TTL, fp.TCP.WindowSize))
		}
	}

	// ============ Layer 4: TCP Timestamp / Uptime Analysis ============
	if fp.TCP != nil && fp.TCP.Timestamp != nil {
		// Very short uptime might indicate container/VM/bot
		if fp.TCP.Timestamp.Uptime != "" {
			check.Details = append(check.Details,
				fmt.Sprintf("System uptime estimated from TCP timestamp: %s", fp.TCP.Timestamp.Uptime))
		}
	}

	// ============ Layer 5: TCP anomalies from collector ============
	if fp.TCP != nil && len(fp.TCP.Anomalies) > 0 {
		for _, a := range fp.TCP.Anomalies {
			check.Anomalies = append(check.Anomalies, a)
			check.Score -= 10
		}
	}

	// ============ Layer 6: TLS Client Type vs UA ============
	if result.TLSAnalysis.ClientType == "Library" && parsedUA != nil && !parsedUA.IsBot {
		if parsedUA.Browser != "" {
			check.Anomalies = append(check.Anomalies,
				fmt.Sprintf("UA claims to be %s browser but TLS fingerprint indicates HTTP library",
					parsedUA.Browser))
			check.Score -= 25
		}
	}

	// ============ Layer 7: Platform consistency ============
	if parsedUA != nil && parsedUA.Platform == "Mobile" && fp.TCP != nil {
		// Mobile devices typically have specific TCP characteristics
		// Windows TTL (128) with mobile UA is suspicious
		if fp.TCP.InitialTTL == 128 {
			check.Anomalies = append(check.Anomalies,
				"UA claims mobile device but TCP TTL (128) indicates Windows desktop")
			check.Score -= 20
		}
	}

	// Ensure score doesn't go below 0
	if check.Score < 0 {
		check.Score = 0
	}

	check.Passed = len(check.Anomalies) == 0

	if check.Passed {
		check.Details = append(check.Details, "✓ All cross-layer consistency checks passed")
	} else {
		check.Details = append(check.Details,
			fmt.Sprintf("✗ Found %d inconsistencies across network layers", len(check.Anomalies)))
	}
}

func generateSummary(result *AnalysisResult, userAgent string) {
	summary := result.Summary
	parsedUA := result.RequestInfo.UserAgentParsed

	// Determine detected client
	if result.HTTP2Analysis != nil && result.HTTP2Analysis.IsImpersonator {
		// Impersonator detected - override client name
		summary.DetectedClient = fmt.Sprintf("Impersonator (%s)", result.HTTP2Analysis.ImpersonatorType)
	} else if result.TLSAnalysis.ClientName != "" {
		summary.DetectedClient = result.TLSAnalysis.ClientName
	} else if parsedUA != nil && parsedUA.Browser != "" {
		summary.DetectedClient = fmt.Sprintf("%s (from UA, TLS unknown)", parsedUA.Browser)
	} else {
		summary.DetectedClient = "Unknown"
	}

	// Determine detected OS - prefer TCP fingerprint over UA
	if result.TCPAnalysis != nil && result.TCPAnalysis.InferredOS != "" {
		summary.DetectedOS = result.TCPAnalysis.InferredOS
		// Add confidence indicator
		if result.TCPAnalysis.OSConfidence == "high" {
			summary.DetectedOS += " (TCP high confidence)"
		}
	} else if parsedUA != nil && parsedUA.OS != "" {
		summary.DetectedOS = parsedUA.OS
		if parsedUA.OSVersion != "" {
			summary.DetectedOS += " " + parsedUA.OSVersion
		}
		summary.DetectedOS += " (from UA only)"
	} else {
		summary.DetectedOS = "Unknown"
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

	// Signal 5: User-Agent explicitly identifies as bot/library
	if parsedUA != nil && parsedUA.IsBot {
		botSignals++
	}

	// Signal 6: No User-Agent header at all (very suspicious)
	if userAgent == "" {
		botSignals++
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
	// 基于特征模式检测，而不是 hash 匹配
	browserScore := 0
	libScore := 0

	// 1. Cipher 数量检测
	// 真正的浏览器: 15-50 个 cipher
	// HTTP 库: 通常 5-15 个
	cipherCount := len(tls.Ciphers)
	if cipherCount >= 20 {
		browserScore += 2
	} else if cipherCount >= 15 {
		browserScore += 1
	} else if cipherCount < 10 {
		libScore += 2
	} else {
		libScore += 1
	}

	// 2. Extension 数量检测
	// 真正的浏览器: 12-20 个 extension
	// HTTP 库: 通常 5-10 个
	extCount := len(tls.Extensions)
	if extCount >= 12 {
		browserScore += 2
	} else if extCount >= 8 {
		browserScore += 1
	} else if extCount < 6 {
		libScore += 2
	} else {
		libScore += 1
	}

	// 3. GREASE 检测 (Chrome/Edge 特有)
	// GREASE 值: 0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a, 0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa
	hasGREASE := false
	for _, ext := range tls.ExtensionsHex {
		// GREASE extensions 都是 0x?a?a 格式
		if len(ext) >= 4 {
			extLower := strings.ToLower(ext)
			if strings.HasSuffix(extLower, "a0a") || strings.Contains(extLower, "0a0a") ||
			   strings.Contains(extLower, "1a1a") || strings.Contains(extLower, "2a2a") ||
			   strings.Contains(extLower, "3a3a") || strings.Contains(extLower, "4a4a") {
				hasGREASE = true
				break
			}
		}
	}
	// 也检查 cipher 中的 GREASE
	for _, cipher := range tls.CiphersHex {
		cipherLower := strings.ToLower(cipher)
		if strings.Contains(cipherLower, "0a0a") || strings.Contains(cipherLower, "1a1a") ||
		   strings.Contains(cipherLower, "2a2a") || strings.Contains(cipherLower, "3a3a") {
			hasGREASE = true
			break
		}
	}
	if hasGREASE {
		browserScore += 3 // GREASE 是强浏览器信号
	} else {
		libScore += 1
	}

	// 4. ALPN 检测
	hasH2 := false
	hasHTTP11 := false
	for _, alpn := range tls.ALPN {
		if alpn == "h2" {
			hasH2 = true
		}
		if alpn == "http/1.1" {
			hasHTTP11 = true
		}
	}
	if hasH2 && hasHTTP11 {
		browserScore += 2 // 浏览器通常同时支持 h2 和 http/1.1
	} else if hasH2 {
		browserScore += 1
	} else if len(tls.ALPN) == 0 {
		libScore += 2 // 无 ALPN 是库的强信号
	} else {
		libScore += 1
	}

	// 5. SNI 检测
	if tls.SNI != "" {
		browserScore += 1
	} else {
		libScore += 2 // 无 SNI 是库的强信号
	}

	// 6. 特定扩展检测
	// 浏览器特有扩展: ECH, signed_certificate_timestamp, application_settings
	hasBrowserOnlyExt := false
	for _, ext := range tls.Extensions {
		// 检查浏览器特有的扩展
		if strings.Contains(ext.Name, "encrypted_client_hello") ||
		   strings.Contains(ext.Name, "application_settings") ||
		   strings.Contains(ext.Name, "compress_certificate") {
			hasBrowserOnlyExt = true
			break
		}
	}
	if hasBrowserOnlyExt {
		browserScore += 2
	}

	// 7. TLS 1.3 支持版本检测
	// 库可能只支持 TLS 1.3/1.2，浏览器通常也支持 1.1/1.0（向后兼容）
	supportedVersionCount := len(tls.SupportedVersions)
	if supportedVersionCount >= 4 {
		browserScore += 1
	} else if supportedVersionCount <= 2 {
		libScore += 1
	}

	// 8. Signature Algorithms 数量
	sigAlgCount := len(tls.SignatureAlgorithms)
	if sigAlgCount >= 10 {
		browserScore += 1
	} else if sigAlgCount < 5 {
		libScore += 1
	}

	// 检查 UA 中是否明确标识为库
	knownLibs := []string{"python", "curl", "go-http", "node", "java", "urllib", "axios", "requests", "httpx", "aiohttp", "scrapy"}
	if ua := strings.ToLower(userAgent); ua != "" {
		for _, lib := range knownLibs {
			if strings.Contains(ua, lib) {
				return "Library"
			}
		}
	}

	// 最终判断
	if browserScore >= libScore+3 {
		return "Browser"
	} else if libScore >= browserScore+2 {
		return "Library"
	} else if libScore > browserScore {
		return "Library (likely)"
	} else if browserScore > libScore {
		return "Browser (likely)"
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

// BuildSimpleResult 构建简化的 API 响应
func BuildSimpleResult(result *AnalysisResult, includeDetails bool) *SimpleAnalysisResult {
	simple := &SimpleAnalysisResult{
		RiskScore:  result.ConsistencyCheck.Score,
		RiskLevel:  result.Summary.RiskLevel,
		IsBot:      result.Summary.IsBot,
		IsSpoofed:  result.Summary.IsSpoofed,
		Anomalies:  result.ConsistencyCheck.Anomalies,
	}

	// 构建 Client 信息
	simple.Client = buildClientInfo(result)

	// 构建 Fingerprints 摘要
	simple.Fingerprints = buildFingerprintSummary(result)

	// 如果需要完整数据
	if includeDetails {
		simple.Details = result
	}

	return simple
}

func buildClientInfo(result *AnalysisResult) ClientInfo {
	info := ClientInfo{}

	// 确定客户端类型
	if result.HTTP2Analysis != nil && result.HTTP2Analysis.IsImpersonator {
		info.Type = "impersonator"
	} else if result.Summary.IsBot {
		info.Type = "bot"
	} else if strings.Contains(result.TLSAnalysis.ClientType, "Library") {
		info.Type = "library"
	} else if strings.Contains(result.TLSAnalysis.ClientType, "Browser") {
		info.Type = "browser"
	} else {
		info.Type = "unknown"
	}

	// UA 声称的
	if result.RequestInfo.UserAgentParsed != nil {
		ua := result.RequestInfo.UserAgentParsed
		if ua.Browser != "" {
			info.Claimed = ua.Browser
			if ua.BrowserVersion != "" {
				info.Claimed += " " + ua.BrowserVersion
			}
		}
		if ua.OS != "" {
			if info.Claimed != "" {
				info.Claimed += " on "
			}
			info.Claimed += ua.OS
			if ua.OSVersion != "" {
				info.Claimed += " " + ua.OSVersion
			}
		}
		if ua.IsBot && ua.BotName != "" {
			info.Claimed = ua.BotName
		}
	}
	if info.Claimed == "" {
		info.Claimed = "Unknown"
	}

	// 实际检测到的
	detected := ""
	if result.HTTP2Analysis != nil && result.HTTP2Analysis.IsImpersonator {
		detected = result.HTTP2Analysis.ImpersonatorType
	} else if result.TLSAnalysis.ClientName != "" {
		detected = result.TLSAnalysis.ClientName
	} else {
		// 没有精确匹配时，使用基于特征模式检测的类型
		clientType := result.TLSAnalysis.ClientType
		if strings.Contains(clientType, "Library") {
			detected = "HTTP Library (TLS pattern)"
		} else if strings.Contains(clientType, "Browser") {
			detected = "Browser (TLS pattern)"
		}
	}

	// 检测到的 OS
	detectedOS := ""
	if result.TCPAnalysis != nil && result.TCPAnalysis.InferredOS != "" {
		detectedOS = result.TCPAnalysis.InferredOS
	}

	if detected != "" && detectedOS != "" {
		info.Detected = detected + " on " + detectedOS
	} else if detected != "" {
		info.Detected = detected
	} else if detectedOS != "" {
		info.Detected = "Unknown client on " + detectedOS
	} else {
		info.Detected = "Unknown"
	}

	// 判断是否匹配
	info.Match = len(result.ConsistencyCheck.Anomalies) == 0 && !result.Summary.IsSpoofed

	return info
}

func buildFingerprintSummary(result *AnalysisResult) FingerprintSummary {
	fp := FingerprintSummary{}

	if result.RawFingerprint.TLS != nil {
		fp.JA3 = result.RawFingerprint.TLS.JA3Hash
		fp.JA4 = result.RawFingerprint.TLS.JA4
	}

	if result.RawFingerprint.HTTP2 != nil {
		fp.HTTP2 = result.RawFingerprint.HTTP2.AkamaiHash
	}

	if result.RawFingerprint.TCP != nil {
		tcp := result.RawFingerprint.TCP
		// 格式: TTL:WindowSize:Options
		fp.TCP = fmt.Sprintf("%d:%d:%s", tcp.InitialTTL, tcp.WindowSize, tcp.OptionsStr)
		fp.TCPOS = tcp.InferredOS
	}

	return fp
}
