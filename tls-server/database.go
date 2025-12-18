package main

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// FingerprintDatabase holds all loaded fingerprint data
type FingerprintDatabase struct {
	JA3  *JA3Database  `json:"ja3"`
	JA4  *JA4Database  `json:"ja4"`
	HTTP2 *HTTP2Database `json:"http2"`
	mu   sync.RWMutex
}

// JA3Database holds JA3 fingerprint mappings
type JA3Database struct {
	Description string                          `json:"description"`
	Sources     []string                        `json:"sources"`
	LastUpdated string                          `json:"last_updated"`
	Fingerprints struct {
		Browsers  map[string]JA3Entry `json:"browsers"`
		Libraries map[string]JA3Entry `json:"libraries"`
		Bots      map[string]JA3Entry `json:"bots"`
		Malware   map[string]JA3Entry `json:"malware"`
		Mobile    map[string]JA3Entry `json:"mobile"`
		Apps      map[string]JA3Entry `json:"apps"`
	} `json:"fingerprints"`
}

// JA3Entry represents a single JA3 fingerprint entry
type JA3Entry struct {
	Name        string `json:"name"`
	Platform    string `json:"platform,omitempty"`
	Version     string `json:"version,omitempty"`
	Language    string `json:"language,omitempty"`
	Type        string `json:"type,omitempty"`
	SampleCount int    `json:"sample_count,omitempty"`
}

// HTTP2Database holds HTTP/2 fingerprint mappings
type HTTP2Database struct {
	Description  string                           `json:"description"`
	Sources      []string                         `json:"sources"`
	LastUpdated  string                           `json:"last_updated"`
	Format       string                           `json:"format"`
	Fingerprints struct {
		Browsers     map[string]HTTP2Entry `json:"browsers"`
		Impersonators map[string]HTTP2Entry `json:"impersonators"`
		Libraries    map[string]HTTP2Entry `json:"libraries"`
	} `json:"fingerprints"`
	DetectionRules struct {
		ImpersonatorSignals []struct {
			Rule        string `json:"rule"`
			Description string `json:"description"`
			Weight      int    `json:"weight"`
			AppliesTo   string `json:"applies_to"`
		} `json:"impersonator_signals"`
		BrowserSignatures map[string]struct {
			WindowUpdate      int    `json:"window_update"`
			PseudoHeaderOrder string `json:"pseudo_header_order"`
			InitialWindowSize int    `json:"initial_window_size,omitempty"`
			HasPriority       bool   `json:"has_priority,omitempty"`
		} `json:"browser_signatures"`
	} `json:"detection_rules"`
}

// HTTP2Entry represents a single HTTP/2 fingerprint entry
type HTTP2Entry struct {
	Name       string `json:"name"`
	Version    string `json:"version,omitempty"`
	Platform   string `json:"platform,omitempty"`
	Notes      string `json:"notes,omitempty"`
	Detection  string `json:"detection,omitempty"`
	Confidence string `json:"confidence,omitempty"`
}

// JA4Database holds JA4 fingerprint mappings
type JA4Database struct {
	Description string   `json:"description"`
	Sources     []string `json:"sources"`
	LastUpdated string   `json:"last_updated"`
	Prefixes    map[string]struct {
		Description string `json:"description"`
		ClientType  string `json:"client_type"`
		Risk        string `json:"risk"`
	} `json:"prefixes"`
	KnownFingerprints map[string]struct {
		Pattern string   `json:"pattern"`
		Clients []string `json:"clients"`
		Notes   string   `json:"notes"`
	} `json:"known_fingerprints"`
	AnalysisRules struct {
		ALPNIndicators     map[string]string `json:"alpn_indicators"`
		CipherCountRanges  map[string]struct {
			Min           int    `json:"min"`
			Max           int    `json:"max"`
			TypicalClient string `json:"typical_client"`
		} `json:"cipher_count_ranges"`
		ExtensionCountRanges map[string]struct {
			Min           int    `json:"min"`
			Max           int    `json:"max"`
			TypicalClient string `json:"typical_client"`
		} `json:"extension_count_ranges"`
	} `json:"analysis_rules"`
}

// Global database instance
var fpDatabase *FingerprintDatabase
var dbOnce sync.Once

// GetDatabase returns the global fingerprint database instance
func GetDatabase() *FingerprintDatabase {
	dbOnce.Do(func() {
		fpDatabase = &FingerprintDatabase{}
		fpDatabase.Load()
	})
	return fpDatabase
}

// Load loads all fingerprint databases from JSON files
func (db *FingerprintDatabase) Load() error {
	db.mu.Lock()
	defer db.mu.Unlock()

	// Find the data directory
	dataDir := findDataDir()

	// Load JA3 database
	ja3Path := filepath.Join(dataDir, "ja3_fingerprints.json")
	if data, err := os.ReadFile(ja3Path); err == nil {
		var ja3DB JA3Database
		if err := json.Unmarshal(data, &ja3DB); err == nil {
			db.JA3 = &ja3DB
			log.Printf("[DB] Loaded JA3 database: %d browsers, %d libraries, %d malware",
				len(ja3DB.Fingerprints.Browsers),
				len(ja3DB.Fingerprints.Libraries),
				len(ja3DB.Fingerprints.Malware))
		} else {
			log.Printf("[DB] Failed to parse JA3 database: %v", err)
		}
	} else {
		log.Printf("[DB] JA3 database not found: %s", ja3Path)
	}

	// Load HTTP/2 database
	http2Path := filepath.Join(dataDir, "http2_fingerprints.json")
	if data, err := os.ReadFile(http2Path); err == nil {
		var http2DB HTTP2Database
		if err := json.Unmarshal(data, &http2DB); err == nil {
			db.HTTP2 = &http2DB
			log.Printf("[DB] Loaded HTTP/2 database: %d browsers, %d impersonators, %d libraries",
				len(http2DB.Fingerprints.Browsers),
				len(http2DB.Fingerprints.Impersonators),
				len(http2DB.Fingerprints.Libraries))
		} else {
			log.Printf("[DB] Failed to parse HTTP/2 database: %v", err)
		}
	} else {
		log.Printf("[DB] HTTP/2 database not found: %s", http2Path)
	}

	// Load JA4 database
	ja4Path := filepath.Join(dataDir, "ja4_fingerprints.json")
	if data, err := os.ReadFile(ja4Path); err == nil {
		var ja4DB JA4Database
		if err := json.Unmarshal(data, &ja4DB); err == nil {
			db.JA4 = &ja4DB
			log.Printf("[DB] Loaded JA4 database: %d prefixes, %d known fingerprints",
				len(ja4DB.Prefixes),
				len(ja4DB.KnownFingerprints))
		} else {
			log.Printf("[DB] Failed to parse JA4 database: %v", err)
		}
	} else {
		log.Printf("[DB] JA4 database not found: %s", ja4Path)
	}

	return nil
}

// findDataDir locates the data directory
func findDataDir() string {
	// Try relative to executable
	if exe, err := os.Executable(); err == nil {
		dataDir := filepath.Join(filepath.Dir(exe), "data")
		if _, err := os.Stat(dataDir); err == nil {
			return dataDir
		}
	}

	// Try current working directory
	if cwd, err := os.Getwd(); err == nil {
		dataDir := filepath.Join(cwd, "data")
		if _, err := os.Stat(dataDir); err == nil {
			return dataDir
		}
	}

	// Try common locations
	locations := []string{
		"./data",
		"../data",
		"./tls-server/data",
	}
	for _, loc := range locations {
		if _, err := os.Stat(loc); err == nil {
			return loc
		}
	}

	return "./data"
}

// LookupJA3 looks up a JA3 hash in the database
func (db *FingerprintDatabase) LookupJA3(hash string) (string, string, bool) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	if db.JA3 == nil {
		return "", "", false
	}

	// Check browsers
	if entry, ok := db.JA3.Fingerprints.Browsers[hash]; ok {
		name := entry.Name
		if entry.Platform != "" {
			name += " (" + entry.Platform + ")"
		}
		if entry.Version != "" {
			name += " " + entry.Version
		}
		return name, "browser", true
	}

	// Check libraries
	if entry, ok := db.JA3.Fingerprints.Libraries[hash]; ok {
		return entry.Name, "library", true
	}

	// Check bots
	if entry, ok := db.JA3.Fingerprints.Bots[hash]; ok {
		return entry.Name, "bot", true
	}

	// Check malware
	if entry, ok := db.JA3.Fingerprints.Malware[hash]; ok {
		return entry.Name + " (Malware)", "malware", true
	}

	// Check mobile
	if entry, ok := db.JA3.Fingerprints.Mobile[hash]; ok {
		return entry.Name, "mobile", true
	}

	// Check apps
	if entry, ok := db.JA3.Fingerprints.Apps[hash]; ok {
		return entry.Name, "app", true
	}

	return "", "", false
}

// LookupHTTP2 looks up an HTTP/2 fingerprint in the database
func (db *FingerprintDatabase) LookupHTTP2(akamai string) (string, bool, string) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	if db.HTTP2 == nil {
		return "", false, ""
	}

	// Check browsers
	if entry, ok := db.HTTP2.Fingerprints.Browsers[akamai]; ok {
		name := entry.Name
		if entry.Version != "" {
			name += " " + entry.Version
		}
		return name, false, ""
	}

	// Check impersonators
	if entry, ok := db.HTTP2.Fingerprints.Impersonators[akamai]; ok {
		return entry.Name, true, entry.Detection
	}

	// Check libraries
	if entry, ok := db.HTTP2.Fingerprints.Libraries[akamai]; ok {
		return entry.Name, false, ""
	}

	return "", false, ""
}

// GetJA4Description returns description for a JA4 prefix
func (db *FingerprintDatabase) GetJA4Description(ja4 string) (string, string, string) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	if db.JA4 == nil || len(ja4) < 4 {
		return "", "", ""
	}

	prefix := ja4[:4]
	if entry, ok := db.JA4.Prefixes[prefix]; ok {
		return entry.Description, entry.ClientType, entry.Risk
	}

	return "", "", ""
}

// IsImpersonatorByHTTP2Rules checks HTTP/2 fingerprint against detection rules
// 核心逻辑: SETTINGS + pseudo_header_order + WINDOW_UPDATE 必须来自同一个浏览器
// 参考: https://lwthiker.com/networks/2022/06/17/http2-fingerprinting.html
// 参考: Akamai Black Hat EU 2017 白皮书
func (db *FingerprintDatabase) IsImpersonatorByHTTP2Rules(akamai string, pseudoOrder string) (bool, []string) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	var reasons []string
	signals := 0

	if db.HTTP2 == nil {
		return false, reasons
	}

	// 解析 Akamai 指纹: SETTINGS|WINDOW_UPDATE|PRIORITY|pseudo_header_order
	parts := strings.Split(akamai, "|")
	if len(parts) < 4 {
		return false, reasons
	}

	settingsPart := parts[0]
	windowUpdate := parts[1]
	// priority := parts[2]  // 暂不使用
	akamaiPseudo := parts[3]

	if pseudoOrder == "" {
		pseudoOrder = akamaiPseudo
	}

	// ========== 浏览器特征定义 ==========
	// Chrome: SETTINGS=1:65536;2:0;4:6291456;6:262144, WU=15663105, pseudo=m,a,s,p
	// Firefox: SETTINGS=1:65536;4:131072;5:16384, WU=12517377, pseudo=m,p,a,s
	// Safari: SETTINGS=2:0;3:100;4:2097152;9:1, WU=10420225, pseudo=m,s,a 或 m,s,p,a
	// curl-impersonate: 复制 Chrome SETTINGS, 但 pseudo 可能是 m,a,s (缺少 p)

	// 检测 Chrome-like SETTINGS
	isChromeLikeSettings := strings.Contains(settingsPart, "4:6291456") && strings.Contains(settingsPart, "6:262144")
	isChromeLikeWU := windowUpdate == "15663105"

	// 检测 Safari-like SETTINGS
	isSafariLikeSettings := strings.HasPrefix(settingsPart, "2:0") && strings.Contains(settingsPart, "9:1")
	isSafariLikeWU := windowUpdate == "10420225"

	// 检测 Firefox-like SETTINGS
	isFirefoxLikeSettings := strings.Contains(settingsPart, "4:131072") && strings.Contains(settingsPart, "5:16384")
	isFirefoxLikeWU := windowUpdate == "12517377"

	// ========== 组合检测 ==========

	// 情况1: Chrome SETTINGS + Chrome WU，但 pseudo 不是 m,a,s,p
	if isChromeLikeSettings && isChromeLikeWU {
		if pseudoOrder != "" && pseudoOrder != "m,a,s,p" {
			signals += 3
			reasons = append(reasons,
				"Chrome SETTINGS+WU but pseudo_header_order='"+pseudoOrder+"' (expected 'm,a,s,p') - likely curl-impersonate")
		}
	}

	// 情况2: Chrome SETTINGS，但 WU 不匹配
	if isChromeLikeSettings && !isChromeLikeWU && windowUpdate != "0" {
		signals += 1
		reasons = append(reasons,
			"Chrome-like SETTINGS but WINDOW_UPDATE="+windowUpdate+" (Chrome uses 15663105)")
	}

	// 情况3: Safari SETTINGS + Safari WU，但 pseudo 不对
	if isSafariLikeSettings && isSafariLikeWU {
		if pseudoOrder != "" && pseudoOrder != "m,s,a" && pseudoOrder != "m,s,p,a" {
			signals += 3
			reasons = append(reasons,
				"Safari SETTINGS+WU but pseudo_header_order='"+pseudoOrder+"' (expected 'm,s,a' or 'm,s,p,a')")
		}
	}

	// 情况4: Firefox SETTINGS + Firefox WU，但 pseudo 不是 m,p,a,s
	if isFirefoxLikeSettings && isFirefoxLikeWU {
		if pseudoOrder != "" && pseudoOrder != "m,p,a,s" {
			signals += 3
			reasons = append(reasons,
				"Firefox SETTINGS+WU but pseudo_header_order='"+pseudoOrder+"' (expected 'm,p,a,s')")
		}
	}

	// 情况5: curl-impersonate 的典型特征
	// Chrome SETTINGS + pseudo=m,a,s (缺少 :path)
	if isChromeLikeSettings && pseudoOrder == "m,a,s" {
		signals += 2
		reasons = append(reasons, "curl-impersonate signature: Chrome SETTINGS with pseudo='m,a,s' (missing ':path')")
	}

	// 情况6: 混合特征 - SETTINGS 和 WU 来自不同浏览器
	if isChromeLikeSettings && isSafariLikeWU {
		signals += 2
		reasons = append(reasons, "Mixed fingerprint: Chrome SETTINGS with Safari WINDOW_UPDATE")
	}
	if isSafariLikeSettings && isChromeLikeWU {
		signals += 2
		reasons = append(reasons, "Mixed fingerprint: Safari SETTINGS with Chrome WINDOW_UPDATE")
	}

	return signals >= 3, reasons
}

// GetBrowserSignature returns expected signature for a browser
func (db *FingerprintDatabase) GetBrowserSignature(browser string) (windowUpdate int, pseudoOrder string, found bool) {
	db.mu.RLock()
	defer db.mu.RUnlock()

	if db.HTTP2 == nil {
		return 0, "", false
	}

	browser = strings.ToLower(browser)
	if sig, ok := db.HTTP2.DetectionRules.BrowserSignatures[browser]; ok {
		return sig.WindowUpdate, sig.PseudoHeaderOrder, true
	}

	return 0, "", false
}
