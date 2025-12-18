package main

import (
	"crypto/md5"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/http2/hpack"
)

// TLS Extension names
var extensionNames = map[uint16]string{
	0:     "server_name",
	1:     "max_fragment_length",
	5:     "status_request",
	10:    "supported_groups",
	11:    "ec_point_formats",
	13:    "signature_algorithms",
	14:    "use_srtp",
	15:    "heartbeat",
	16:    "application_layer_protocol_negotiation",
	17:    "signed_certificate_timestamp",
	18:    "client_certificate_type",
	19:    "server_certificate_type",
	20:    "padding",
	21:    "encrypt_then_mac",
	22:    "extended_master_secret",
	23:    "extended_master_secret",
	27:    "compress_certificate",
	28:    "record_size_limit",
	35:    "session_ticket",
	41:    "pre_shared_key",
	42:    "early_data",
	43:    "supported_versions",
	44:    "cookie",
	45:    "psk_key_exchange_modes",
	47:    "certificate_authorities",
	48:    "oid_filters",
	49:    "post_handshake_auth",
	50:    "signature_algorithms_cert",
	51:    "key_share",
	17513: "application_settings",
	65037: "encrypted_client_hello",
	65281: "renegotiation_info",
}

// Cipher suite names
var cipherNames = map[uint16]string{
	0x1301: "TLS_AES_128_GCM_SHA256",
	0x1302: "TLS_AES_256_GCM_SHA384",
	0x1303: "TLS_CHACHA20_POLY1305_SHA256",
	0xc02b: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
	0xc02f: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
	0xc02c: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
	0xc030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
	0xcca9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
	0xcca8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
	0xc013: "TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
	0xc014: "TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
	0x009c: "TLS_RSA_WITH_AES_128_GCM_SHA256",
	0x009d: "TLS_RSA_WITH_AES_256_GCM_SHA384",
	0x002f: "TLS_RSA_WITH_AES_128_CBC_SHA",
	0x0035: "TLS_RSA_WITH_AES_256_CBC_SHA",
}

// Supported groups names
var groupNames = map[uint16]string{
	23:   "secp256r1",
	24:   "secp384r1",
	25:   "secp521r1",
	29:   "x25519",
	30:   "x448",
	256:  "ffdhe2048",
	257:  "ffdhe3072",
	258:  "ffdhe4096",
	4588: "X25519MLKEM768",
}

// Signature algorithms
var sigAlgNames = map[uint16]string{
	0x0401: "rsa_pkcs1_sha256",
	0x0501: "rsa_pkcs1_sha384",
	0x0601: "rsa_pkcs1_sha512",
	0x0403: "ecdsa_secp256r1_sha256",
	0x0503: "ecdsa_secp384r1_sha384",
	0x0603: "ecdsa_secp521r1_sha512",
	0x0804: "rsa_pss_rsae_sha256",
	0x0805: "rsa_pss_rsae_sha384",
	0x0806: "rsa_pss_rsae_sha512",
	0x0807: "ed25519",
	0x0808: "ed448",
}

// Complete TLS Fingerprint
type TLSFingerprint struct {
	// JA3
	JA3     string `json:"ja3"`
	JA3Hash string `json:"ja3_hash"`

	// JA4
	JA4  string `json:"ja4"`
	JA4R string `json:"ja4_r,omitempty"`

	// Raw data
	TLSVersionRecord     string   `json:"tls_version_record"`
	TLSVersionNegotiated string   `json:"tls_version_negotiated,omitempty"`
	ClientRandom         string   `json:"client_random"`
	SessionID            string   `json:"session_id"`
	Ciphers              []string `json:"ciphers"`
	CiphersHex           []string `json:"ciphers_hex"`
	Extensions           []ExtensionInfo `json:"extensions"`
	ExtensionsHex        []string `json:"extensions_hex"`
	SupportedGroups      []string `json:"supported_groups"`
	ECPointFormats       []string `json:"ec_point_formats"`
	SignatureAlgorithms  []string `json:"signature_algorithms"`
	ALPN                 []string `json:"alpn"`
	SupportedVersions    []string `json:"supported_versions"`
	SNI                  string   `json:"sni"`
	CompressMethods      []uint8  `json:"compress_methods"`
}

// CombinedFingerprint holds TLS, HTTP/2, and TCP/IP fingerprints
type CombinedFingerprint struct {
	TLS   *TLSFingerprint   `json:"tls"`
	HTTP2 *HTTP2Fingerprint `json:"http2,omitempty"`
	TCP   *TCPIPFingerprint `json:"tcp,omitempty"`
}

type ExtensionInfo struct {
	Name string      `json:"name"`
	ID   uint16      `json:"id"`
	Data interface{} `json:"data,omitempty"`
}

// Store
var (
	fingerprintStore = make(map[string]*CombinedFingerprint)
	storeMutex       sync.RWMutex
)

func main() {
	// 命令行参数
	port := flag.Int("port", 8443, "服务监听端口")
	certFile := flag.String("cert", "server.crt", "TLS 证书文件路径")
	keyFile := flag.String("key", "server.key", "TLS 私钥文件路径")
	host := flag.String("host", "0.0.0.0", "监听地址")
	iface := flag.String("iface", "", "网络接口名称 (如 en0, eth0)，留空自动检测")
	disableTCP := flag.Bool("disable-tcp", false, "禁用 TCP/IP 指纹采集")
	flag.Parse()

	// Initialize fingerprint database
	log.Println("Loading fingerprint databases...")
	GetDatabase()

	// Load certificate
	cert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
	if err != nil {
		log.Fatalf("Failed to load certificate: %v", err)
	}

	// Start TCP/IP fingerprint capture (requires root/sudo)
	if !*disableTCP {
		if err := StartTCPCapture(*iface, *port); err != nil {
			log.Printf("[WARNING] TCP fingerprint capture disabled: %v", err)
			log.Printf("[WARNING] Run with sudo for TCP/IP fingerprinting, or use -disable-tcp flag")
		} else {
			// Start cleanup goroutine
			CleanupOldFingerprints(30 * time.Minute)
		}
	}

	// Start raw TCP listener to capture ClientHello
	addr := fmt.Sprintf("%s:%d", *host, *port)
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("Failed to listen: %v", err)
	}

	log.Printf("TLS Fingerprint Server starting on https://%s", addr)
	log.Printf("访问 https://%s/api/fingerprint 获取 TLS 指纹", addr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("Accept error: %v", err)
			continue
		}
		go handleConnection(conn, &cert)
	}
}

func handleConnection(conn net.Conn, cert *tls.Certificate) {
	defer conn.Close()

	// Set read deadline
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))

	// Read ClientHello - 需要读取完整数据，Chrome的ClientHello可能很大
	buf := make([]byte, 16384)
	n, err := conn.Read(buf)
	if err != nil {
		log.Printf("Read error: %v", err)
		return
	}

	clientHelloData := buf[:n]
	remoteAddr := conn.RemoteAddr().String()

	// Parse ClientHello for TLS fingerprint
	tlsFp, err := parseClientHello(clientHelloData)
	if err != nil {
		log.Printf("Parse ClientHello error: %v", err)
		return
	}

	// Get client IP for TCP fingerprint lookup
	clientIP, _, _ := net.SplitHostPort(remoteAddr)

	// Get TCP fingerprint if available
	tcpFp := GetTCPFingerprint(clientIP)

	// Create combined fingerprint
	combined := &CombinedFingerprint{
		TLS: tlsFp,
		TCP: tcpFp,
	}

	log.Printf("TLS ClientHello from %s: JA3=%s, JA4=%s", remoteAddr, tlsFp.JA3Hash, tlsFp.JA4)
	if tcpFp != nil {
		log.Printf("TCP fingerprint for %s: TTL=%d, OS=%s", clientIP, tcpFp.TTL, tcpFp.InferredOS)
	}

	// Create TLS config with HTTP/2 support
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*cert},
		MinVersion:   tls.VersionTLS12,
		MaxVersion:   tls.VersionTLS13,
		NextProtos:   []string{"h2", "http/1.1"}, // Enable HTTP/2
	}

	// Create a wrapper that replays the ClientHello data
	replayConn := &replayConn{
		Conn:       conn,
		replayData: clientHelloData,
	}

	// Upgrade to TLS
	tlsConn := tls.Server(replayConn, tlsConfig)
	tlsConn.SetDeadline(time.Now().Add(30 * time.Second))

	err = tlsConn.Handshake()
	if err != nil {
		log.Printf("TLS handshake error: %v", err)
		return
	}

	// Check negotiated protocol
	negotiatedProto := tlsConn.ConnectionState().NegotiatedProtocol
	isHTTP2 := negotiatedProto == "h2"

	log.Printf("Negotiated protocol: %s (HTTP/2: %v)", negotiatedProto, isHTTP2)

	if isHTTP2 {
		// Handle HTTP/2 connection with fingerprinting
		handleHTTP2(tlsConn, remoteAddr, combined)
	} else {
		// Store fingerprint (HTTP/1.1, no HTTP/2 fingerprint)
		storeMutex.Lock()
		fingerprintStore[remoteAddr] = combined
		host, _, _ := net.SplitHostPort(remoteAddr)
		fingerprintStore[host] = combined
		storeMutex.Unlock()

		// Handle HTTP/1.1
		handleHTTP(tlsConn, remoteAddr)
	}
}

// replayConn wraps a connection and replays initial data
type replayConn struct {
	net.Conn
	replayData []byte
	replayDone bool
}

func (c *replayConn) Read(b []byte) (int, error) {
	if !c.replayDone && len(c.replayData) > 0 {
		n := copy(b, c.replayData)
		c.replayData = c.replayData[n:]
		if len(c.replayData) == 0 {
			c.replayDone = true
		}
		return n, nil
	}
	return c.Conn.Read(b)
}

// handleHTTP2 handles HTTP/2 connections with fingerprint extraction
func handleHTTP2(conn net.Conn, remoteAddr string, combined *CombinedFingerprint) {
	defer conn.Close()

	conn.SetReadDeadline(time.Now().Add(30 * time.Second))

	// Read HTTP/2 connection preface and initial frames
	buf := make([]byte, 32768)
	n, err := conn.Read(buf)
	if err != nil {
		log.Printf("HTTP/2 read error: %v", err)
		return
	}

	data := buf[:n]

	// Verify HTTP/2 preface
	if !IsHTTP2Preface(data) {
		log.Printf("Invalid HTTP/2 preface")
		return
	}

	log.Printf("HTTP/2 connection preface received, %d bytes total", n)

	// Parse HTTP/2 frames after preface (24 bytes)
	frameData := data[len(http2Preface):]
	http2Fp, err := ParseHTTP2Frames(frameData)
	if err != nil {
		log.Printf("HTTP/2 parse error: %v", err)
	} else {
		combined.HTTP2 = http2Fp
		log.Printf("HTTP/2 fingerprint: %s", http2Fp.Akamai)
	}

	// Store combined fingerprint
	storeMutex.Lock()
	fingerprintStore[remoteAddr] = combined
	host, _, _ := net.SplitHostPort(remoteAddr)
	fingerprintStore[host] = combined
	storeMutex.Unlock()

	// Now we need to respond as an HTTP/2 server
	// Send SETTINGS frame (server settings)
	serverSettings := buildServerSettingsFrame()
	conn.Write(serverSettings)

	// Send SETTINGS ACK for client's SETTINGS
	settingsAck := buildSettingsAckFrame()
	conn.Write(settingsAck)

	// Read more data (HEADERS frame with actual request)
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))

	// If we already have HEADERS in the initial data, process it
	// Otherwise, read more - client sends SETTINGS_ACK + HEADERS after receiving our SETTINGS
	headerData := frameData
	if !containsHeadersFrame(frameData) {
		n2, err := conn.Read(buf)
		if err == nil && n2 > 0 {
			headerData = buf[:n2]
		}
	}

	// Find and respond to HEADERS frame
	respondToHTTP2Request(conn, headerData, combined, remoteAddr)
}

// buildServerSettingsFrame creates a SETTINGS frame for server
func buildServerSettingsFrame() []byte {
	// SETTINGS frame with some default values
	// Format: Length(3) + Type(1) + Flags(1) + StreamID(4) + Payload
	settings := []byte{
		// SETTINGS_MAX_CONCURRENT_STREAMS = 100
		0x00, 0x03, 0x00, 0x00, 0x00, 0x64,
		// SETTINGS_INITIAL_WINDOW_SIZE = 65535
		0x00, 0x04, 0x00, 0x00, 0xff, 0xff,
	}

	frame := make([]byte, 9+len(settings))
	// Length (3 bytes)
	frame[0] = byte(len(settings) >> 16)
	frame[1] = byte(len(settings) >> 8)
	frame[2] = byte(len(settings))
	// Type = SETTINGS (0x04)
	frame[3] = 0x04
	// Flags = 0
	frame[4] = 0x00
	// Stream ID = 0 (4 bytes)
	frame[5] = 0x00
	frame[6] = 0x00
	frame[7] = 0x00
	frame[8] = 0x00
	// Payload
	copy(frame[9:], settings)

	return frame
}

// buildSettingsAckFrame creates a SETTINGS ACK frame
func buildSettingsAckFrame() []byte {
	return []byte{
		0x00, 0x00, 0x00, // Length = 0
		0x04,             // Type = SETTINGS
		0x01,             // Flags = ACK
		0x00, 0x00, 0x00, 0x00, // Stream ID = 0
	}
}

// containsHeadersFrame checks if data contains a HEADERS frame
func containsHeadersFrame(data []byte) bool {
	pos := 0
	for pos+9 <= len(data) {
		frameLen := int(data[pos])<<16 | int(data[pos+1])<<8 | int(data[pos+2])
		frameType := data[pos+3]

		if frameType == FrameHeaders {
			return true
		}

		pos += 9 + frameLen
		if pos > len(data) {
			break
		}
	}
	return false
}

// respondToHTTP2Request sends an HTTP/2 response
func respondToHTTP2Request(conn net.Conn, data []byte, combined *CombinedFingerprint, remoteAddr string) {
	// Find the stream ID and path from HEADERS frame
	streamID := uint32(1) // Default to stream 1
	path := "/"
	userAgent := ""

	pos := 0
	for pos+9 <= len(data) {
		frameLen := int(data[pos])<<16 | int(data[pos+1])<<8 | int(data[pos+2])
		frameType := data[pos+3]
		frameFlags := data[pos+4]

		if frameType == FrameHeaders {
			streamID = binary.BigEndian.Uint32(data[pos+5:pos+9]) & 0x7FFFFFFF
			// Try to extract path from HPACK encoded headers
			if pos+9+frameLen <= len(data) {
				headerPayload := data[pos+9 : pos+9+frameLen]

				// Handle PADDED flag (0x08)
				padLen := 0
				payloadOffset := 0
				if frameFlags&0x08 != 0 && len(headerPayload) > 0 {
					padLen = int(headerPayload[0])
					payloadOffset = 1
				}

				// Handle PRIORITY flag (0x20)
				if frameFlags&0x20 != 0 {
					payloadOffset += 5 // Skip stream dependency (4 bytes) + weight (1 byte)
				}

				// Extract actual HPACK data
				if payloadOffset < len(headerPayload)-padLen {
					hpackData := headerPayload[payloadOffset : len(headerPayload)-padLen]
					path, userAgent = extractHTTP2Path(hpackData)
				}
			}
			break
		}

		pos += 9 + frameLen
		if pos > len(data) {
			break
		}
	}

	// Route based on path
	var jsonBody []byte

	if strings.Contains(path, "/api/analysis") {
		// Return analysis (简化格式)
		host, _, _ := net.SplitHostPort(remoteAddr)
		analysis := AnalyzeFingerprint(combined, host, userAgent)
		includeDetails := strings.Contains(path, "details=true")
		simpleResult := BuildSimpleResult(analysis, includeDetails)
		jsonBody, _ = json.MarshalIndent(simpleResult, "", "  ")
	} else {
		// Default: return fingerprint
		response := map[string]interface{}{
			"success":     true,
			"fingerprint": combined,
		}
		jsonBody, _ = json.MarshalIndent(response, "", "  ")
	}

	// Send HEADERS frame with :status 200
	headersFrame := buildHTTP2HeadersFrame(streamID, len(jsonBody))
	conn.Write(headersFrame)

	// Send DATA frame with response body
	dataFrame := buildHTTP2DataFrame(streamID, jsonBody)
	conn.Write(dataFrame)
}

// extractHTTP2Path uses proper HPACK decoding to extract the :path header
func extractHTTP2Path(headerPayload []byte) (string, string) {
	path := "/"
	userAgent := ""

	// Use proper HPACK decoder
	decoder := hpack.NewDecoder(4096, nil)
	headers, err := decoder.DecodeFull(headerPayload)
	if err != nil {
		return path, userAgent
	}

	for _, hf := range headers {
		switch hf.Name {
		case ":path":
			path = hf.Value
		case "user-agent":
			userAgent = hf.Value
		}
	}

	return path, userAgent
}

// buildHTTP2HeadersFrame builds a HEADERS frame with status 200
func buildHTTP2HeadersFrame(streamID uint32, contentLength int) []byte {
	// Simple HPACK encoded headers using indexed and literal representations
	// See RFC 7541 for HPACK specification
	var headers []byte

	// :status 200 - indexed header field (index 8 in static table)
	headers = append(headers, 0x88)

	// content-type: application/json - literal header with incremental indexing
	// Format: 0x40 | index (0 = new name)
	headers = append(headers, 0x40)
	// Header name length (without Huffman)
	headers = append(headers, 0x0c) // 12 = len("content-type")
	headers = append(headers, []byte("content-type")...)
	// Header value length
	headers = append(headers, 0x10) // 16 = len("application/json")
	headers = append(headers, []byte("application/json")...)

	// access-control-allow-origin: * - literal header without indexing
	// Format: 0x00 | 0 (new name)
	headers = append(headers, 0x00)
	headers = append(headers, 0x1b) // 27 = len("access-control-allow-origin")
	headers = append(headers, []byte("access-control-allow-origin")...)
	headers = append(headers, 0x01) // 1 = len("*")
	headers = append(headers, '*')

	frame := make([]byte, 9+len(headers))
	// Length (3 bytes big-endian)
	frame[0] = byte(len(headers) >> 16)
	frame[1] = byte(len(headers) >> 8)
	frame[2] = byte(len(headers))
	// Type = HEADERS (0x01)
	frame[3] = 0x01
	// Flags = END_HEADERS (0x04)
	frame[4] = 0x04
	// Stream ID (4 bytes)
	binary.BigEndian.PutUint32(frame[5:9], streamID)
	// Payload
	copy(frame[9:], headers)

	return frame
}

// buildHTTP2DataFrame builds a DATA frame
func buildHTTP2DataFrame(streamID uint32, body []byte) []byte {
	frame := make([]byte, 9+len(body))
	// Length
	frame[0] = byte(len(body) >> 16)
	frame[1] = byte(len(body) >> 8)
	frame[2] = byte(len(body))
	// Type = DATA
	frame[3] = 0x00
	// Flags = END_STREAM (0x01)
	frame[4] = 0x01
	// Stream ID
	binary.BigEndian.PutUint32(frame[5:9], streamID)
	// Payload
	copy(frame[9:], body)

	return frame
}

func parseClientHello(data []byte) (*TLSFingerprint, error) {
	if len(data) < 5 {
		return nil, fmt.Errorf("data too short")
	}

	// TLS Record Layer
	contentType := data[0]
	if contentType != 22 { // Handshake
		return nil, fmt.Errorf("not a handshake record: %d", contentType)
	}

	recordVersion := binary.BigEndian.Uint16(data[1:3])
	recordLength := binary.BigEndian.Uint16(data[3:5])

	fp := &TLSFingerprint{
		TLSVersionRecord: fmt.Sprintf("%d", recordVersion),
	}

	if len(data) < int(5+recordLength) {
		return nil, fmt.Errorf("incomplete record")
	}

	handshake := data[5 : 5+recordLength]
	if len(handshake) < 4 {
		return nil, fmt.Errorf("handshake too short")
	}

	// Handshake header
	handshakeType := handshake[0]
	if handshakeType != 1 { // ClientHello
		return nil, fmt.Errorf("not a ClientHello: %d", handshakeType)
	}

	handshakeLength := int(handshake[1])<<16 | int(handshake[2])<<8 | int(handshake[3])
	if len(handshake) < 4+handshakeLength {
		return nil, fmt.Errorf("incomplete ClientHello")
	}

	clientHello := handshake[4 : 4+handshakeLength]
	pos := 0

	// Client Version
	if pos+2 > len(clientHello) {
		return nil, fmt.Errorf("missing client version")
	}
	clientVersion := binary.BigEndian.Uint16(clientHello[pos : pos+2])
	pos += 2

	// Client Random
	if pos+32 > len(clientHello) {
		return nil, fmt.Errorf("missing client random")
	}
	fp.ClientRandom = hex.EncodeToString(clientHello[pos : pos+32])
	pos += 32

	// Session ID
	if pos+1 > len(clientHello) {
		return nil, fmt.Errorf("missing session id length")
	}
	sessionIDLen := int(clientHello[pos])
	pos++
	if pos+sessionIDLen > len(clientHello) {
		return nil, fmt.Errorf("incomplete session id")
	}
	fp.SessionID = hex.EncodeToString(clientHello[pos : pos+sessionIDLen])
	pos += sessionIDLen

	// Cipher Suites
	if pos+2 > len(clientHello) {
		return nil, fmt.Errorf("missing cipher suites length")
	}
	cipherSuitesLen := int(binary.BigEndian.Uint16(clientHello[pos : pos+2]))
	pos += 2
	if pos+cipherSuitesLen > len(clientHello) {
		return nil, fmt.Errorf("incomplete cipher suites")
	}

	var cipherSuites []uint16
	var ciphersHex []string
	var ciphersStr []string
	for i := 0; i < cipherSuitesLen; i += 2 {
		cs := binary.BigEndian.Uint16(clientHello[pos+i : pos+i+2])
		// Skip GREASE values
		if !isGREASE(cs) {
			cipherSuites = append(cipherSuites, cs)
		}
		name := getCipherName(cs)
		fp.Ciphers = append(fp.Ciphers, name)
		ciphersHex = append(ciphersHex, fmt.Sprintf("0x%04x", cs))
		ciphersStr = append(ciphersStr, fmt.Sprintf("%d", cs))
	}
	fp.CiphersHex = ciphersHex
	pos += cipherSuitesLen

	// Compression Methods
	if pos+1 > len(clientHello) {
		return nil, fmt.Errorf("missing compression methods length")
	}
	compMethodsLen := int(clientHello[pos])
	pos++
	if pos+compMethodsLen > len(clientHello) {
		return nil, fmt.Errorf("incomplete compression methods")
	}
	for i := 0; i < compMethodsLen; i++ {
		fp.CompressMethods = append(fp.CompressMethods, clientHello[pos+i])
	}
	pos += compMethodsLen

	// Extensions
	var extensions []uint16
	var extensionsStr []string
	var supportedGroups []uint16
	var ecPointFormats []uint8
	var signatureAlgorithms []uint16
	var supportedVersions []uint16

	if pos+2 <= len(clientHello) {
		extensionsLen := int(binary.BigEndian.Uint16(clientHello[pos : pos+2]))
		pos += 2

		extEnd := pos + extensionsLen
		for pos < extEnd && pos+4 <= len(clientHello) {
			extType := binary.BigEndian.Uint16(clientHello[pos : pos+2])
			extLen := int(binary.BigEndian.Uint16(clientHello[pos+2 : pos+4]))
			pos += 4

			if pos+extLen > len(clientHello) {
				break
			}
			extData := clientHello[pos : pos+extLen]

			extInfo := ExtensionInfo{
				ID:   extType,
				Name: getExtensionName(extType),
			}

			// Parse specific extensions
			switch extType {
			case 0: // server_name
				if len(extData) > 5 {
					nameLen := int(binary.BigEndian.Uint16(extData[3:5]))
					if 5+nameLen <= len(extData) {
						fp.SNI = string(extData[5 : 5+nameLen])
						extInfo.Data = fp.SNI
					}
				}
			case 10: // supported_groups
				if len(extData) >= 2 {
					groupsLen := int(binary.BigEndian.Uint16(extData[0:2]))
					for i := 2; i < 2+groupsLen && i+1 < len(extData); i += 2 {
						g := binary.BigEndian.Uint16(extData[i : i+2])
						if !isGREASE(g) {
							supportedGroups = append(supportedGroups, g)
						}
						fp.SupportedGroups = append(fp.SupportedGroups, getGroupName(g))
					}
				}
			case 11: // ec_point_formats
				if len(extData) >= 1 {
					formatsLen := int(extData[0])
					for i := 1; i < 1+formatsLen && i < len(extData); i++ {
						ecPointFormats = append(ecPointFormats, extData[i])
						fp.ECPointFormats = append(fp.ECPointFormats, fmt.Sprintf("0x%02x", extData[i]))
					}
				}
			case 13: // signature_algorithms
				if len(extData) >= 2 {
					algLen := int(binary.BigEndian.Uint16(extData[0:2]))
					for i := 2; i < 2+algLen && i+1 < len(extData); i += 2 {
						alg := binary.BigEndian.Uint16(extData[i : i+2])
						signatureAlgorithms = append(signatureAlgorithms, alg)
						fp.SignatureAlgorithms = append(fp.SignatureAlgorithms, getSigAlgName(alg))
					}
				}
			case 16: // ALPN
				if len(extData) >= 2 {
					alpnLen := int(binary.BigEndian.Uint16(extData[0:2]))
					i := 2
					for i < 2+alpnLen && i < len(extData) {
						protoLen := int(extData[i])
						i++
						if i+protoLen <= len(extData) {
							fp.ALPN = append(fp.ALPN, string(extData[i:i+protoLen]))
							i += protoLen
						}
					}
					extInfo.Data = fp.ALPN
				}
			case 43: // supported_versions
				if len(extData) >= 1 {
					versionsLen := int(extData[0])
					for i := 1; i < 1+versionsLen && i+1 < len(extData); i += 2 {
						v := binary.BigEndian.Uint16(extData[i : i+2])
						if !isGREASE(v) {
							supportedVersions = append(supportedVersions, v)
						}
						fp.SupportedVersions = append(fp.SupportedVersions, getVersionName(v))
					}
				}
			}

			fp.Extensions = append(fp.Extensions, extInfo)
			fp.ExtensionsHex = append(fp.ExtensionsHex, fmt.Sprintf("0x%04x", extType))

			if !isGREASE(extType) {
				extensions = append(extensions, extType)
				extensionsStr = append(extensionsStr, fmt.Sprintf("%d", extType))
			}

			pos += extLen
		}
	}

	// Build JA3: SSLVersion,Ciphers,Extensions,EllipticCurves,EllipticCurvePointFormats
	ja3Parts := []string{
		fmt.Sprintf("%d", clientVersion),
		joinUint16(cipherSuites, "-"),
		joinUint16(extensions, "-"),
		joinUint16(supportedGroups, "-"),
		joinUint8(ecPointFormats, "-"),
	}
	fp.JA3 = strings.Join(ja3Parts, ",")
	hash := md5.Sum([]byte(fp.JA3))
	fp.JA3Hash = hex.EncodeToString(hash[:])

	// Build JA4
	fp.JA4 = buildJA4(clientVersion, supportedVersions, fp.SNI, cipherSuites, extensions, fp.ALPN, signatureAlgorithms)

	// Build JA4_r
	fp.JA4R = buildJA4R(clientVersion, supportedVersions, fp.SNI, cipherSuites, extensions, fp.ALPN, signatureAlgorithms)

	// Set negotiated version
	if len(supportedVersions) > 0 {
		fp.TLSVersionNegotiated = getVersionName(supportedVersions[0])
	}

	return fp, nil
}

func buildJA4(clientVersion uint16, supportedVersions []uint16, sni string, ciphers, extensions []uint16, alpn []string, sigAlgs []uint16) string {
	// Protocol
	proto := "t"

	// Version
	ver := "00"
	if len(supportedVersions) > 0 {
		switch supportedVersions[0] {
		case 0x0304:
			ver = "13"
		case 0x0303:
			ver = "12"
		case 0x0302:
			ver = "11"
		case 0x0301:
			ver = "10"
		}
	} else {
		switch clientVersion {
		case 0x0303:
			ver = "12"
		case 0x0302:
			ver = "11"
		case 0x0301:
			ver = "10"
		}
	}

	// SNI
	sniFlag := "i"
	if sni != "" {
		sniFlag = "d"
	}

	// Cipher count
	cipherCount := fmt.Sprintf("%02d", min(len(ciphers), 99))

	// Extension count
	extCount := fmt.Sprintf("%02d", min(len(extensions), 99))

	// ALPN first
	alpnFirst := "00"
	if len(alpn) > 0 {
		if len(alpn[0]) >= 2 {
			alpnFirst = alpn[0][:2]
		} else {
			alpnFirst = alpn[0]
		}
	}

	// JA4格式: t[ver][sni][cipher_count][ext_count][alpn]_[cipher_hash]_[ext_hash]
	// alpn直接拼接，不需要下划线
	part1 := proto + ver + sniFlag + cipherCount + extCount + alpnFirst

	// Sorted cipher hash
	sortedCiphers := make([]uint16, len(ciphers))
	copy(sortedCiphers, ciphers)
	sort.Slice(sortedCiphers, func(i, j int) bool { return sortedCiphers[i] < sortedCiphers[j] })
	cipherStr := joinUint16Hex(sortedCiphers, ",")
	cipherHash := sha256.Sum256([]byte(cipherStr))
	part2 := hex.EncodeToString(cipherHash[:])[:12]

	// Sorted extension hash (excluding SNI and ALPN)
	var filteredExts []uint16
	for _, e := range extensions {
		if e != 0 && e != 16 { // Exclude SNI and ALPN
			filteredExts = append(filteredExts, e)
		}
	}
	sort.Slice(filteredExts, func(i, j int) bool { return filteredExts[i] < filteredExts[j] })

	// Add signature algorithms to extension hash
	extStr := joinUint16Hex(filteredExts, ",")
	if len(sigAlgs) > 0 {
		extStr += "_" + joinUint16Hex(sigAlgs, ",")
	}
	extHash := sha256.Sum256([]byte(extStr))
	part3 := hex.EncodeToString(extHash[:])[:12]

	return part1 + "_" + part2 + "_" + part3
}

func buildJA4R(clientVersion uint16, supportedVersions []uint16, sni string, ciphers, extensions []uint16, alpn []string, sigAlgs []uint16) string {
	// Same prefix as JA4
	proto := "t"
	ver := "00"
	if len(supportedVersions) > 0 {
		switch supportedVersions[0] {
		case 0x0304:
			ver = "13"
		case 0x0303:
			ver = "12"
		}
	}

	sniFlag := "i"
	if sni != "" {
		sniFlag = "d"
	}

	cipherCount := fmt.Sprintf("%02d", min(len(ciphers), 99))
	extCount := fmt.Sprintf("%02d", min(len(extensions), 99))
	alpnFirst := "00"
	if len(alpn) > 0 && len(alpn[0]) >= 2 {
		alpnFirst = alpn[0][:2]
	}

	// JA4_r格式同JA4，alpn直接拼接
	prefix := proto + ver + sniFlag + cipherCount + extCount + alpnFirst

	// Sorted ciphers in hex
	sortedCiphers := make([]uint16, len(ciphers))
	copy(sortedCiphers, ciphers)
	sort.Slice(sortedCiphers, func(i, j int) bool { return sortedCiphers[i] < sortedCiphers[j] })
	cipherPart := joinUint16Hex(sortedCiphers, ",")

	// Sorted extensions (excluding SNI/ALPN)
	var filteredExts []uint16
	for _, e := range extensions {
		if e != 0 && e != 16 {
			filteredExts = append(filteredExts, e)
		}
	}
	sort.Slice(filteredExts, func(i, j int) bool { return filteredExts[i] < filteredExts[j] })
	extPart := joinUint16Hex(filteredExts, ",")

	// Signature algorithms
	sigPart := joinUint16Hex(sigAlgs, ",")

	return prefix + "_" + cipherPart + "_" + extPart + "_" + sigPart
}

func handleHTTP(conn net.Conn, remoteAddr string) {
	defer conn.Close()

	buf := make([]byte, 8192)
	n, err := conn.Read(buf)
	if err != nil {
		return
	}

	request := string(buf[:n])
	lines := strings.Split(request, "\r\n")
	if len(lines) == 0 {
		return
	}

	parts := strings.Split(lines[0], " ")
	if len(parts) < 2 {
		return
	}

	fullPath := parts[1]
	path := fullPath
	if idx := strings.Index(path, "?"); idx != -1 {
		path = path[:idx] // 去掉查询参数用于路由匹配
	}

	// Extract User-Agent header
	userAgent := ""
	for _, line := range lines {
		if strings.HasPrefix(strings.ToLower(line), "user-agent:") {
			userAgent = strings.TrimSpace(line[11:])
			break
		}
	}

	var response string
	var body []byte

	switch {
	case path == "/" || path == "/index.html":
		body = []byte(`<!DOCTYPE html>
<html>
<head>
    <meta charset="UTF-8">
    <title>TLS Fingerprint Server</title>
    <style>
        body { font-family: -apple-system, sans-serif; max-width: 800px; margin: 50px auto; padding: 20px; background: #f5f5f5; }
        h1 { color: #333; }
        pre { background: #fff; padding: 20px; border-radius: 8px; overflow-x: auto; }
        a { color: #0066cc; }
        .risk-low { color: #16a34a; }
        .risk-medium { color: #ca8a04; }
        .risk-high { color: #dc2626; }
    </style>
</head>
<body>
    <h1>TLS Fingerprint Server</h1>
    <p>Your TLS fingerprint has been captured!</p>
    <p>Visit <a href="/api/fingerprint">/api/fingerprint</a> to see the raw result.</p>
    <h2>API Endpoints:</h2>
    <ul>
        <li><a href="/api/fingerprint">/api/fingerprint</a> - Get your raw TLS/HTTP2/TCP fingerprint</li>
        <li><a href="/api/analysis">/api/analysis</a> - <strong>Get full security analysis with conclusions</strong></li>
        <li><a href="/api/all">/api/all</a> - Get all stored fingerprints</li>
    </ul>
    <h2>Security Analysis</h2>
    <p>The <code>/api/analysis</code> endpoint provides:</p>
    <ul>
        <li>Client identification (Browser/Library/Bot)</li>
        <li>Cross-layer consistency check (TLS vs HTTP/2 vs TCP vs User-Agent)</li>
        <li>Bot/Spoofing detection</li>
        <li>Security advice for defenders and pentesters</li>
    </ul>
</body>
</html>`)
		response = fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: %d\r\nAccess-Control-Allow-Origin: *\r\n\r\n", len(body))

	case path == "/api/analysis":
		storeMutex.RLock()
		host, _, _ := net.SplitHostPort(remoteAddr)
		fp := fingerprintStore[host]
		if fp == nil {
			fp = fingerprintStore[remoteAddr]
		}
		storeMutex.RUnlock()

		// 检查是否需要完整数据 (?details=true)
		includeDetails := strings.Contains(fullPath, "details=true")

		if fp != nil {
			analysis := AnalyzeFingerprint(fp, host, userAgent)
			simpleResult := BuildSimpleResult(analysis, includeDetails)
			body, _ = json.MarshalIndent(simpleResult, "", "  ")
		} else {
			result := map[string]interface{}{
				"risk_score": 0,
				"risk_level": "unknown",
				"is_bot":     false,
				"is_spoofed": false,
				"client":     map[string]interface{}{"type": "unknown", "claimed": "Unknown", "detected": "Unknown", "match": false},
				"error":      "No fingerprint found. Visit this page in a browser first.",
			}
			body, _ = json.MarshalIndent(result, "", "  ")
		}
		response = fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: %d\r\nAccess-Control-Allow-Origin: *\r\n\r\n", len(body))

	case path == "/api/fingerprint":
		storeMutex.RLock()
		host, _, _ := net.SplitHostPort(remoteAddr)
		fp := fingerprintStore[host]
		if fp == nil {
			fp = fingerprintStore[remoteAddr]
		}
		storeMutex.RUnlock()

		var result interface{}
		if fp != nil {
			result = map[string]interface{}{
				"success":     true,
				"client_ip":   host,
				"fingerprint": fp,
			}
		} else {
			result = map[string]interface{}{
				"success": false,
				"error":   "No fingerprint found",
			}
		}
		body, _ = json.MarshalIndent(result, "", "  ")
		response = fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: %d\r\nAccess-Control-Allow-Origin: *\r\n\r\n", len(body))

	case path == "/api/all":
		storeMutex.RLock()
		body, _ = json.MarshalIndent(fingerprintStore, "", "  ")
		storeMutex.RUnlock()
		response = fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: %d\r\nAccess-Control-Allow-Origin: *\r\n\r\n", len(body))

	default:
		body = []byte("Not Found")
		response = fmt.Sprintf("HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\nContent-Length: %d\r\nAccess-Control-Allow-Origin: *\r\n\r\n", len(body))
	}

	conn.Write([]byte(response))
	conn.Write(body)
}

// Helper functions
func isGREASE(val uint16) bool {
	// GREASE values: 0x0a0a, 0x1a1a, 0x2a2a, etc.
	return (val&0x0f0f) == 0x0a0a
}

func getCipherName(cs uint16) string {
	if isGREASE(cs) {
		return fmt.Sprintf("TLS_GREASE (0x%04X)", cs)
	}
	if name, ok := cipherNames[cs]; ok {
		return name
	}
	return fmt.Sprintf("0x%04X", cs)
}

func getExtensionName(ext uint16) string {
	if isGREASE(ext) {
		return fmt.Sprintf("TLS_GREASE (0x%04x)", ext)
	}
	if name, ok := extensionNames[ext]; ok {
		return fmt.Sprintf("%s (%d)", name, ext)
	}
	return fmt.Sprintf("unknown (%d)", ext)
}

func getGroupName(g uint16) string {
	if isGREASE(g) {
		return fmt.Sprintf("TLS_GREASE (0x%04X)", g)
	}
	if name, ok := groupNames[g]; ok {
		return fmt.Sprintf("%s (%d)", name, g)
	}
	return fmt.Sprintf("0x%04X", g)
}

func getSigAlgName(alg uint16) string {
	if name, ok := sigAlgNames[alg]; ok {
		return name
	}
	return fmt.Sprintf("0x%04x", alg)
}

func getVersionName(v uint16) string {
	if isGREASE(v) {
		return fmt.Sprintf("TLS_GREASE (0x%04X)", v)
	}
	switch v {
	case 0x0304:
		return "TLS 1.3"
	case 0x0303:
		return "TLS 1.2"
	case 0x0302:
		return "TLS 1.1"
	case 0x0301:
		return "TLS 1.0"
	default:
		return fmt.Sprintf("0x%04X", v)
	}
}

func joinUint16(arr []uint16, sep string) string {
	if len(arr) == 0 {
		return ""
	}
	strs := make([]string, len(arr))
	for i, v := range arr {
		strs[i] = strconv.Itoa(int(v))
	}
	return strings.Join(strs, sep)
}

func joinUint16Hex(arr []uint16, sep string) string {
	if len(arr) == 0 {
		return ""
	}
	strs := make([]string, len(arr))
	for i, v := range arr {
		strs[i] = fmt.Sprintf("%04x", v)
	}
	return strings.Join(strs, sep)
}

func joinUint8(arr []uint8, sep string) string {
	if len(arr) == 0 {
		return ""
	}
	strs := make([]string, len(arr))
	for i, v := range arr {
		strs[i] = strconv.Itoa(int(v))
	}
	return strings.Join(strs, sep)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
