package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

// HTTP/2 Frame Types
const (
	FrameData         = 0x0
	FrameHeaders      = 0x1
	FramePriority     = 0x2
	FrameRSTStream    = 0x3
	FrameSettings     = 0x4
	FramePushPromise  = 0x5
	FramePing         = 0x6
	FrameGoAway       = 0x7
	FrameWindowUpdate = 0x8
	FrameContinuation = 0x9
)

// HTTP/2 Settings IDs
const (
	SettingsHeaderTableSize      = 0x1
	SettingsEnablePush           = 0x2
	SettingsMaxConcurrentStreams = 0x3
	SettingsInitialWindowSize    = 0x4
	SettingsMaxFrameSize         = 0x5
	SettingsMaxHeaderListSize    = 0x6
)

// HTTP/2 Connection Preface
var http2Preface = []byte("PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")

// HTTP2Fingerprint represents the Akamai-style HTTP/2 fingerprint
type HTTP2Fingerprint struct {
	// Akamai format fingerprint
	Akamai     string `json:"akamai"`
	AkamaiHash string `json:"akamai_hash"`

	// Raw data
	Settings          []SettingParam `json:"settings"`
	WindowUpdate      uint32         `json:"window_update"`
	Priorities        []PriorityInfo `json:"priorities,omitempty"`
	PseudoHeaderOrder string         `json:"pseudo_header_order"`

	// Frame order (for debugging)
	FrameOrder []string `json:"frame_order,omitempty"`
}

// SettingParam represents a single HTTP/2 SETTINGS parameter
type SettingParam struct {
	ID    uint16 `json:"id"`
	Name  string `json:"name"`
	Value uint32 `json:"value"`
}

// PriorityInfo represents HTTP/2 PRIORITY frame data
type PriorityInfo struct {
	StreamID   uint32 `json:"stream_id"`
	Exclusive  uint8  `json:"exclusive"`
	DependsOn  uint32 `json:"depends_on"`
	Weight     uint8  `json:"weight"`
}

// HTTP2Frame represents a parsed HTTP/2 frame
type HTTP2Frame struct {
	Length   uint32
	Type     uint8
	Flags    uint8
	StreamID uint32
	Payload  []byte
}

// ParseHTTP2Frames parses HTTP/2 frames from raw data after the connection preface
func ParseHTTP2Frames(data []byte) (*HTTP2Fingerprint, error) {
	fp := &HTTP2Fingerprint{
		WindowUpdate: 0,
	}

	pos := 0
	frameCount := 0
	maxFrames := 50 // Limit frames to parse

	for pos+9 <= len(data) && frameCount < maxFrames {
		frame, err := parseFrame(data[pos:])
		if err != nil {
			break
		}

		frameLen := 9 + int(frame.Length)
		if pos+frameLen > len(data) {
			break
		}

		fp.FrameOrder = append(fp.FrameOrder, getFrameTypeName(frame.Type))

		switch frame.Type {
		case FrameSettings:
			if frame.Flags&0x1 == 0 { // Not ACK
				parseSettingsFrame(frame, fp)
			}
		case FrameWindowUpdate:
			if frame.StreamID == 0 { // Connection-level window update
				parseWindowUpdateFrame(frame, fp)
			}
		case FramePriority:
			parsePriorityFrame(frame, fp)
		case FrameHeaders:
			// Extract pseudo-header order from HEADERS frame
			parseHeadersFrameOrder(frame, fp)
		}

		pos += frameLen
		frameCount++
	}

	// Build Akamai fingerprint string
	fp.Akamai = buildAkamaiFingerprint(fp)

	// Calculate hash
	hash := sha256.Sum256([]byte(fp.Akamai))
	fp.AkamaiHash = hex.EncodeToString(hash[:])[:32]

	return fp, nil
}

func parseFrame(data []byte) (*HTTP2Frame, error) {
	if len(data) < 9 {
		return nil, fmt.Errorf("frame header too short")
	}

	frame := &HTTP2Frame{
		Length:   uint32(data[0])<<16 | uint32(data[1])<<8 | uint32(data[2]),
		Type:     data[3],
		Flags:    data[4],
		StreamID: binary.BigEndian.Uint32(data[5:9]) & 0x7FFFFFFF,
	}

	if len(data) >= 9+int(frame.Length) {
		frame.Payload = data[9 : 9+frame.Length]
	}

	return frame, nil
}

func parseSettingsFrame(frame *HTTP2Frame, fp *HTTP2Fingerprint) {
	payload := frame.Payload
	for i := 0; i+6 <= len(payload); i += 6 {
		id := binary.BigEndian.Uint16(payload[i : i+2])
		value := binary.BigEndian.Uint32(payload[i+2 : i+6])

		fp.Settings = append(fp.Settings, SettingParam{
			ID:    id,
			Name:  getSettingName(id),
			Value: value,
		})
	}
}

func parseWindowUpdateFrame(frame *HTTP2Frame, fp *HTTP2Fingerprint) {
	if len(frame.Payload) >= 4 {
		fp.WindowUpdate = binary.BigEndian.Uint32(frame.Payload[:4]) & 0x7FFFFFFF
	}
}

func parsePriorityFrame(frame *HTTP2Frame, fp *HTTP2Fingerprint) {
	if len(frame.Payload) >= 5 {
		depAndExclusive := binary.BigEndian.Uint32(frame.Payload[:4])
		exclusive := uint8((depAndExclusive >> 31) & 1)
		dependsOn := depAndExclusive & 0x7FFFFFFF
		weight := frame.Payload[4]

		fp.Priorities = append(fp.Priorities, PriorityInfo{
			StreamID:  frame.StreamID,
			Exclusive: exclusive,
			DependsOn: dependsOn,
			Weight:    weight,
		})
	}
}

func parseHeadersFrameOrder(frame *HTTP2Frame, fp *HTTP2Fingerprint) {
	// The pseudo-header order is encoded in HPACK compressed headers
	// For simplicity, we'll try to detect common patterns
	// A full implementation would need HPACK decoding

	if fp.PseudoHeaderOrder != "" {
		return // Already set
	}

	payload := frame.Payload

	// Skip padding if present
	padLength := uint8(0)
	pos := 0
	if frame.Flags&0x8 != 0 { // PADDED flag
		if len(payload) > 0 {
			padLength = payload[0]
			pos = 1
		}
	}

	// Skip priority data if present
	if frame.Flags&0x20 != 0 { // PRIORITY flag
		pos += 5
	}

	if pos >= len(payload) {
		return
	}

	headerBlock := payload[pos : len(payload)-int(padLength)]

	// Try to extract pseudo-header order from HPACK encoded data
	order := extractPseudoHeaderOrder(headerBlock)
	if order != "" {
		fp.PseudoHeaderOrder = order
	}
}

// extractPseudoHeaderOrder attempts to extract pseudo-header order from HPACK data
// This is a simplified implementation that looks for indexed header patterns
func extractPseudoHeaderOrder(data []byte) string {
	// HPACK uses static table indices for pseudo-headers:
	// Index 2: :method GET
	// Index 3: :method POST
	// Index 4: :path /
	// Index 5: :path /index.html
	// Index 6: :scheme http
	// Index 7: :scheme https
	// Index 1: :authority (needs value)

	// Look for common patterns in the first bytes
	// This is heuristic - browsers have consistent patterns

	var order []string
	seen := make(map[string]bool)

	for i := 0; i < len(data) && i < 20; i++ {
		b := data[i]

		// Indexed header field (starts with 1)
		if b&0x80 != 0 {
			index := int(b & 0x7F)
			switch index {
			case 2, 3: // :method
				if !seen["m"] {
					order = append(order, "m")
					seen["m"] = true
				}
			case 4, 5: // :path
				if !seen["p"] {
					order = append(order, "p")
					seen["p"] = true
				}
			case 6, 7: // :scheme
				if !seen["s"] {
					order = append(order, "s")
					seen["s"] = true
				}
			case 1: // :authority
				if !seen["a"] {
					order = append(order, "a")
					seen["a"] = true
				}
			}
		}

		// Literal header with incremental indexing (starts with 01)
		if b&0xC0 == 0x40 {
			index := int(b & 0x3F)
			switch index {
			case 2, 3:
				if !seen["m"] {
					order = append(order, "m")
					seen["m"] = true
				}
			case 4, 5:
				if !seen["p"] {
					order = append(order, "p")
					seen["p"] = true
				}
			case 6, 7:
				if !seen["s"] {
					order = append(order, "s")
					seen["s"] = true
				}
			case 1:
				if !seen["a"] {
					order = append(order, "a")
					seen["a"] = true
				}
			}
		}
	}

	// If we found at least 3 pseudo-headers, return the order
	if len(order) >= 3 {
		return strings.Join(order, ",")
	}

	// Default fallback based on common browser patterns
	return ""
}

func buildAkamaiFingerprint(fp *HTTP2Fingerprint) string {
	// Format: SETTINGS|WINDOW_UPDATE|PRIORITY|Pseudo-Header-Order

	// 1. Settings part: "id:value;id:value;..."
	// Sort settings by ID for consistency
	sortedSettings := make([]SettingParam, len(fp.Settings))
	copy(sortedSettings, fp.Settings)
	sort.Slice(sortedSettings, func(i, j int) bool {
		return sortedSettings[i].ID < sortedSettings[j].ID
	})

	var settingParts []string
	for _, s := range sortedSettings {
		settingParts = append(settingParts, fmt.Sprintf("%d:%d", s.ID, s.Value))
	}
	settingsStr := strings.Join(settingParts, ";")

	// 2. Window Update
	windowStr := fmt.Sprintf("%d", fp.WindowUpdate)

	// 3. Priority: "streamID:exclusive:dependsOn:weight,..."
	var priorityParts []string
	for _, p := range fp.Priorities {
		priorityParts = append(priorityParts, fmt.Sprintf("%d:%d:%d:%d",
			p.StreamID, p.Exclusive, p.DependsOn, p.Weight))
	}
	priorityStr := "0"
	if len(priorityParts) > 0 {
		priorityStr = strings.Join(priorityParts, ",")
	}

	// 4. Pseudo-header order
	headerOrder := fp.PseudoHeaderOrder
	if headerOrder == "" {
		headerOrder = "m,a,s,p" // Default Chrome order
	}

	return fmt.Sprintf("%s|%s|%s|%s", settingsStr, windowStr, priorityStr, headerOrder)
}

func getFrameTypeName(t uint8) string {
	switch t {
	case FrameData:
		return "DATA"
	case FrameHeaders:
		return "HEADERS"
	case FramePriority:
		return "PRIORITY"
	case FrameRSTStream:
		return "RST_STREAM"
	case FrameSettings:
		return "SETTINGS"
	case FramePushPromise:
		return "PUSH_PROMISE"
	case FramePing:
		return "PING"
	case FrameGoAway:
		return "GOAWAY"
	case FrameWindowUpdate:
		return "WINDOW_UPDATE"
	case FrameContinuation:
		return "CONTINUATION"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", t)
	}
}

func getSettingName(id uint16) string {
	switch id {
	case SettingsHeaderTableSize:
		return "HEADER_TABLE_SIZE"
	case SettingsEnablePush:
		return "ENABLE_PUSH"
	case SettingsMaxConcurrentStreams:
		return "MAX_CONCURRENT_STREAMS"
	case SettingsInitialWindowSize:
		return "INITIAL_WINDOW_SIZE"
	case SettingsMaxFrameSize:
		return "MAX_FRAME_SIZE"
	case SettingsMaxHeaderListSize:
		return "MAX_HEADER_LIST_SIZE"
	default:
		return fmt.Sprintf("UNKNOWN(%d)", id)
	}
}

// IsHTTP2Preface checks if data starts with HTTP/2 connection preface
func IsHTTP2Preface(data []byte) bool {
	if len(data) < len(http2Preface) {
		return false
	}
	for i := 0; i < len(http2Preface); i++ {
		if data[i] != http2Preface[i] {
			return false
		}
	}
	return true
}
