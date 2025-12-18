# Browser Fingerprint Collector

A comprehensive browser fingerprint collection tool that captures TLS, HTTP/2, Canvas, WebGL, Audio, and other browser fingerprints.

## Features

- **Client Fingerprints**: Canvas, WebGL, Audio, Navigator, Screen, Fonts, WebRTC IPs
- **TLS Fingerprints**: JA3, JA4, Cipher Suites, Extensions
- **HTTP/2 Fingerprints**: Akamai format (SETTINGS, WINDOW_UPDATE, PRIORITY, Pseudo-header order)
- **Server Fingerprints**: HTTP Headers, IP, Client Hints
- **Device ID**: Stable browser identifier using MurmurHash3
- **Automation Detection**: WebDriver, Selenium, Puppeteer detection
- **Incognito Detection**: Private browsing mode detection

## Quick Start

```bash
# Clone and install
git clone https://github.com/zhizhuodemao/fingerprint-collector.git
cd fingerprint-collector
pip install -r requirements.txt

# Generate TLS certificate (first time only)
cd tls-server
openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt \
  -sha256 -days 365 -nodes -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
cd ..

# Run (auto-starts both Flask and TLS servers)
python app.py
```

Then visit: **http://localhost:5000**

## Project Structure

```
fingerprint-collector/
├── app.py                      # Flask main server (auto-starts TLS server)
├── requirements.txt            # Python dependencies
├── templates/
│   ├── index.html              # Main collection page
│   ├── history.html            # Fingerprint history
│   └── api.html                # API documentation
├── static/
│   ├── css/simple.css          # Unified styles
│   └── js/
│       ├── app.js              # Main application
│       ├── collectors/         # Fingerprint collectors
│       └── utils/              # Utilities (API, Device ID)
└── tls-server/
    ├── main.go                 # TLS + HTTP/2 fingerprint server
    ├── http2.go                # HTTP/2 frame parsing
    ├── tls-server-darwin-arm64 # macOS ARM64 binary
    ├── tls-server-linux-amd64  # Linux x86_64 binary
    ├── tls-server-windows-amd64.exe # Windows binary
    ├── server.crt              # TLS certificate (generate locally)
    └── server.key              # TLS private key (generate locally)
```

## Collected Fingerprints

### Device Identity

| ID | Source | Stability |
|----|--------|-----------|
| Device ID (Core) | Hardware signals (Canvas, WebGL, Audio, Fonts) | High |
| TLS ID (JA4) | TLS ClientHello parameters | High |
| HTTP/2 ID (Akamai) | HTTP/2 connection parameters | High |

### TLS Fingerprint (JA3/JA4)

```json
{
  "ja3": "771,4865-4866-4867-49195-...",
  "ja3_hash": "640bdf38bd25e28b0c1ac2ac45cfe6ba",
  "ja4": "t13d1516h2_8daaf6152771_d8a2da3f94cd",
  "ciphers": ["TLS_AES_128_GCM_SHA256", "..."],
  "extensions": [{"name": "server_name", "id": 0}, "..."],
  "supported_versions": ["TLS 1.3", "TLS 1.2"],
  "alpn": ["h2", "http/1.1"]
}
```

### HTTP/2 Fingerprint (Akamai Format)

Format: `SETTINGS|WINDOW_UPDATE|PRIORITY|Pseudo-Header-Order`

```json
{
  "akamai": "1:65536;2:0;4:6291456;6:262144|15663105|0|m,a,s,p",
  "akamai_hash": "b95b8e312a5ef15db8fae48013d3616c",
  "settings": [
    {"id": 1, "name": "HEADER_TABLE_SIZE", "value": 65536},
    {"id": 2, "name": "ENABLE_PUSH", "value": 0},
    {"id": 4, "name": "INITIAL_WINDOW_SIZE", "value": 6291456},
    {"id": 6, "name": "MAX_HEADER_LIST_SIZE", "value": 262144}
  ],
  "window_update": 15663105,
  "pseudo_header_order": "m,a,s,p"
}
```

| Component | Description | Example |
|-----------|-------------|---------|
| SETTINGS | HTTP/2 SETTINGS frame parameters | `1:65536;2:0;4:6291456` |
| WINDOW_UPDATE | Connection-level window size | `15663105` |
| PRIORITY | Stream priority (if sent) | `0` or `3:0:0:201` |
| Pseudo-Header | Order of :method, :authority, :scheme, :path | `m,a,s,p` (Chrome) |

### Browser Fingerprints

| Category | Signals |
|----------|---------|
| Canvas | Geometry hash, Text hash |
| WebGL | Renderer, Vendor, Extensions, Parameters |
| Audio | AudioContext fingerprint, Sample rate |
| Navigator | userAgent, platform, language, hardwareConcurrency |
| Screen | Resolution, Color depth, Device pixel ratio |
| Fonts | Detected system fonts |
| WebRTC | Local/Public IP addresses |

## API Endpoints

### Flask Server (port 5000)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Main collection page |
| `/history` | GET | Fingerprint history page |
| `/api-docs` | GET | API documentation page |
| `/api/collect` | POST | Submit fingerprint data |
| `/api/fingerprints` | GET | List all fingerprints |
| `/api/fingerprint/:id` | GET | Get fingerprint by ID |
| `/api/server-info` | GET | Get server-side info |
| `/api/config` | GET | Get server configuration |

### TLS Server (port 8443)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Server info page |
| `/api/fingerprint` | GET | Get TLS + HTTP/2 fingerprint |
| `/api/all` | GET | Get all stored fingerprints |

## Building from Source

### Build TLS Server

```bash
cd tls-server

# macOS ARM64
GOOS=darwin GOARCH=arm64 go build -o tls-server-darwin-arm64 .

# Linux x86_64
GOOS=linux GOARCH=amd64 go build -o tls-server-linux-amd64 .

# Windows x86_64
GOOS=windows GOARCH=amd64 go build -o tls-server-windows-amd64.exe .
```

### Generate TLS Certificate

```bash
cd tls-server
openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt \
  -sha256 -days 365 -nodes -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
```

## Browser Differences

| Browser | TLS ID (JA4) | HTTP/2 Pseudo-Header Order |
|---------|--------------|---------------------------|
| Chrome | `t13d1516h2_...` | `m,a,s,p` |
| Firefox | `t13d1516h2_...` | `m,p,a,s` |
| Safari | `t13d1514h2_...` | `m,s,a,p` |

## Notes

- **Certificate**: Self-signed certificate requires manual acceptance in browser
- **JA3 Instability**: Chrome randomizes cipher suite order; use JA4 for stability
- **HTTP/2**: Requires TLS 1.2+ and ALPN negotiation
- **GREASE**: Random values are filtered from fingerprints

## References

- [JA3 Fingerprinting](https://github.com/salesforce/ja3)
- [JA4+ Fingerprinting](https://github.com/FoxIO-LLC/ja4)
- [Akamai HTTP/2 Fingerprinting](https://www.blackhat.com/docs/eu-17/materials/eu-17-Shuster-Passive-Fingerprinting-Of-HTTP2-Clients-wp.pdf)
- [FingerprintJS](https://fingerprint.com/)

## License

For educational and research purposes only.
