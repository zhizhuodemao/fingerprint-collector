# Browser Fingerprint Collector

A comprehensive browser fingerprint collection tool that captures TLS, Canvas, WebGL, Audio, and other browser fingerprints.

## Features

- **Frontend Fingerprints**: Canvas, WebGL, Audio, Navigator, Screen, Fonts, Automation Detection
- **Backend Fingerprints**: HTTP Headers, IP, Request Characteristics
- **TLS Fingerprints**: JA3, JA4, Cipher Suites, Extensions (via local Go server)

## Project Structure

```
fingerprint-collector/
├── app.py                 # Flask main server (port 5000)
├── requirements.txt       # Python dependencies
├── templates/
│   └── index.html         # Frontend page
├── static/
│   ├── style.css          # Styles
│   └── fingerprint.js     # Fingerprint collection logic
└── tls-server/
    ├── main.go            # Go TLS fingerprint server (port 8443)
    ├── server.crt         # TLS certificate
    └── server.key         # TLS private key
```

## Requirements

- Python 3.8+
- Go 1.20+ (for TLS fingerprint collection)
- OpenSSL (for certificate generation)

## Installation

### 1. Install Python Dependencies

```bash
cd /Users/wenbo.chen/Documents/code/fingerprint-collector
pip3 install flask flask-cors requests
```

### 2. Install Go (if not installed)

```bash
brew install go
```

### 3. Generate TLS Certificate (first time only)

```bash
cd tls-server
openssl req -x509 -newkey rsa:2048 -keyout server.key -out server.crt \
  -days 365 -nodes -subj '/CN=localhost'
```

### 4. Build Go TLS Server (first time only)

```bash
cd tls-server
go build -o tls-server main.go
```

## Usage

### Start Services

```bash
# Terminal 1: Start Flask server
cd /Users/wenbo.chen/Documents/code/fingerprint-collector
python3 app.py

# Terminal 2: Start TLS server
cd /Users/wenbo.chen/Documents/code/fingerprint-collector/tls-server
./tls-server
```

Or run both in background:

```bash
cd /Users/wenbo.chen/Documents/code/fingerprint-collector && python3 app.py &
cd /Users/wenbo.chen/Documents/code/fingerprint-collector/tls-server && ./tls-server &
```

### Access

| Service | URL | Description |
|---------|-----|-------------|
| Main UI | http://localhost:5000 | Fingerprint collection page |
| TLS API | https://localhost:8443 | TLS fingerprint capture |

### Collect Fingerprints

1. Open **http://localhost:5000** in your browser
2. Click **"Start Collection"** to collect frontend fingerprints
3. Visit **https://localhost:8443** first and accept the certificate warning
4. Return to main page and click **"Fetch from Local Server"** to get TLS fingerprint
5. Click **"Export JSON"** to download complete fingerprint data

## API Endpoints

### Flask Server (port 5000)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Main page |
| `/api/collect` | POST | Submit fingerprint data |
| `/api/fingerprint/<id>` | GET | Get stored fingerprint by ID |
| `/api/fingerprints` | GET | List all fingerprints |
| `/api/server-info` | GET | Get server-side collected info |

### TLS Server (port 8443)

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Info page |
| `/api/fingerprint` | GET | Get your TLS fingerprint |
| `/api/all` | GET | Get all stored fingerprints |

## Collected Data

### Frontend (JavaScript)

| Category | Data |
|----------|------|
| Navigator | userAgent, platform, language, hardwareConcurrency, deviceMemory, webdriver |
| Screen | width, height, colorDepth, pixelDepth, devicePixelRatio |
| Canvas | Rendered image hash |
| WebGL | Renderer, vendor, extensions, parameters |
| Audio | AudioContext fingerprint, sampleRate |
| Fonts | Detected system fonts |
| Automation | webdriver, Selenium, Puppeteer detection |

### Backend (Python)

| Category | Data |
|----------|------|
| HTTP | Headers, User-Agent, Accept-Language |
| Network | Client IP, HTTP version |
| Client Hints | Sec-CH-UA, Sec-CH-UA-Platform |

### TLS (Go)

| Category | Data |
|----------|------|
| JA3 | Full string and MD5 hash |
| JA4 | Full string and hash |
| Cipher Suites | List with names |
| Extensions | List with parsed data |
| Supported Groups | Elliptic curves |
| Signature Algorithms | List |
| ALPN | Protocol list |

## Example Output

```json
{
  "ja3": "771,4865-4866-4867-49195-...",
  "ja3_hash": "8a8a25700a1e0d3f6988233e7152aa74",
  "ja4": "t13d1517h2_8daaf6152771_b6f405a00624",
  "ciphers": [
    "TLS_AES_128_GCM_SHA256",
    "TLS_AES_256_GCM_SHA384",
    "..."
  ],
  "extensions": [
    {"name": "server_name (0)", "data": "localhost"},
    {"name": "supported_versions (43)", "..."}
  ],
  "supported_versions": ["TLS 1.3", "TLS 1.2"],
  "alpn": ["h2", "http/1.1"]
}
```

## Notes

- TLS fingerprints vary based on target domain (SNI), so `localhost` fingerprint may differ from external sites
- GREASE values are randomized by Chrome on each connection
- Self-signed certificate requires manual acceptance in browser

## License

For educational and research purposes only.
