/**
 * 浏览器指纹收集器
 * 收集 Canvas, WebGL, Audio, Navigator, Screen, Fonts 等信息
 */

class FingerprintCollector {
    constructor() {
        this.fingerprint = {};
        this.config = null;
        this.init();
    }

    async init() {
        await this.loadConfig();
        this.bindEvents();
        this.updateTlsLink();
        this.showTlsToast();
    }

    async loadConfig() {
        try {
            const response = await fetch('/api/config');
            this.config = await response.json();
        } catch (e) {
            // 使用默认配置
            this.config = {
                tls_url: 'https://localhost:8443',
                api_url: 'https://localhost:8443/api/fingerprint',
            };
        }
    }

    updateTlsLink() {
        // 更新 TLS 链接显示
        const tlsLink = document.querySelector('.card-note a');
        if (tlsLink && this.config) {
            tlsLink.href = this.config.tls_url;
            tlsLink.textContent = this.config.tls_url;
        }
    }

    showTlsToast() {
        const toast = document.getElementById('tlsToast');
        const toastLink = document.getElementById('tlsToastLink');
        const toastClose = document.getElementById('toastClose');

        if (!toast) return;

        // 检查是否已经接受过证书（使用 localStorage 记录）
        const tlsCertAccepted = localStorage.getItem('tlsCertAccepted');
        if (tlsCertAccepted) {
            return; // 已经接受过，不显示 toast
        }

        // 设置 TLS 链接
        const tlsUrl = this.config?.tls_url || 'https://localhost:8443';
        toastLink.href = tlsUrl;

        // 延迟显示 toast
        setTimeout(() => {
            toast.classList.add('visible');
        }, 1000);

        // 关闭按钮
        toastClose.addEventListener('click', () => {
            toast.classList.remove('visible');
        });

        // 点击链接后标记为已接受
        toastLink.addEventListener('click', () => {
            localStorage.setItem('tlsCertAccepted', 'true');
            setTimeout(() => {
                toast.classList.remove('visible');
            }, 500);
        });
    }

    bindEvents() {
        document.getElementById('collectBtn').addEventListener('click', () => this.collect());
        document.getElementById('getTlsBtn').addEventListener('click', () => this.getTlsFingerprint());
        document.getElementById('exportBtn').addEventListener('click', () => this.exportJSON());
        document.getElementById('copyDataBtn').addEventListener('click', () => this.copyJSON());
    }

    // 复制 JSON 到剪贴板
    async copyJSON() {
        const btn = document.getElementById('copyDataBtn');
        const fullData = document.getElementById('fullData').textContent;

        if (fullData === '-') {
            return;
        }

        try {
            await navigator.clipboard.writeText(fullData);
            btn.classList.add('copied');
            btn.querySelector('span').textContent = 'Copied!';

            setTimeout(() => {
                btn.classList.remove('copied');
                btn.querySelector('span').textContent = 'Copy JSON';
            }, 2000);
        } catch (error) {
            console.error('复制失败:', error);
        }
    }

    setStatus(message, type = 'loading') {
        const status = document.getElementById('status');
        const statusText = status.querySelector('.status-text');
        const fingerprintVisual = document.getElementById('fingerprintVisual');
        const statusIcon = document.getElementById('statusIcon');

        statusText.textContent = message;
        status.className = `status-bar visible ${type}`;

        // Update fingerprint visual
        fingerprintVisual.className = 'fingerprint-rings';
        if (type === 'loading') {
            fingerprintVisual.classList.add('collecting');
            statusIcon.textContent = '...';
        } else if (type === 'success') {
            fingerprintVisual.classList.add('success');
            statusIcon.textContent = '✓';
        } else if (type === 'error') {
            statusIcon.textContent = '✗';
        }
    }

    async collect() {
        this.setStatus('正在收集指纹...', 'loading');

        try {
            // 收集各类指纹
            this.fingerprint = {
                timestamp: new Date().toISOString(),
                navigator: this.collectNavigator(),
                screen: this.collectScreen(),
                canvas: await this.collectCanvas(),
                webgl: this.collectWebGL(),
                audio: await this.collectAudio(),
                fonts: this.collectFonts(),
                automation: this.detectAutomation(),
                incognito: await this.detectIncognito(),
                features: this.collectFeatures(),
                timing: this.collectTiming(),
                storage: this.collectStorage(),
                plugins: this.collectPlugins(),
                mimeTypes: this.collectMimeTypes(),
            };

            // 计算指纹哈希
            this.fingerprint.hash = await this.calculateHash(JSON.stringify(this.fingerprint));

            // 先尝试获取 TLS 指纹（静默模式）
            this.setStatus('正在获取 TLS 指纹...', 'loading');
            await this.fetchTlsFingerprint();

            // 显示结果
            this.displayResults();

            // 发送到服务器（包含 TLS 数据）
            await this.sendToServer();

            // 获取 IP 详细信息
            this.setStatus('正在查询 IP 信息...', 'loading');
            await this.fetchIpInfo();

            this.setStatus('指纹收集完成!', 'success');
        } catch (error) {
            console.error('收集失败:', error);
            this.setStatus(`收集失败: ${error.message}`, 'error');
        }
    }

    // 仅获取 TLS 指纹数据，不更新 UI 状态
    async fetchTlsFingerprint() {
        const tlsApiUrl = this.config?.api_url || 'https://localhost:8443/api/fingerprint';
        try {
            const response = await fetch(tlsApiUrl);
            const result = await response.json();
            if (result.success) {
                this.fingerprint.tls = result.fingerprint;
                document.getElementById('tlsInfo').textContent = JSON.stringify(result.fingerprint, null, 2);
            }
        } catch (error) {
            // TLS 获取失败不影响主流程
            console.log('TLS 指纹获取失败:', error.message);
            this.fingerprint.tls = null;
        }
    }

    // 获取 IP 详细信息
    async fetchIpInfo() {
        try {
            const response = await fetch('/api/ip-info');
            const result = await response.json();
            if (result.success) {
                this.displayIpInfo(result.ip_info);
            }
        } catch (error) {
            console.log('IP 信息获取失败:', error.message);
        }

        // 同时获取 WebRTC IP
        await this.fetchWebRtcIp();
    }

    // 获取 WebRTC IP（可能泄露真实 IP）
    async fetchWebRtcIp() {
        try {
            const ips = await this.getWebRtcIps();

            // 显示 WebRTC 本地 IP
            if (ips.local.length > 0) {
                const localIp = ips.local[0];
                document.getElementById('webrtcIp').textContent = localIp;
                // 查询 IP 位置
                this.lookupIpLocation('webrtcIp', localIp);
            } else {
                document.getElementById('webrtcIp').textContent = '未检测到';
            }

            // 显示 WebRTC STUN IP（公网 IP）
            if (ips.public.length > 0) {
                const publicIp = ips.public[0];
                document.getElementById('webrtcStun').textContent = publicIp;
                // 查询 IP 位置
                this.lookupIpLocation('webrtcStun', publicIp);

                // 如果 HTTP IP 是本地 IP，使用 WebRTC 公网 IP 更新时区信息
                const httpIp = document.getElementById('ipAddress').textContent;
                if (httpIp.startsWith('127.') || httpIp.startsWith('192.168.') || httpIp.startsWith('10.')) {
                    await this.updateTimezoneFromIp(publicIp);
                }
            } else {
                document.getElementById('webrtcStun').textContent = '未检测到';
            }
        } catch (error) {
            console.log('WebRTC IP 检测失败:', error.message);
            document.getElementById('webrtcIp').textContent = '不支持/已禁用';
            document.getElementById('webrtcStun').textContent = '不支持/已禁用';
        }
    }

    // 使用指定 IP 更新时区信息
    async updateTimezoneFromIp(ip) {
        try {
            const response = await fetch(`/api/ip-info/${ip}`);
            const result = await response.json();
            if (result.success && result.ip_info) {
                const info = result.ip_info;

                // 更新基于 IP 的时区
                const ipTimezone = info.timezone || '-';
                document.getElementById('ipTimezone').textContent = ipTimezone;

                // 更新时区匹配
                const localTimezone = Intl.DateTimeFormat().resolvedOptions().timeZone;
                const timezoneMatch = document.getElementById('timezoneMatch');
                if (ipTimezone !== '-' && ipTimezone !== 'Local') {
                    const isMatch = ipTimezone === localTimezone;
                    timezoneMatch.textContent = isMatch ? '匹配' : '不匹配';
                    timezoneMatch.className = 'ip-info-value ' + (isMatch ? 'match' : 'mismatch');
                }

                // 更新基于 IP 时区的时间
                if (ipTimezone && ipTimezone !== '-' && ipTimezone !== 'Local') {
                    try {
                        const ipTime = new Date().toLocaleString('zh-CN', {
                            timeZone: ipTimezone,
                            weekday: 'short',
                            year: 'numeric',
                            month: 'short',
                            day: 'numeric',
                            hour: '2-digit',
                            minute: '2-digit',
                            second: '2-digit',
                            timeZoneName: 'short'
                        });
                        document.getElementById('ipTime').textContent = ipTime;
                    } catch (e) {
                        // 忽略错误
                    }
                }
            }
        } catch (error) {
            // 忽略查询错误
        }
    }

    // 通过 WebRTC 获取本地和公网 IP
    getWebRtcIps() {
        return new Promise((resolve, reject) => {
            const ips = { local: [], public: [] };
            const seen = new Set();

            // 检查 WebRTC 是否支持
            if (!window.RTCPeerConnection) {
                reject(new Error('WebRTC not supported'));
                return;
            }

            const pc = new RTCPeerConnection({
                iceServers: [
                    { urls: 'stun:stun.l.google.com:19302' },
                    { urls: 'stun:stun1.l.google.com:19302' },
                ]
            });

            pc.createDataChannel('');

            pc.onicecandidate = (event) => {
                if (!event.candidate) {
                    pc.close();
                    resolve(ips);
                    return;
                }

                const candidate = event.candidate.candidate;
                // 解析 IP 地址
                const ipRegex = /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/;
                const match = candidate.match(ipRegex);

                if (match && !seen.has(match[1])) {
                    const ip = match[1];
                    seen.add(ip);

                    // 判断是本地 IP 还是公网 IP
                    if (ip.startsWith('10.') || ip.startsWith('192.168.') ||
                        ip.startsWith('172.16.') || ip.startsWith('172.17.') ||
                        ip.startsWith('172.18.') || ip.startsWith('172.19.') ||
                        ip.startsWith('172.2') || ip.startsWith('172.30.') ||
                        ip.startsWith('172.31.') || ip === '127.0.0.1') {
                        ips.local.push(ip);
                    } else {
                        ips.public.push(ip);
                    }
                }
            };

            pc.createOffer()
                .then(offer => pc.setLocalDescription(offer))
                .catch(reject);

            // 超时处理
            setTimeout(() => {
                pc.close();
                resolve(ips);
            }, 3000);
        });
    }

    // 查询 IP 位置并更新显示
    async lookupIpLocation(elementId, ip) {
        try {
            const response = await fetch(`/api/ip-info/${ip}`);
            const result = await response.json();
            if (result.success && result.ip_info) {
                const info = result.ip_info;
                const location = info.country !== '本地网络' && info.country !== '查询失败'
                    ? `${info.city || info.country}`
                    : '';
                if (location) {
                    const el = document.getElementById(elementId);
                    el.textContent = `${ip} (${location})`;
                }
            }
        } catch (error) {
            // 忽略查询错误
        }
    }

    // 显示 IP 信息
    displayIpInfo(info) {
        document.getElementById('ipAddress').textContent = info.ip || '-';

        // 显示 IP 和位置
        const ipLocation = info.country !== '本地网络' && info.country !== '查询失败'
            ? ` (${info.city || info.country})`
            : '';
        document.getElementById('ipAddress').textContent = `${info.ip}${ipLocation}`;

        document.getElementById('ipIsp').textContent = info.isp || '-';

        // 基于 IP 的时区
        const ipTimezone = info.timezone || '-';
        document.getElementById('ipTimezone').textContent = ipTimezone;

        // 本地时区
        const localTimezone = Intl.DateTimeFormat().resolvedOptions().timeZone;
        document.getElementById('localTimezone').textContent = localTimezone;

        // 时区匹配检测
        const timezoneMatch = document.getElementById('timezoneMatch');
        if (ipTimezone !== '-' && ipTimezone !== 'Local') {
            const isMatch = ipTimezone === localTimezone;
            timezoneMatch.textContent = isMatch ? '匹配' : '不匹配';
            timezoneMatch.className = 'ip-info-value ' + (isMatch ? 'match' : 'mismatch');
        } else {
            timezoneMatch.textContent = '-';
        }

        // 基于 IP 时区的时间
        if (ipTimezone && ipTimezone !== '-' && ipTimezone !== 'Local') {
            try {
                const ipTime = new Date().toLocaleString('zh-CN', {
                    timeZone: ipTimezone,
                    weekday: 'short',
                    year: 'numeric',
                    month: 'short',
                    day: 'numeric',
                    hour: '2-digit',
                    minute: '2-digit',
                    second: '2-digit',
                    timeZoneName: 'short'
                });
                document.getElementById('ipTime').textContent = ipTime;
            } catch (e) {
                document.getElementById('ipTime').textContent = '-';
            }
        } else {
            document.getElementById('ipTime').textContent = '-';
        }

        // 本地时间
        const localTime = new Date().toLocaleString('zh-CN', {
            weekday: 'short',
            year: 'numeric',
            month: 'short',
            day: 'numeric',
            hour: '2-digit',
            minute: '2-digit',
            second: '2-digit',
            timeZoneName: 'long'
        });
        document.getElementById('localTime').textContent = localTime;

        // 风险等级徽章
        const riskBadge = document.getElementById('ipRiskBadge');
        riskBadge.textContent = info.risk_level || '-';
        riskBadge.className = 'card-badge';
        if (info.risk_level === '低风险' || info.risk_level === '安全') {
            riskBadge.classList.add('low-risk');
        } else if (info.risk_level === '中风险') {
            riskBadge.classList.add('medium-risk');
        } else if (info.risk_level === '高风险') {
            riskBadge.classList.add('high-risk');
        }

        // IP 标签
        const flagsContainer = document.getElementById('ipFlags');
        flagsContainer.innerHTML = '';

        const flags = [];
        if (info.is_proxy) flags.push({ text: '代理/VPN', type: 'danger' });
        if (info.is_datacenter) flags.push({ text: '数据中心', type: 'warning' });
        if (info.is_mobile) flags.push({ text: '移动网络', type: '' });
        if (!info.is_proxy && !info.is_datacenter && info.type !== 'local') {
            flags.push({ text: '住宅 IP', type: 'success' });
        }
        if (info.type === 'local') flags.push({ text: '本地测试', type: '' });

        flags.forEach(flag => {
            const span = document.createElement('span');
            span.className = `ip-flag ${flag.type}`;
            span.textContent = flag.text;
            flagsContainer.appendChild(span);
        });
    }

    // Navigator 信息
    collectNavigator() {
        const nav = navigator;
        return {
            userAgent: nav.userAgent,
            platform: nav.platform,
            language: nav.language,
            languages: Array.from(nav.languages || []),
            cookieEnabled: nav.cookieEnabled,
            doNotTrack: nav.doNotTrack,
            hardwareConcurrency: nav.hardwareConcurrency,
            maxTouchPoints: nav.maxTouchPoints,
            deviceMemory: nav.deviceMemory,
            vendor: nav.vendor,
            vendorSub: nav.vendorSub,
            product: nav.product,
            productSub: nav.productSub,
            appCodeName: nav.appCodeName,
            appName: nav.appName,
            appVersion: nav.appVersion,
            oscpu: nav.oscpu,
            buildID: nav.buildID,
            pdfViewerEnabled: nav.pdfViewerEnabled,
            webdriver: nav.webdriver,
            connection: this.collectConnection(),
            permissions: this.collectPermissions(),
        };
    }

    collectConnection() {
        const conn = navigator.connection || navigator.mozConnection || navigator.webkitConnection;
        if (!conn) return null;
        return {
            effectiveType: conn.effectiveType,
            downlink: conn.downlink,
            rtt: conn.rtt,
            saveData: conn.saveData,
        };
    }

    collectPermissions() {
        // 返回权限 API 是否存在
        return {
            permissionsAPI: !!navigator.permissions,
            geolocation: !!navigator.geolocation,
            mediaDevices: !!navigator.mediaDevices,
            bluetooth: !!navigator.bluetooth,
            usb: !!navigator.usb,
            hid: !!navigator.hid,
            serial: !!navigator.serial,
            wakeLock: !!navigator.wakeLock,
            clipboard: !!navigator.clipboard,
            credentials: !!navigator.credentials,
            serviceWorker: !!navigator.serviceWorker,
        };
    }

    // 屏幕信息
    collectScreen() {
        const screen = window.screen;
        return {
            width: screen.width,
            height: screen.height,
            availWidth: screen.availWidth,
            availHeight: screen.availHeight,
            colorDepth: screen.colorDepth,
            pixelDepth: screen.pixelDepth,
            devicePixelRatio: window.devicePixelRatio,
            orientation: screen.orientation ? {
                type: screen.orientation.type,
                angle: screen.orientation.angle,
            } : null,
            innerWidth: window.innerWidth,
            innerHeight: window.innerHeight,
            outerWidth: window.outerWidth,
            outerHeight: window.outerHeight,
            screenX: window.screenX,
            screenY: window.screenY,
        };
    }

    // Canvas 指纹
    async collectCanvas() {
        const canvas = document.createElement('canvas');
        canvas.width = 300;
        canvas.height = 150;
        const ctx = canvas.getContext('2d');

        // 绘制文本和图形
        ctx.textBaseline = 'top';
        ctx.font = '14px Arial';
        ctx.fillStyle = '#f60';
        ctx.fillRect(125, 1, 62, 20);

        ctx.fillStyle = '#069';
        ctx.fillText('Fingerprint Canvas Test 🎨', 2, 15);

        ctx.fillStyle = 'rgba(102, 204, 0, 0.7)';
        ctx.fillText('Hello, World!', 4, 45);

        // 绘制渐变
        const gradient = ctx.createLinearGradient(0, 0, 300, 0);
        gradient.addColorStop(0, 'red');
        gradient.addColorStop(0.5, 'green');
        gradient.addColorStop(1, 'blue');
        ctx.fillStyle = gradient;
        ctx.fillRect(0, 80, 300, 30);

        // 绘制圆弧
        ctx.beginPath();
        ctx.arc(50, 120, 20, 0, Math.PI * 2, true);
        ctx.closePath();
        ctx.fillStyle = '#ff6b6b';
        ctx.fill();

        // 绘制贝塞尔曲线
        ctx.beginPath();
        ctx.moveTo(100, 100);
        ctx.bezierCurveTo(130, 80, 160, 140, 200, 120);
        ctx.strokeStyle = '#00d4ff';
        ctx.lineWidth = 3;
        ctx.stroke();

        const dataURL = canvas.toDataURL();
        const hash = await this.calculateHash(dataURL);

        // 显示预览
        const preview = document.getElementById('canvasPreview');
        preview.innerHTML = '';
        preview.appendChild(canvas);

        return {
            dataURL: dataURL.substring(0, 100) + '...',
            hash: hash,
            width: canvas.width,
            height: canvas.height,
        };
    }

    // WebGL 指纹
    collectWebGL() {
        const canvas = document.createElement('canvas');
        const gl = canvas.getContext('webgl') || canvas.getContext('experimental-webgl');

        if (!gl) {
            return { supported: false };
        }

        const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');

        const result = {
            supported: true,
            version: gl.getParameter(gl.VERSION),
            shadingLanguageVersion: gl.getParameter(gl.SHADING_LANGUAGE_VERSION),
            vendor: gl.getParameter(gl.VENDOR),
            renderer: gl.getParameter(gl.RENDERER),
            unmaskedVendor: debugInfo ? gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL) : null,
            unmaskedRenderer: debugInfo ? gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL) : null,
            maxTextureSize: gl.getParameter(gl.MAX_TEXTURE_SIZE),
            maxViewportDims: gl.getParameter(gl.MAX_VIEWPORT_DIMS),
            maxRenderbufferSize: gl.getParameter(gl.MAX_RENDERBUFFER_SIZE),
            maxCubeMapTextureSize: gl.getParameter(gl.MAX_CUBE_MAP_TEXTURE_SIZE),
            maxTextureImageUnits: gl.getParameter(gl.MAX_TEXTURE_IMAGE_UNITS),
            maxVertexTextureImageUnits: gl.getParameter(gl.MAX_VERTEX_TEXTURE_IMAGE_UNITS),
            maxCombinedTextureImageUnits: gl.getParameter(gl.MAX_COMBINED_TEXTURE_IMAGE_UNITS),
            maxVertexAttribs: gl.getParameter(gl.MAX_VERTEX_ATTRIBS),
            maxVertexUniformVectors: gl.getParameter(gl.MAX_VERTEX_UNIFORM_VECTORS),
            maxFragmentUniformVectors: gl.getParameter(gl.MAX_FRAGMENT_UNIFORM_VECTORS),
            maxVaryingVectors: gl.getParameter(gl.MAX_VARYING_VECTORS),
            aliasedLineWidthRange: Array.from(gl.getParameter(gl.ALIASED_LINE_WIDTH_RANGE)),
            aliasedPointSizeRange: Array.from(gl.getParameter(gl.ALIASED_POINT_SIZE_RANGE)),
            redBits: gl.getParameter(gl.RED_BITS),
            greenBits: gl.getParameter(gl.GREEN_BITS),
            blueBits: gl.getParameter(gl.BLUE_BITS),
            alphaBits: gl.getParameter(gl.ALPHA_BITS),
            depthBits: gl.getParameter(gl.DEPTH_BITS),
            stencilBits: gl.getParameter(gl.STENCIL_BITS),
            extensions: gl.getSupportedExtensions(),
        };

        // WebGL2 检测
        const gl2 = canvas.getContext('webgl2');
        result.webgl2Supported = !!gl2;

        return result;
    }

    // 音频指纹
    async collectAudio() {
        try {
            const audioContext = new (window.AudioContext || window.webkitAudioContext)();

            // 创建音频节点
            const oscillator = audioContext.createOscillator();
            const analyser = audioContext.createAnalyser();
            const gainNode = audioContext.createGain();
            const scriptProcessor = audioContext.createScriptProcessor(4096, 1, 1);

            // 设置参数
            oscillator.type = 'triangle';
            oscillator.frequency.setValueAtTime(10000, audioContext.currentTime);
            gainNode.gain.setValueAtTime(0, audioContext.currentTime);

            // 连接节点
            oscillator.connect(analyser);
            analyser.connect(scriptProcessor);
            scriptProcessor.connect(gainNode);
            gainNode.connect(audioContext.destination);

            // 收集音频数据
            let audioData = [];
            let resolved = false;

            return new Promise((resolve) => {
                const cleanup = () => {
                    if (resolved) return;
                    resolved = true;
                    try { oscillator.stop(); } catch (e) {}
                    if (audioContext.state !== 'closed') {
                        audioContext.close().catch(() => {});
                    }
                };

                scriptProcessor.onaudioprocess = (event) => {
                    if (resolved) return;

                    const inputData = event.inputBuffer.getChannelData(0);
                    for (let i = 0; i < inputData.length; i++) {
                        if (inputData[i] !== 0) {
                            audioData.push(inputData[i]);
                        }
                    }

                    if (audioData.length > 100) {
                        const sum = audioData.slice(0, 100).reduce((a, b) => a + Math.abs(b), 0);
                        const result = {
                            supported: true,
                            sampleRate: audioContext.sampleRate,
                            state: 'collected',
                            fingerprint: sum.toString(),
                            baseLatency: audioContext.baseLatency,
                            outputLatency: audioContext.outputLatency,
                            channelCount: audioContext.destination.channelCount,
                            maxChannelCount: audioContext.destination.maxChannelCount,
                        };
                        cleanup();
                        resolve(result);
                    }
                };

                oscillator.start(0);

                // 超时处理
                setTimeout(() => {
                    if (resolved) return;
                    const result = {
                        supported: true,
                        sampleRate: audioContext.sampleRate,
                        state: 'timeout',
                        fingerprint: audioData.length > 0 ?
                            audioData.slice(0, 100).reduce((a, b) => a + Math.abs(b), 0).toString() : null,
                    };
                    cleanup();
                    resolve(result);
                }, 1000);
            });
        } catch (error) {
            return {
                supported: false,
                error: error.message,
            };
        }
    }

    // 字体检测
    collectFonts() {
        const baseFonts = ['monospace', 'sans-serif', 'serif'];
        const testFonts = [
            'Arial', 'Arial Black', 'Arial Narrow', 'Calibri', 'Cambria',
            'Cambria Math', 'Comic Sans MS', 'Consolas', 'Courier', 'Courier New',
            'Georgia', 'Helvetica', 'Impact', 'Lucida Console', 'Lucida Sans Unicode',
            'Microsoft Sans Serif', 'MS Gothic', 'MS PGothic', 'MS Sans Serif',
            'MS Serif', 'Palatino Linotype', 'Segoe Print', 'Segoe Script',
            'Segoe UI', 'Segoe UI Light', 'Segoe UI Semibold', 'Segoe UI Symbol',
            'Tahoma', 'Times', 'Times New Roman', 'Trebuchet MS', 'Verdana',
            'Wingdings', 'Wingdings 2', 'Wingdings 3',
            // 中文字体
            'SimHei', 'SimSun', 'NSimSun', 'FangSong', 'KaiTi', 'Microsoft YaHei',
            'Microsoft JhengHei', 'PMingLiU', 'MingLiU',
            // macOS 字体
            'Apple Braille', 'Apple Chancery', 'Apple Color Emoji', 'Apple SD Gothic Neo',
            'Apple Symbols', 'AppleGothic', 'AppleMyungjo', 'Avenir', 'Avenir Next',
            'Baskerville', 'Big Caslon', 'Brush Script MT', 'Chalkboard',
            'Chalkboard SE', 'Chalkduster', 'Charter', 'Cochin', 'Copperplate',
            'Didot', 'Futura', 'Geneva', 'Gill Sans', 'Helvetica Neue',
            'Herculanum', 'Hoefler Text', 'Lucida Grande', 'Luminari', 'Marker Felt',
            'Menlo', 'Monaco', 'Noteworthy', 'Optima', 'Palatino', 'Papyrus',
            'Phosphate', 'PingFang SC', 'PingFang TC', 'PingFang HK',
            'Rockwell', 'Savoye LET', 'SignPainter', 'Skia', 'Snell Roundhand',
            'STHeiti', 'STXihei', 'Zapfino',
        ];

        const testString = 'mmmmmmmmmmlli';
        const testSize = '72px';

        const canvas = document.createElement('canvas');
        const ctx = canvas.getContext('2d');

        // 获取基础字体宽度
        const getWidth = (font) => {
            ctx.font = `${testSize} ${font}`;
            return ctx.measureText(testString).width;
        };

        const baseWidths = {};
        baseFonts.forEach(font => {
            baseWidths[font] = getWidth(font);
        });

        // 检测字体
        const detectedFonts = [];
        testFonts.forEach(font => {
            for (const baseFont of baseFonts) {
                const width = getWidth(`'${font}', ${baseFont}`);
                if (width !== baseWidths[baseFont]) {
                    detectedFonts.push(font);
                    break;
                }
            }
        });

        // 显示字体
        const fontsDiv = document.getElementById('fontsInfo');
        fontsDiv.innerHTML = detectedFonts.map(f =>
            `<span class="font-tag detected">${f}</span>`
        ).join('');

        return {
            detected: detectedFonts,
            count: detectedFonts.length,
        };
    }

    // 检测无痕模式
    async detectIncognito() {
        const result = {
            isIncognito: false,
            confidence: 'low',
            browserName: this.getBrowserName(),
            checks: {
                storageQuota: null,
                storageQuotaLimit: null,
                fileSystem: null,
                serviceWorker: null,
                indexedDB: null,
            }
        };

        try {
            const browserName = result.browserName;

            // Chrome/Edge/Opera/Brave 检测
            if (browserName === 'Chrome' || browserName === 'Edge' || browserName === 'Opera' || browserName === 'Brave') {
                let checksPerformed = 0;
                let incognitoSignals = 0;

                // 方法1: Storage Quota 检测
                if ('storage' in navigator && 'estimate' in navigator.storage) {
                    const { quota } = await navigator.storage.estimate();
                    result.checks.storageQuota = quota;
                    checksPerformed++;

                    // Chrome 无痕模式的配额通常受限
                    // 正常模式配额通常 > 1GB，无痕模式 < 300MB
                    if (quota && quota < 300000000) {
                        incognitoSignals++;
                    }

                    // 更精确的检测：对比 performance.memory (如果可用)
                    if (window.performance && window.performance.memory) {
                        const heapLimit = window.performance.memory.jsHeapSizeLimit;
                        result.checks.storageQuotaLimit = heapLimit;
                        checksPerformed++;
                        // 无痕模式下 quota 通常小于 heapLimit 的 2 倍
                        if (quota < heapLimit * 2) {
                            incognitoSignals++;
                        }
                    }
                }

                // 方法2: webkitRequestFileSystem (某些版本仍有效)
                if (window.webkitRequestFileSystem) {
                    checksPerformed++;
                    try {
                        await new Promise((resolve, reject) => {
                            window.webkitRequestFileSystem(
                                window.TEMPORARY,
                                1,
                                () => {
                                    result.checks.fileSystem = 'available';
                                    resolve();
                                },
                                (err) => {
                                    result.checks.fileSystem = 'blocked';
                                    incognitoSignals++;
                                    resolve();
                                }
                            );
                        });
                    } catch (e) {
                        result.checks.fileSystem = 'error';
                    }
                }

                // 根据信号数量判断
                if (incognitoSignals > 0) {
                    result.isIncognito = true;
                    result.confidence = incognitoSignals >= 2 ? 'high' : 'medium';
                } else if (checksPerformed > 0) {
                    // 执行了检测但没有发现无痕信号，说明是正常模式
                    result.confidence = checksPerformed >= 2 ? 'high' : 'medium';
                }
            }

            // Firefox 检测
            if (browserName === 'Firefox') {
                let checksPerformed = 0;
                let incognitoSignals = 0;

                if ('serviceWorker' in navigator) {
                    checksPerformed++;
                    try {
                        await navigator.serviceWorker.getRegistrations();
                        result.checks.serviceWorker = 'available';
                    } catch (e) {
                        result.checks.serviceWorker = 'blocked';
                        incognitoSignals++;
                    }
                }

                if ('storage' in navigator && 'estimate' in navigator.storage) {
                    checksPerformed++;
                    const { quota } = await navigator.storage.estimate();
                    result.checks.storageQuota = quota;
                    // Firefox 无痕模式配额通常较小
                    if (quota && quota < 2147483648) {
                        incognitoSignals++;
                    }
                }

                if (incognitoSignals > 0) {
                    result.isIncognito = true;
                    result.confidence = incognitoSignals >= 2 ? 'high' : 'medium';
                } else if (checksPerformed > 0) {
                    result.confidence = checksPerformed >= 2 ? 'high' : 'medium';
                }
            }

            // Safari 检测
            if (browserName === 'Safari') {
                let checksPerformed = 0;
                let incognitoSignals = 0;

                try {
                    checksPerformed++;
                    const db = indexedDB.open('test-private');
                    await new Promise((resolve) => {
                        db.onerror = () => {
                            result.checks.indexedDB = 'blocked';
                            incognitoSignals++;
                            resolve();
                        };
                        db.onsuccess = () => {
                            result.checks.indexedDB = 'available';
                            db.result.close();
                            indexedDB.deleteDatabase('test-private');
                            resolve();
                        };
                    });
                } catch (e) {
                    result.checks.indexedDB = 'error';
                    incognitoSignals++;
                }

                if (incognitoSignals > 0) {
                    result.isIncognito = true;
                    result.confidence = 'high';
                } else if (checksPerformed > 0) {
                    result.confidence = 'high';
                }
            }

        } catch (e) {
            result.error = e.message;
        }

        return result;
    }

    // 获取浏览器名称
    getBrowserName() {
        const ua = navigator.userAgent;
        if (ua.includes('Firefox')) return 'Firefox';
        if (ua.includes('Edg/')) return 'Edge';
        if (ua.includes('OPR/') || ua.includes('Opera')) return 'Opera';
        if (ua.includes('Brave')) return 'Brave';
        if (ua.includes('Chrome')) return 'Chrome';
        if (ua.includes('Safari')) return 'Safari';
        return 'Unknown';
    }

    // 自动化检测
    detectAutomation() {
        const checks = {
            // Webdriver 检测
            webdriver: navigator.webdriver,
            webdriverUndefined: navigator.webdriver === undefined,

            // Chrome 自动化特征
            chromeDriver: !!window.cdc_adoQpoasnfa76pfcZLmcfl_Array,
            chromeDriverUnderscore: !!window._cdc_adoQpoasnfa76pfcZLmcfl_,
            domAutomation: !!window.domAutomation,
            domAutomationController: !!window.domAutomationController,

            // Selenium
            seleniumDocumentKey: !!document.__selenium_evaluate ||
                !!document.__selenium_unwrapped ||
                !!document.__webdriver_evaluate ||
                !!document.__driver_evaluate ||
                !!document.__webdriver_script_function ||
                !!document.__webdriver_script_func ||
                !!document.__webdriver_script_fn ||
                !!document.$chrome_asyncScriptInfo ||
                !!document.$cdc_asdjflasutopfhvcZLmcfl_,

            seleniumWindowKey: !!window._selenium ||
                !!window._Selenium_IDE_Recorder ||
                !!window.callSelenium ||
                !!window.__webdriver_unwrapped ||
                !!window.__selenium_unwrapped,

            // Puppeteer / Playwright
            puppeteer: !!(window._pptrhack || window.__pptr_injected || document.__pptr_injected),

            // PhantomJS
            phantomJS: !!(window.callPhantom || window._phantom || window.phantom),

            // Nightmare
            nightmare: !!window.__nightmare,

            // HeadlessChrome
            headless: /HeadlessChrome/.test(navigator.userAgent),

            // Permissions 异常
            permissionsInconsistent: false,

            // 插件数量异常
            pluginsLengthZero: navigator.plugins.length === 0,

            // Languages 异常
            languagesLengthZero: (navigator.languages || []).length === 0,

            // Chrome 对象检测
            chromeNotExist: typeof window.chrome === 'undefined',
            chromeRuntimeNotExist: !window.chrome?.runtime,

            // 触控事件检测
            touchSupportInconsistent: false,

            // 分辨率异常
            screenResolutionZero: screen.width === 0 || screen.height === 0,
        };

        // 检测 Permission 异常
        if (navigator.permissions) {
            navigator.permissions.query({ name: 'notifications' }).then(result => {
                if (Notification.permission !== 'denied' && result.state === 'denied') {
                    checks.permissionsInconsistent = true;
                }
            }).catch(() => {});
        }

        // 触控检测
        const maxTouchPoints = navigator.maxTouchPoints || 0;
        const touchEvent = 'ontouchstart' in window;
        if ((maxTouchPoints > 0) !== touchEvent) {
            checks.touchSupportInconsistent = true;
        }

        // 计算检测评分
        const automationScore = Object.values(checks).filter(v => v === true).length;

        return {
            checks: checks,
            score: automationScore,
            isLikelyAutomated: automationScore > 3,
        };
    }

    // 浏览器特性检测
    collectFeatures() {
        return {
            // API 支持
            localStorage: !!window.localStorage,
            sessionStorage: !!window.sessionStorage,
            indexedDB: !!window.indexedDB,
            openDatabase: !!window.openDatabase,
            requestIdleCallback: !!window.requestIdleCallback,
            requestAnimationFrame: !!window.requestAnimationFrame,
            fetch: !!window.fetch,
            webSocket: !!window.WebSocket,
            webWorker: !!window.Worker,
            sharedWorker: !!window.SharedWorker,
            serviceWorker: !!navigator.serviceWorker,

            // 多媒体
            webGL: !!document.createElement('canvas').getContext('webgl'),
            webGL2: !!document.createElement('canvas').getContext('webgl2'),
            webAudio: !!(window.AudioContext || window.webkitAudioContext),
            webRTC: !!window.RTCPeerConnection,

            // 传感器
            accelerometer: !!window.Accelerometer,
            gyroscope: !!window.Gyroscope,
            magnetometer: !!window.Magnetometer,
            absoluteOrientationSensor: !!window.AbsoluteOrientationSensor,

            // 其他
            webAuthn: !!navigator.credentials,
            speechSynthesis: !!window.speechSynthesis,
            speechRecognition: !!(window.SpeechRecognition || window.webkitSpeechRecognition),
            notifications: !!window.Notification,
            geolocation: !!navigator.geolocation,
            vibrate: !!navigator.vibrate,
            getBattery: !!navigator.getBattery,
            bluetooth: !!navigator.bluetooth,
            usb: !!navigator.usb,
            hid: !!navigator.hid,
            serial: !!navigator.serial,
            share: !!navigator.share,
            clipboard: !!navigator.clipboard,
            presentation: !!navigator.presentation,
            wakeLock: !!navigator.wakeLock,

            // CSS
            cssSupportsAPI: !!window.CSS?.supports,
            cssGrid: CSS?.supports?.('display', 'grid'),
            cssFlexbox: CSS?.supports?.('display', 'flex'),
            cssVariables: CSS?.supports?.('--custom', '0'),

            // Performance
            performanceObserver: !!window.PerformanceObserver,
            intersectionObserver: !!window.IntersectionObserver,
            resizeObserver: !!window.ResizeObserver,
            mutationObserver: !!window.MutationObserver,
        };
    }

    // 时间相关
    collectTiming() {
        const performance = window.performance;
        const timing = performance?.timing;

        return {
            timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
            timezoneOffset: new Date().getTimezoneOffset(),
            performanceNow: performance?.now?.(),
            dateNow: Date.now(),
            navigationStart: timing?.navigationStart,
            loadEventEnd: timing?.loadEventEnd,
            domContentLoadedEventEnd: timing?.domContentLoadedEventEnd,
        };
    }

    // 存储检测
    collectStorage() {
        const result = {
            localStorageEnabled: false,
            sessionStorageEnabled: false,
            cookiesEnabled: navigator.cookieEnabled,
            indexedDBEnabled: false,
        };

        try {
            localStorage.setItem('__test__', '1');
            localStorage.removeItem('__test__');
            result.localStorageEnabled = true;
        } catch (e) {}

        try {
            sessionStorage.setItem('__test__', '1');
            sessionStorage.removeItem('__test__');
            result.sessionStorageEnabled = true;
        } catch (e) {}

        try {
            const request = indexedDB.open('__test__');
            request.onerror = () => {};
            request.onsuccess = () => {
                result.indexedDBEnabled = true;
                request.result.close();
                indexedDB.deleteDatabase('__test__');
            };
        } catch (e) {}

        return result;
    }

    // 插件检测
    collectPlugins() {
        const plugins = Array.from(navigator.plugins || []).map(p => ({
            name: p.name,
            filename: p.filename,
            description: p.description,
        }));
        return {
            count: plugins.length,
            list: plugins,
        };
    }

    // MIME 类型检测
    collectMimeTypes() {
        const mimeTypes = Array.from(navigator.mimeTypes || []).map(m => ({
            type: m.type,
            suffixes: m.suffixes,
            description: m.description,
        }));
        return {
            count: mimeTypes.length,
            list: mimeTypes,
        };
    }

    // 计算 Hash
    async calculateHash(data) {
        // crypto.subtle 只在 HTTPS 或 localhost 下可用
        if (crypto.subtle) {
            const encoder = new TextEncoder();
            const dataBuffer = encoder.encode(data);
            const hashBuffer = await crypto.subtle.digest('SHA-256', dataBuffer);
            const hashArray = Array.from(new Uint8Array(hashBuffer));
            return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
        } else {
            // HTTP 环境下使用简单哈希
            return this.simpleHash(data);
        }
    }

    // 简单哈希函数（HTTP 环境备用）
    simpleHash(str) {
        let hash = 0;
        for (let i = 0; i < str.length; i++) {
            const char = str.charCodeAt(i);
            hash = ((hash << 5) - hash) + char;
            hash = hash & hash;
        }
        // 转为16进制并补齐到64位
        const hex = Math.abs(hash).toString(16);
        return hex.padStart(16, '0').repeat(4);
    }

    // 显示结果
    displayResults() {
        // 摘要
        document.getElementById('summaryCard').style.display = 'block';
        // 初始显示等待服务端返回
        document.getElementById('browserId').textContent = '收集中...';
        document.getElementById('tlsId').textContent = '-';
        document.getElementById('combinedId').textContent = '-';

        // 格式化时间显示
        const timestamp = this.fingerprint.timestamp ? new Date(this.fingerprint.timestamp).toLocaleString('zh-CN') : '-';
        document.getElementById('fpTime').textContent = timestamp;

        // 基础信息
        document.getElementById('basicInfo').textContent = JSON.stringify(this.fingerprint.navigator, null, 2);

        // 屏幕信息
        document.getElementById('screenInfo').textContent = JSON.stringify(this.fingerprint.screen, null, 2);

        // Canvas 信息
        document.getElementById('canvasInfo').textContent = JSON.stringify(this.fingerprint.canvas, null, 2);

        // WebGL 信息
        const webglData = { ...this.fingerprint.webgl };
        if (webglData.extensions) {
            webglData.extensionsCount = webglData.extensions.length;
            webglData.extensions = webglData.extensions.slice(0, 10).join(', ') + '...';
        }
        document.getElementById('webglInfo').textContent = JSON.stringify(webglData, null, 2);

        // 音频信息
        document.getElementById('audioInfo').textContent = JSON.stringify(this.fingerprint.audio, null, 2);

        // 自动化检测
        document.getElementById('automationInfo').textContent = JSON.stringify(this.fingerprint.automation, null, 2);

        // 无痕模式检测
        const incognito = this.fingerprint.incognito;
        if (incognito) {
            const badge = document.getElementById('incognitoBadge');
            const statusEl = document.getElementById('incognitoStatus');
            const browserEl = document.getElementById('incognitoBrowser');
            const confidenceEl = document.getElementById('incognitoConfidence');
            const quotaEl = document.getElementById('incognitoQuota');
            const heapEl = document.getElementById('incognitoHeap');

            if (incognito.isIncognito) {
                badge.textContent = '检测到';
                badge.className = 'card-badge detected';
                statusEl.textContent = '无痕模式';
                statusEl.className = 'incognito-value detected';
            } else {
                badge.textContent = '正常';
                badge.className = 'card-badge normal';
                statusEl.textContent = '正常模式';
                statusEl.className = 'incognito-value normal';
            }

            browserEl.textContent = incognito.browserName || '-';

            const confidenceMap = { high: '高', medium: '中', low: '低' };
            confidenceEl.textContent = confidenceMap[incognito.confidence] || '低';

            if (incognito.checks.storageQuota) {
                const quotaMB = (incognito.checks.storageQuota / 1024 / 1024).toFixed(2);
                quotaEl.textContent = `${quotaMB} MB`;
            } else {
                quotaEl.textContent = '不支持';
            }

            if (incognito.checks.storageQuotaLimit) {
                const heapMB = (incognito.checks.storageQuotaLimit / 1024 / 1024).toFixed(2);
                heapEl.textContent = `${heapMB} MB`;
            } else {
                heapEl.textContent = '不支持';
            }
        }

        // 完整数据
        document.getElementById('fullData').textContent = JSON.stringify(this.fingerprint, null, 2);
    }

    // 发送到服务器
    async sendToServer() {
        try {
            const response = await fetch('/api/collect', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                },
                body: JSON.stringify(this.fingerprint),
            });

            const result = await response.json();

            if (result.success) {
                // 显示服务端信息
                document.getElementById('serverInfo').textContent = JSON.stringify(result.fingerprint.server, null, 2);
                // 显示三个 ID
                document.getElementById('browserId').textContent = result.browser_id || '-';
                document.getElementById('tlsId').textContent = result.tls_id || '未获取';
                document.getElementById('combinedId').textContent = result.combined_id || '-';
            }
        } catch (error) {
            console.error('发送到服务器失败:', error);
        }
    }

    // 获取 TLS 指纹
    // silent: 静默模式，不单独设置状态消息
    async getTlsFingerprint(silent = false) {
        if (!silent) {
            this.setStatus('正在获取 TLS 指纹...', 'loading');
        }

        const tlsApiUrl = this.config?.api_url || 'https://localhost:8443/api/fingerprint';
        const tlsUrl = this.config?.tls_url || 'https://localhost:8443';

        try {
            // 从 Go TLS 服务获取真实的浏览器 TLS 指纹
            const response = await fetch(tlsApiUrl);
            const result = await response.json();

            if (result.success) {
                document.getElementById('tlsInfo').textContent = JSON.stringify(result.fingerprint, null, 2);

                if (!silent) {
                    this.setStatus('TLS 指纹获取成功!', 'success');
                }

                // 保存到 fingerprint 对象
                this.fingerprint.tls = result.fingerprint;
            } else {
                throw new Error(result.error || 'Unknown error');
            }
        } catch (error) {
            const helpText = `获取失败: ${error.message}

请先完成以下步骤:
1. 在浏览器中访问 ${tlsUrl}
2. 接受自签名证书警告 (点击"高级" -> "继续访问")
3. 然后回来点击此按钮重试`;
            document.getElementById('tlsInfo').textContent = helpText;

            if (!silent) {
                this.setStatus('TLS 指纹获取失败', 'error');
            }
        }
    }

    // 导出 JSON
    exportJSON() {
        if (!this.fingerprint.hash) {
            alert('请先收集指纹');
            return;
        }

        const dataStr = JSON.stringify(this.fingerprint, null, 2);
        const blob = new Blob([dataStr], { type: 'application/json' });
        const url = URL.createObjectURL(blob);

        const a = document.createElement('a');
        a.href = url;
        a.download = `fingerprint-${this.fingerprint.hash.substring(0, 8)}.json`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
    }
}

// 初始化
document.addEventListener('DOMContentLoaded', () => {
    new FingerprintCollector();
});
