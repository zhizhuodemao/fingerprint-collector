/**
 * Fingerprint Collector - Simplified Version
 */

// 收集器
import {
    collectNavigator,
    collectScreen,
    collectCanvas,
    collectWebGL,
    collectAudio,
    collectFonts,
    collectMath,
    detectIncognito,
    detectAutomation,
    collectFeatures,
    collectTiming,
    collectStorage,
    collectPlugins,
    collectMimeTypes,
    getWebRtcIps
} from './collectors/index.js';

// 工具
import { loadConfig, sendFingerprint, fetchTlsFingerprint } from './utils/api.js';
import { collectStableSignals, generateDeviceId } from './utils/deviceId.js';

/**
 * 主应用类
 */
class FingerprintApp {
    constructor() {
        this.fingerprint = null;
        this.tlsData = null;
        this.serverData = null;
        this.config = null;
        this.init();
    }

    async init() {
        // 加载配置
        this.config = await loadConfig();

        // 绑定事件
        this.bindEvents();

        // 设置 TLS 服务器链接
        const tlsLink = document.getElementById('tlsServerLink');
        if (tlsLink && this.config) {
            tlsLink.href = this.config.tls_url;
        }

        // 恢复之前的数据
        this.restoreData();

        // 显示 TLS 提示弹窗
        this.showTlsPrompt();
    }

    // 保存数据到 sessionStorage
    saveData() {
        const data = {
            fingerprint: this.fingerprint,
            tlsData: this.tlsData,
            serverData: this.serverData,
        };
        sessionStorage.setItem('fingerprint-data', JSON.stringify(data));
    }

    // 从 sessionStorage 恢复数据
    restoreData() {
        const saved = sessionStorage.getItem('fingerprint-data');
        if (!saved) return;

        try {
            const data = JSON.parse(saved);
            this.fingerprint = data.fingerprint;
            this.tlsData = data.tlsData;
            this.serverData = data.serverData;

            // 如果有数据，显示结果
            if (this.fingerprint) {
                this.displayResults({ success: true });
            }
            if (this.tlsData) {
                document.getElementById('tlsJson').textContent = JSON.stringify(this.tlsData, null, 2);
                const tlsId = this.tlsData?.ja4?.substring(0, 16) ||
                              this.tlsData?.ja3_hash?.substring(0, 16) || '-';
                document.getElementById('tlsId').textContent = tlsId;
            }
        } catch (e) {
            console.error('Failed to restore data:', e);
        }
    }

    showTlsPrompt() {
        // 检查是否已经提示过（本次会话）
        if (sessionStorage.getItem('tls-prompt-shown')) {
            return;
        }

        const modal = document.createElement('div');
        modal.className = 'modal-overlay';
        modal.innerHTML = `
            <div class="modal">
                <div class="modal-header">
                    <h3>TLS Server Setup</h3>
                </div>
                <div class="modal-body">
                    <p>为获取完整的 TLS 指纹，请先在新标签页中打开 TLS Server 并接受证书。</p>
                    <p class="modal-note">这是一次性操作，完成后即可自动采集 TLS 指纹。</p>
                </div>
                <div class="modal-footer">
                    <button class="btn" id="modalSkipBtn">跳过</button>
                    <button class="btn btn-primary" id="modalOpenBtn">打开 TLS Server</button>
                </div>
            </div>
        `;

        document.body.appendChild(modal);

        // 绑定按钮事件
        document.getElementById('modalOpenBtn').addEventListener('click', () => {
            window.open(this.config?.tls_url || 'https://localhost:8443', '_blank');
            sessionStorage.setItem('tls-prompt-shown', '1');
            modal.remove();
        });

        document.getElementById('modalSkipBtn').addEventListener('click', () => {
            sessionStorage.setItem('tls-prompt-shown', '1');
            modal.remove();
        });

        // 点击遮罩关闭
        modal.addEventListener('click', (e) => {
            if (e.target === modal) {
                sessionStorage.setItem('tls-prompt-shown', '1');
                modal.remove();
            }
        });
    }

    bindEvents() {
        // 收集按钮
        document.getElementById('collectBtn')?.addEventListener('click', () => this.collect());

        // TLS 获取按钮
        document.getElementById('fetchTlsBtn')?.addEventListener('click', () => this.fetchTls());

        // 主题切换
        document.getElementById('themeToggle')?.addEventListener('click', () => this.toggleTheme());

        // 复制按钮 - 直接从 pre 元素读取内容
        document.getElementById('copyBrowserBtn')?.addEventListener('click', () => {
            const content = document.getElementById('browserJson')?.textContent;
            this.copyToClipboard(content, 'copyBrowserBtn');
        });
        document.getElementById('copyTlsBtn')?.addEventListener('click', () => {
            const content = document.getElementById('tlsJson')?.textContent;
            this.copyToClipboard(content, 'copyTlsBtn');
        });
        document.getElementById('copyServerBtn')?.addEventListener('click', () => {
            const content = document.getElementById('serverJson')?.textContent;
            this.copyToClipboard(content, 'copyServerBtn');
        });

        // ID 复制按钮
        document.querySelectorAll('.copy-btn[data-copy]').forEach(btn => {
            btn.addEventListener('click', () => {
                const targetId = btn.dataset.copy;
                const el = document.getElementById(targetId);
                if (el) {
                    this.copyToClipboard(el.textContent, btn);
                }
            });
        });
    }

    setStatus(text, type = '') {
        const status = document.getElementById('status');
        if (status) {
            status.textContent = text;
            status.className = 'status ' + type;
        }
    }

    async collect() {
        this.setStatus('Collecting...', 'collecting');

        try {
            // 收集浏览器指纹
            this.fingerprint = {
                timestamp: new Date().toISOString(),
                navigator: collectNavigator(),
                screen: collectScreen(),
                webgl: collectWebGL(),
                fonts: collectFonts(),
                math: collectMath(),
                automation: detectAutomation(),
                features: collectFeatures(),
                timing: collectTiming(),
                storage: collectStorage(),
                plugins: collectPlugins(),
                mimeTypes: collectMimeTypes(),
            };

            // 异步收集
            const [canvas, audio, incognito, webrtcIps] = await Promise.all([
                collectCanvas(),
                collectAudio(),
                detectIncognito(),
                getWebRtcIps().catch(() => null),
            ]);

            this.fingerprint.canvas = canvas;
            this.fingerprint.audio = audio;
            this.fingerprint.incognito = incognito;
            this.fingerprint.webrtcIps = webrtcIps;

            // 生成设备ID
            const stableSignals = collectStableSignals(this.fingerprint);
            const deviceIdResult = generateDeviceId(stableSignals);
            this.fingerprint.deviceId = deviceIdResult;

            // 发送到服务器
            const result = await sendFingerprint(this.fingerprint);

            if (result.success) {
                this.serverData = result.fingerprint?.server || null;
                this.displayResults(result);

                // 自动获取 TLS 指纹
                this.setStatus('Fetching TLS...', 'collecting');
                await this.fetchTls(true); // silent mode

                // 保存数据
                this.saveData();

                this.setStatus('Collected successfully', 'success');
            } else {
                this.setStatus('Collection failed', 'error');
            }

        } catch (error) {
            console.error('Collection error:', error);
            this.setStatus('Error: ' + error.message, 'error');
        }
    }

    async fetchTls(silent = false) {
        try {
            if (!silent) {
                this.setStatus('Fetching TLS...', 'collecting');
            }
            const result = await fetchTlsFingerprint(this.config);

            if (result && result.success) {
                this.tlsData = result.fingerprint;
                document.getElementById('tlsJson').textContent = JSON.stringify(this.tlsData, null, 2);

                // 更新 TLS ID (优先使用 JA4，更稳定)
                const tlsId = this.tlsData?.ja4?.substring(0, 16) ||
                              this.tlsData?.ja3_hash?.substring(0, 16) || '-';
                document.getElementById('tlsId').textContent = tlsId;

                // 保存数据
                this.saveData();

                if (!silent) {
                    this.setStatus('TLS fetched', 'success');
                }
                return true;
            } else {
                document.getElementById('tlsJson').textContent = 'TLS 指纹获取失败。请先访问 TLS Server 并接受证书。';
                if (!silent) {
                    this.setStatus('TLS fetch failed', 'error');
                }
                return false;
            }
        } catch (error) {
            document.getElementById('tlsJson').textContent = 'TLS 指纹获取失败。请先访问 TLS Server 并接受证书。';
            if (!silent) {
                this.setStatus('TLS error', 'error');
            }
            return false;
        }
    }

    displayResults(result) {
        // 显示所有卡片
        document.getElementById('deviceCard').style.display = 'block';
        document.getElementById('browserCard').style.display = 'block';
        document.getElementById('tlsCard').style.display = 'block';
        document.getElementById('serverCard').style.display = 'block';

        // Device ID
        const deviceId = this.fingerprint.deviceId;
        document.getElementById('deviceCoreId').textContent = deviceId?.coreId || '-';
        document.getElementById('tlsId').textContent = result.tls_id || '-';
        document.getElementById('collectedAt').textContent = new Date().toLocaleString('zh-CN');

        // Confidence badge
        const confidence = deviceId?.confidence || 0;
        const badge = document.getElementById('confidenceBadge');
        badge.textContent = `${confidence}% Confidence`;
        badge.className = confidence >= 80 ? 'badge success' : 'badge';

        // Browser JSON (不包含 deviceId，避免重复)
        const browserData = { ...this.fingerprint };
        delete browserData.deviceId;
        document.getElementById('browserJson').textContent = JSON.stringify(browserData, null, 2);

        // Server JSON
        if (this.serverData) {
            document.getElementById('serverJson').textContent = JSON.stringify(this.serverData, null, 2);
        }
    }

    copyToClipboard(text, btnOrId) {
        const btn = typeof btnOrId === 'string' ? document.getElementById(btnOrId) : btnOrId;

        if (!text || text === '-' || text === 'null') {
            return;
        }

        navigator.clipboard.writeText(text).then(() => {
            if (btn) {
                btn.classList.add('copied');
                const span = btn.querySelector('span');
                const originalText = span?.textContent;
                if (span) {
                    span.textContent = 'Copied!';
                }
                setTimeout(() => {
                    btn.classList.remove('copied');
                    if (span && originalText) {
                        span.textContent = originalText;
                    }
                }, 2000);
            }
        }).catch(err => {
            console.error('Copy failed:', err);
        });
    }

    toggleTheme() {
        const current = document.documentElement.getAttribute('data-theme');
        const isDark = current === 'dark' ||
            (!current && window.matchMedia('(prefers-color-scheme: dark)').matches);
        const next = isDark ? 'light' : 'dark';
        document.documentElement.setAttribute('data-theme', next);
        localStorage.setItem('fingerprint-theme', next);
    }
}

// 启动应用
new FingerprintApp();
