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
        this.consistencyTippy = null;
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

                // Handle both old format (direct ja4) and new format (tls.ja4)
                const tlsObj = this.tlsData.tls || this.tlsData;
                const tlsId = tlsObj?.ja4?.substring(0, 16) ||
                              tlsObj?.ja3_hash?.substring(0, 16) || '-';
                document.getElementById('tlsId').textContent = tlsId;

                // Update HTTP/2 ID if present
                const http2IdEl = document.getElementById('http2Id');
                if (http2IdEl && this.tlsData.http2) {
                    const http2Id = this.tlsData.http2.akamai_hash?.substring(0, 16) || '-';
                    http2IdEl.textContent = http2Id;
                }

                // Update TCP/IP ID if present
                const tcpIdEl = document.getElementById('tcpId');
                if (tcpIdEl && this.tlsData.tcp) {
                    tcpIdEl.textContent = this.tlsData.tcp.inferred_os || '-';
                    if (this.tlsData.tcp.anomalies && this.tlsData.tcp.anomalies.length > 0) {
                        tcpIdEl.style.color = '#e74c3c';
                        tcpIdEl.title = this.tlsData.tcp.anomalies.join('\n');
                    } else {
                        tcpIdEl.title = `TTL: ${this.tlsData.tcp.ttl}, Window: ${this.tlsData.tcp.window_size}`;
                    }
                }

                // 恢复 TLS 摘要卡片
                document.getElementById('tlsSummaryCard').style.display = 'block';
                this.updateTlsSummary(this.tlsData);

                // 恢复一致性校验状态
                this.updateConsistencyCheck(this.tlsData.tcp);
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
        document.getElementById('fetchTlsBtn2')?.addEventListener('click', () => this.fetchTls());

        // 主题切换
        document.getElementById('themeToggle')?.addEventListener('click', () => this.toggleTheme());

        // 折叠卡片切换
        document.querySelectorAll('.card-toggle').forEach(header => {
            header.addEventListener('click', (e) => {
                // 如果点击的是按钮，不触发折叠
                if (e.target.closest('button')) return;
                const card = header.closest('.card-collapsible');
                if (card) {
                    card.classList.toggle('collapsed');
                }
            });
        });

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
                // New response format: fingerprint contains { tls, http2, tcp }
                const fpData = result.fingerprint;

                // Store TLS, HTTP/2, and TCP data
                this.tlsData = {
                    tls: fpData.tls,
                    http2: fpData.http2,
                    tcp: fpData.tcp
                };

                document.getElementById('tlsJson').textContent = JSON.stringify(this.tlsData, null, 2);

                // 更新 TLS ID (优先使用 JA4，更稳定)
                const tlsId = fpData.tls?.ja4?.substring(0, 16) ||
                              fpData.tls?.ja3_hash?.substring(0, 16) || '-';
                document.getElementById('tlsId').textContent = tlsId;

                // 更新 HTTP/2 ID (如果有)
                const http2IdEl = document.getElementById('http2Id');
                if (http2IdEl && fpData.http2) {
                    const http2Id = fpData.http2.akamai_hash?.substring(0, 16) || '-';
                    http2IdEl.textContent = http2Id;
                }

                // 更新 TCP/IP ID (如果有)
                const tcpIdEl = document.getElementById('tcpId');
                if (tcpIdEl) {
                    if (fpData.tcp) {
                        // 显示推断的 OS 和置信度
                        const tcpInfo = fpData.tcp.inferred_os || 'Unknown';
                        tcpIdEl.textContent = tcpInfo;
                        // 如果有异常，添加警告样式
                        if (fpData.tcp.anomalies && fpData.tcp.anomalies.length > 0) {
                            tcpIdEl.style.color = '#e74c3c';
                            tcpIdEl.title = fpData.tcp.anomalies.join('\n');
                        } else {
                            tcpIdEl.style.color = '';
                            tcpIdEl.title = `TTL: ${fpData.tcp.ttl}, Window: ${fpData.tcp.window_size}`;
                        }
                    } else {
                        tcpIdEl.textContent = '-';
                        tcpIdEl.title = 'TCP fingerprinting requires sudo';
                    }
                }

                // 更新 TLS 摘要卡片
                this.updateTlsSummary(fpData);

                // 更新一致性校验状态
                this.updateConsistencyCheck(fpData.tcp);

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
        document.getElementById('tlsSummaryCard').style.display = 'block';
        document.getElementById('browserCard').style.display = 'block';
        document.getElementById('tlsCard').style.display = 'block';
        document.getElementById('serverCard').style.display = 'block';

        // Device ID
        const deviceId = this.fingerprint.deviceId;
        document.getElementById('deviceCoreId').textContent = deviceId?.coreId || '-';
        document.getElementById('tlsId').textContent = result.tls_id || '-';
        document.getElementById('collectedAt').textContent = new Date().toLocaleString('zh-CN');

        // 一致性校验状态 - 等待 TLS 数据后更新
        const consistencyEl = document.getElementById('consistencyStatus');
        consistencyEl.textContent = 'Checking...';
        consistencyEl.className = 'consistency-status';

        // Browser JSON (不包含 deviceId，避免重复)
        const browserData = { ...this.fingerprint };
        delete browserData.deviceId;
        document.getElementById('browserJson').textContent = JSON.stringify(browserData, null, 2);

        // Server JSON
        if (this.serverData) {
            document.getElementById('serverJson').textContent = JSON.stringify(this.serverData, null, 2);
        }
    }

    // 更新 TLS 摘要卡片
    updateTlsSummary(fpData) {
        if (!fpData) return;

        const tls = fpData.tls || {};
        const http2 = fpData.http2 || {};
        const tcp = fpData.tcp || {};

        // TLS 字段
        document.getElementById('tlsJa4').textContent = tls.ja4 || '-';
        document.getElementById('tlsJa3Hash').textContent = tls.ja3_hash || '-';
        document.getElementById('tlsVersion').textContent = tls.tls_version_negotiated || '-';
        document.getElementById('tlsAlpn').textContent = (tls.alpn || []).join(', ') || '-';

        // HTTP/2 字段
        document.getElementById('http2Akamai').textContent = http2.akamai || '-';
        document.getElementById('http2AkamaiHash').textContent = http2.akamai_hash || '-';

        // TCP 字段
        document.getElementById('tcpTtl').textContent = tcp.ttl ? `${tcp.ttl} (初始: ${tcp.initial_ttl})` : '-';
        document.getElementById('tcpWindow').textContent = tcp.window_size || '-';
        document.getElementById('tcpOptions').textContent = tcp.options_str || '-';
        document.getElementById('tcpUptime').textContent = tcp.timestamp?.uptime || '-';
    }

    // 更新一致性校验状态
    updateConsistencyCheck(tcp) {
        const consistencyEl = document.getElementById('consistencyStatus');
        const anomaliesContainer = document.getElementById('anomaliesContainer');
        const anomaliesList = document.getElementById('anomaliesList');

        // 构建 Tippy tooltip
        const tooltipContent = this.buildConsistencyTooltipContent(tcp);
        this.initConsistencyTippy(consistencyEl, tooltipContent);

        if (!tcp) {
            consistencyEl.textContent = 'N/A';
            consistencyEl.className = 'consistency-status';
            anomaliesContainer.style.display = 'none';
            return;
        }

        const anomalies = tcp.anomalies || [];

        if (anomalies.length === 0) {
            consistencyEl.textContent = '✓ PASS';
            consistencyEl.className = 'consistency-status pass';
            anomaliesContainer.style.display = 'none';
        } else {
            consistencyEl.textContent = '✗ FAIL';
            consistencyEl.className = 'consistency-status fail';

            // 显示异常列表
            anomaliesList.innerHTML = anomalies.map(a => `<li>${a}</li>`).join('');
            anomaliesContainer.style.display = 'block';
        }
    }

    // 初始化/更新 Tippy tooltip
    initConsistencyTippy(element, content) {
        if (this.consistencyTippy) {
            this.consistencyTippy.setContent(content);
        } else if (typeof tippy !== 'undefined') {
            this.consistencyTippy = tippy(element, {
                content: content,
                allowHTML: true,
                theme: 'consistency',
                placement: 'top',
                arrow: true,
                animation: 'shift-away',
                interactive: true,
                appendTo: document.body,
                maxWidth: 400,
                trigger: 'mouseenter focus',
                hideOnClick: false,
            });
        }
    }

    // 构建 Tippy tooltip 内容
    buildConsistencyTooltipContent(tcp) {
        const checkIcon = `<svg class="check-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="20 6 9 17 4 12"/></svg>`;
        const failIcon = `<svg class="check-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>`;
        const infoIcon = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><line x1="12" y1="16" x2="12" y2="12"/><line x1="12" y1="8" x2="12.01" y2="8"/></svg>`;
        const successIcon = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>`;
        const warningIcon = `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>`;

        if (!tcp) {
            return `
                <div class="tooltip-header neutral">
                    ${infoIcon}
                    <span>无 TCP 数据</span>
                </div>
                <div class="tooltip-note">
                    TCP/IP 指纹采集需要以 sudo 权限启动服务端<br>
                    <code style="font-size: 0.7rem;">ENABLE_TCP=1 python app.py</code>
                </div>
            `;
        }

        const anomalies = tcp.anomalies || [];
        const checks = this.buildConsistencyChecks(tcp, anomalies);
        const passed = anomalies.length === 0;

        const headerClass = passed ? 'pass' : 'fail';
        const headerIcon = passed ? successIcon : warningIcon;
        const headerText = passed ? '所有校验通过' : `检测到 ${anomalies.length} 项异常`;

        const checksList = checks.map(c => {
            if (c.failed) {
                return `
                    <li>
                        <span class="check-fail">${failIcon}</span>
                        <div>
                            <div class="check-name">${c.name}</div>
                            <div class="check-reason">${c.reason}</div>
                        </div>
                    </li>
                `;
            }
            return `
                <li>
                    <span class="check-pass">${checkIcon}</span>
                    <span class="check-name">${c.name}</span>
                </li>
            `;
        }).join('');

        let content = `
            <div class="tooltip-header ${headerClass}">
                ${headerIcon}
                <span>${headerText}</span>
            </div>
            <ul class="tooltip-checks">${checksList}</ul>
        `;

        // 添加额外信息
        if (tcp.inferred_os) {
            content += `
                <div class="tooltip-note">
                    推断 OS: <strong>${tcp.inferred_os}</strong> (${tcp.os_confidence || 'unknown'})
                </div>
            `;
        }

        return content;
    }

    // 构建校验项列表
    buildConsistencyChecks(tcp, anomalies) {
        const checks = [
            { name: 'OS 一致性', key: 'OS_MISMATCH', desc: 'User-Agent 与 TCP 指纹匹配' },
            { name: 'TCP Timestamp', key: 'TCP_TIMESTAMP', desc: '时间戳选项正常' },
            { name: '窗口大小', key: 'DEFAULT_WINDOW', desc: '非默认窗口大小' },
            { name: '系统运行时长', key: 'SHORT_UPTIME', desc: 'Uptime 正常' },
            { name: 'TCP 选项', key: 'MINIMAL_OPTIONS', desc: '选项数量正常' }
        ];

        return checks.map(check => {
            const failedAnomaly = anomalies.find(a => a.includes(check.key));
            if (failedAnomaly) {
                // 提取失败原因
                const reason = failedAnomaly.split(':').slice(1).join(':').trim() || '异常';
                return { ...check, failed: true, reason };
            }
            return { ...check, failed: false };
        });
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
