/**
 * 浏览器指纹收集器 - 主入口
 * ES Modules 版本
 */

// 工具模块
import { calculateHash } from './utils/hash.js';
import { loadConfig, sendFingerprint, fetchIpInfo, lookupIp, fetchTlsFingerprint } from './utils/api.js';

// 收集器模块
import {
    collectNavigator,
    collectScreen,
    collectCanvas,
    collectWebGL,
    collectAudio,
    collectFonts,
    detectIncognito,
    detectAutomation,
    collectFeatures,
    collectTiming,
    collectStorage,
    collectPlugins,
    collectMimeTypes,
    getWebRtcIps
} from './collectors/index.js';

// UI 模块
import { setStatus } from './ui/status.js';
import { displayResults, displayServerResult, displayIpInfo, displayWebRtcIp, displayTlsInfo } from './ui/display.js';
import { showTlsToast, updateTlsLink } from './ui/toast.js';
import { initTheme, bindThemeToggle } from './ui/theme.js';

/**
 * 指纹收集器应用
 */
class FingerprintApp {
    constructor() {
        this.fingerprint = {};
        this.config = null;
    }

    /**
     * 初始化应用
     */
    async init() {
        this.config = await loadConfig();
        this.bindEvents();
        updateTlsLink(this.config);
        showTlsToast(this.config);
    }

    /**
     * 绑定事件
     */
    bindEvents() {
        document.getElementById('collectBtn').addEventListener('click', () => this.collect());
        document.getElementById('getTlsBtn').addEventListener('click', () => this.getTlsFingerprint());
        document.getElementById('exportBtn').addEventListener('click', () => this.exportJSON());
        document.getElementById('copyDataBtn').addEventListener('click', () => this.copyJSON());
    }

    /**
     * 收集指纹
     */
    async collect() {
        setStatus('正在收集指纹...', 'loading');

        try {
            // 启动耗时的异步任务（并行执行）
            const incognitoPromise = detectIncognito();
            const canvasPromise = collectCanvas();
            const audioPromise = collectAudio();
            const tlsPromise = fetchTlsFingerprint(this.config);

            // 收集同步数据
            this.fingerprint = {
                timestamp: new Date().toISOString(),
                navigator: collectNavigator(),
                screen: collectScreen(),
                webgl: collectWebGL(),
                fonts: collectFonts(),
                automation: detectAutomation(),
                features: collectFeatures(),
                timing: collectTiming(),
                storage: collectStorage(),
                plugins: collectPlugins(),
                mimeTypes: collectMimeTypes(),
            };

            // 等待并行任务完成
            const [canvas, audio, incognito, tlsResult] = await Promise.all([
                canvasPromise,
                audioPromise,
                incognitoPromise,
                tlsPromise.catch(() => null), // TLS 失败不影响主流程
            ]);

            // 合并异步结果
            this.fingerprint.canvas = canvas;
            this.fingerprint.audio = audio;
            this.fingerprint.incognito = incognito;

            // 处理 TLS 指纹
            if (tlsResult && tlsResult.success) {
                this.fingerprint.tls = tlsResult.fingerprint;
                displayTlsInfo(tlsResult);
            }

            // 计算指纹哈希
            this.fingerprint.hash = await calculateHash(JSON.stringify(this.fingerprint));

            // 显示结果
            displayResults(this.fingerprint);

            // 发送到服务器
            const serverResult = await sendFingerprint(this.fingerprint);
            displayServerResult(serverResult);

            // 获取 IP 详细信息
            setStatus('正在查询 IP 信息...', 'loading');
            const ipResult = await fetchIpInfo();
            if (ipResult && ipResult.success) {
                displayIpInfo(ipResult.ip_info);
            }

            // 获取 WebRTC IP
            await this.fetchWebRtcIp();

            setStatus('指纹收集完成!', 'success');
        } catch (error) {
            console.error('收集失败:', error);
            setStatus(`收集失败: ${error.message}`, 'error');
        }
    }

    /**
     * 获取 WebRTC IP
     */
    async fetchWebRtcIp() {
        try {
            const ips = await getWebRtcIps();

            // 显示 WebRTC 本地 IP
            if (ips.local.length > 0) {
                const localIp = ips.local[0];
                displayWebRtcIp('webrtcIp', localIp);
                // 查询 IP 位置
                const location = await this.lookupIpLocation(localIp);
                if (location) {
                    displayWebRtcIp('webrtcIp', localIp, location);
                }
            } else {
                displayWebRtcIp('webrtcIp', '未检测到');
            }

            // 显示 WebRTC STUN IP
            if (ips.public.length > 0) {
                const publicIp = ips.public[0];
                displayWebRtcIp('webrtcStun', publicIp);
                // 查询 IP 位置
                const location = await this.lookupIpLocation(publicIp);
                if (location) {
                    displayWebRtcIp('webrtcStun', publicIp, location);
                }
            } else {
                displayWebRtcIp('webrtcStun', '未检测到');
            }
        } catch (error) {
            console.log('WebRTC IP 检测失败:', error.message);
            displayWebRtcIp('webrtcIp', '不支持/已禁用');
            displayWebRtcIp('webrtcStun', '不支持/已禁用');
        }
    }

    /**
     * 查询 IP 位置
     */
    async lookupIpLocation(ip) {
        try {
            const result = await lookupIp(ip);
            if (result && result.success && result.ip_info) {
                const info = result.ip_info;
                if (info.country !== '本地网络' && info.country !== '查询失败') {
                    return info.city || info.country;
                }
            }
        } catch (error) {
            // 忽略查询错误
        }
        return null;
    }

    /**
     * 单独获取 TLS 指纹
     */
    async getTlsFingerprint() {
        setStatus('正在获取 TLS 指纹...', 'loading');

        try {
            const tlsResult = await fetchTlsFingerprint(this.config);
            if (tlsResult && tlsResult.success) {
                this.fingerprint.tls = tlsResult.fingerprint;
                displayTlsInfo(tlsResult);
                setStatus('TLS 指纹获取成功!', 'success');
            } else {
                setStatus('TLS 指纹获取失败', 'error');
            }
        } catch (error) {
            console.error('TLS 获取失败:', error);
            setStatus(`TLS 获取失败: ${error.message}`, 'error');
        }
    }

    /**
     * 导出 JSON
     */
    exportJSON() {
        const data = JSON.stringify(this.fingerprint, null, 2);
        const blob = new Blob([data], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `fingerprint-${Date.now()}.json`;
        a.click();
        URL.revokeObjectURL(url);
    }

    /**
     * 复制 JSON 到剪贴板
     */
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
}

// 初始化应用
function initApp() {
    // 初始化主题（优先执行避免闪烁）
    initTheme();
    bindThemeToggle();

    // 初始化指纹收集器
    const app = new FingerprintApp();
    app.init();
}

// ES modules 是 deferred 的，DOM 可能已经加载完成
if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initApp);
} else {
    initApp();
}
