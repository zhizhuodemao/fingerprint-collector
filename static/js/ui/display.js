/**
 * Display UI Module
 * 管理指纹数据显示
 */

/**
 * 显示指纹收集结果
 * @param {Object} fingerprint - 指纹数据
 */
export function displayResults(fingerprint) {
    // 摘要
    document.getElementById('summaryCard').style.display = 'block';
    // 初始显示等待服务端返回
    document.getElementById('browserId').textContent = '收集中...';
    document.getElementById('tlsId').textContent = '-';
    document.getElementById('combinedId').textContent = '-';

    // 格式化时间显示
    const timestamp = fingerprint.timestamp ? new Date(fingerprint.timestamp).toLocaleString('zh-CN') : '-';
    document.getElementById('fpTime').textContent = timestamp;

    // 基础信息
    document.getElementById('basicInfo').textContent = JSON.stringify(fingerprint.navigator, null, 2);

    // 屏幕信息
    document.getElementById('screenInfo').textContent = JSON.stringify(fingerprint.screen, null, 2);

    // Canvas 信息
    document.getElementById('canvasInfo').textContent = JSON.stringify(fingerprint.canvas, null, 2);

    // WebGL 信息
    const webglData = { ...fingerprint.webgl };
    if (webglData.extensions) {
        webglData.extensionsCount = webglData.extensions.length;
        webglData.extensions = webglData.extensions.slice(0, 10).join(', ') + '...';
    }
    document.getElementById('webglInfo').textContent = JSON.stringify(webglData, null, 2);

    // 音频信息
    document.getElementById('audioInfo').textContent = JSON.stringify(fingerprint.audio, null, 2);

    // 自动化检测
    document.getElementById('automationInfo').textContent = JSON.stringify(fingerprint.automation, null, 2);

    // 无痕模式检测
    displayIncognitoResult(fingerprint.incognito);

    // 完整数据
    document.getElementById('fullData').textContent = JSON.stringify(fingerprint, null, 2);
}

/**
 * 显示无痕模式检测结果
 * @param {Object} incognito - 无痕模式检测结果
 */
function displayIncognitoResult(incognito) {
    if (!incognito) return;

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

/**
 * 显示服务器响应数据
 * @param {Object} result - 服务器响应
 */
export function displayServerResult(result) {
    if (result.success) {
        document.getElementById('serverInfo').textContent = JSON.stringify(result.fingerprint.server, null, 2);
        document.getElementById('browserId').textContent = result.browser_id || '-';
        document.getElementById('tlsId').textContent = result.tls_id || '未获取';
        document.getElementById('combinedId').textContent = result.combined_id || '-';
    }
}

/**
 * 显示 IP 信息
 * @param {Object} info - IP 信息
 */
export function displayIpInfo(info) {
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
    displayIpFlags(info);
}

/**
 * 显示 IP 标签
 * @param {Object} info - IP 信息
 */
function displayIpFlags(info) {
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

/**
 * 显示 WebRTC IP
 * @param {string} elementId - 元素 ID
 * @param {string} ip - IP 地址
 * @param {string} location - 位置信息
 */
export function displayWebRtcIp(elementId, ip, location = '') {
    const el = document.getElementById(elementId);
    if (location) {
        el.textContent = `${ip} (${location})`;
    } else {
        el.textContent = ip;
    }
}

/**
 * 显示 TLS 指纹
 * @param {Object} tlsData - TLS 数据
 */
export function displayTlsInfo(tlsData) {
    document.getElementById('tlsInfo').textContent = JSON.stringify(tlsData, null, 2);
}
