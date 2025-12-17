/**
 * API Utilities
 * 处理与后端的通信
 */

let config = null;

/**
 * 加载配置
 * @returns {Promise<Object>} 配置对象
 */
export async function loadConfig() {
    if (config) return config;

    try {
        const response = await fetch('/api/config');
        config = await response.json();
    } catch (e) {
        // 使用默认配置
        config = {
            tls_url: 'https://localhost:8443',
            api_url: 'https://localhost:8443/api/fingerprint',
        };
    }
    return config;
}

/**
 * 获取配置
 * @returns {Object|null} 配置对象
 */
export function getConfig() {
    return config;
}

/**
 * 发送指纹数据到服务器
 * @param {Object} fingerprint - 指纹数据
 * @returns {Promise<Object>} 服务器响应
 */
export async function sendFingerprint(fingerprint) {
    const response = await fetch('/api/collect', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
        },
        body: JSON.stringify(fingerprint),
    });
    return response.json();
}

/**
 * 获取 IP 详细信息
 * @returns {Promise<Object>} IP 信息
 */
export async function fetchIpInfo() {
    const response = await fetch('/api/ip-info');
    return response.json();
}

/**
 * 查询指定 IP 的位置信息
 * @param {string} ip - IP 地址
 * @returns {Promise<Object>} IP 位置信息
 */
export async function lookupIp(ip) {
    const response = await fetch(`/api/ip-info/${ip}`);
    return response.json();
}

/**
 * 获取 TLS 指纹
 * @returns {Promise<Object>} TLS 指纹数据
 */
export async function fetchTlsFingerprint() {
    const cfg = await loadConfig();
    const tlsApiUrl = cfg?.api_url || 'https://localhost:8443/api/fingerprint';
    const response = await fetch(tlsApiUrl);
    return response.json();
}
