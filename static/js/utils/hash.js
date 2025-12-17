/**
 * Hash Utilities
 * 提供哈希计算功能
 */

/**
 * 计算 SHA-256 哈希 (使用 Web Crypto API)
 * @param {string} data - 要哈希的数据
 * @returns {Promise<string>} 十六进制哈希字符串
 */
export async function calculateHash(data) {
    // crypto.subtle 只在 HTTPS 或 localhost 下可用
    if (crypto.subtle) {
        const encoder = new TextEncoder();
        const dataBuffer = encoder.encode(data);
        const hashBuffer = await crypto.subtle.digest('SHA-256', dataBuffer);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
    } else {
        // HTTP 环境下使用简单哈希
        return simpleHash(data);
    }
}

/**
 * 简单哈希函数（HTTP 环境备用）
 * @param {string} str - 要哈希的字符串
 * @returns {string} 64位十六进制字符串
 */
export function simpleHash(str) {
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
