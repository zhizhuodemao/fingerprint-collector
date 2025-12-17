/**
 * Device ID Generator
 * 基于稳定信号生成跨环境一致的设备唯一标识
 * 参考 FingerprintJS 实现
 *
 * 设计原则：
 * - 核心信号：与硬件强相关、不受 HTTPS 限制
 * - 分层架构：coreId（最稳定）+ extendedId（更精确）
 */

import { murmurHash3, hashComponents } from './murmur.js';

/**
 * 信号权重配置（参考 FingerprintJS）
 */
const SIGNAL_WEIGHTS = {
    // 核心信号（必须稳定，不受 HTTPS 影响）
    audio: 20,
    canvasGeometry: 15,
    canvasText: 10,
    webglRenderer: 20,
    webglVendor: 10,
    fonts: 10,
    math: 10,
    // 环境信号（辅助）
    screen: 2,
    colorDepth: 1,
    timezone: 2,
    platform: 1,
    hardwareConcurrency: 1,
};

/**
 * 从收集的指纹数据中提取稳定信号
 * @param {Object} fingerprint - 完整指纹数据
 * @returns {Object} 稳定信号集合
 */
export function collectStableSignals(fingerprint) {
    const signals = {
        // === 核心信号（硬件相关，跨 HTTP/HTTPS 一致）===

        // Audio 指纹
        audio: fingerprint.audio?.fingerprint || null,

        // Canvas 指纹（分离 geometry 和 text）
        canvasGeometry: fingerprint.canvas?.geometry || fingerprint.canvas?.hash || null,
        canvasText: fingerprint.canvas?.text || null,

        // WebGL 指纹
        webglRenderer: fingerprint.webgl?.unmaskedRenderer || fingerprint.webgl?.renderer || null,
        webglVendor: fingerprint.webgl?.unmaskedVendor || fingerprint.webgl?.vendor || null,

        // 字体列表哈希
        fonts: fingerprint.fonts ? hashArray(fingerprint.fonts) : null,

        // 数学计算精度
        math: fingerprint.math?.fingerprint || null,

        // === 环境信号（辅助判断）===
        screen: `${screen.width}x${screen.height}`,
        colorDepth: screen.colorDepth,
        deviceMemory: navigator.deviceMemory || null,
        hardwareConcurrency: navigator.hardwareConcurrency || null,
        timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
        languages: navigator.languages ? navigator.languages.join(',') : navigator.language,
        platform: navigator.platform,
    };

    return signals;
}

/**
 * 生成设备唯一标识（使用 MurmurHash3）
 * @param {Object} signals - 稳定信号集合
 * @returns {Object} 设备ID信息
 */
export function generateDeviceId(signals) {
    // 核心数据（最稳定，跨 HTTP/HTTPS 一致）
    const coreComponents = {
        audio: signals.audio,
        canvasGeometry: signals.canvasGeometry,
        canvasText: signals.canvasText,
        webglRenderer: signals.webglRenderer,
        webglVendor: signals.webglVendor,
        math: signals.math,
    };

    // 扩展数据（更精确，包含环境信息）
    const extendedComponents = {
        ...coreComponents,
        fonts: signals.fonts,
        screen: signals.screen,
        colorDepth: signals.colorDepth,
        timezone: signals.timezone,
        platform: signals.platform,
        hardwareConcurrency: signals.hardwareConcurrency,
    };

    // 使用 FingerprintJS 兼容的哈希方式生成 ID
    const coreId = hashComponents(coreComponents);
    const extendedId = hashComponents(extendedComponents);

    // 计算置信度
    const confidence = calculateConfidence(signals);

    return {
        coreId: coreId.substring(0, 32),
        extendedId: extendedId.substring(0, 32),
        fullCoreId: coreId,
        fullExtendedId: extendedId,
        confidence,
        signals,
    };
}

/**
 * 计算指纹置信度
 * @param {Object} signals - 信号集合
 * @returns {number} 置信度百分比 (0-100)
 */
function calculateConfidence(signals) {
    let score = 0;
    let maxScore = 0;

    for (const [key, weight] of Object.entries(SIGNAL_WEIGHTS)) {
        maxScore += weight;
        if (signals[key] !== null && signals[key] !== undefined && signals[key] !== '') {
            score += weight;
        }
    }

    return Math.round((score / maxScore) * 100);
}

/**
 * 将数组转为哈希字符串
 * @param {Array} arr - 数组
 * @returns {string} 哈希字符串
 */
function hashArray(arr) {
    if (!Array.isArray(arr)) return null;
    return murmurHash3(arr.sort().join('|'));
}

/**
 * 比较两个设备指纹的相似度
 * @param {Object} signals1 - 第一个设备的信号
 * @param {Object} signals2 - 第二个设备的信号
 * @returns {Object} 匹配结果
 */
export function compareDevices(signals1, signals2) {
    // 核心信号匹配
    const coreKeys = ['audio', 'canvasGeometry', 'canvasText', 'webglRenderer', 'math'];
    const coreMatches = {};
    let coreMatchCount = 0;

    for (const key of coreKeys) {
        const match = signals1[key] === signals2[key] && signals1[key] !== null;
        coreMatches[key] = match;
        if (match) coreMatchCount++;
    }

    const totalCore = coreKeys.length;

    // 环境信号匹配
    const envKeys = ['screen', 'colorDepth', 'timezone', 'platform', 'hardwareConcurrency'];
    let envMatches = 0;
    let envTotal = 0;

    for (const key of envKeys) {
        if (signals1[key] && signals2[key]) {
            envTotal++;
            if (signals1[key] === signals2[key]) {
                envMatches++;
            }
        }
    }

    const envSimilarity = envTotal > 0 ? envMatches / envTotal : 0;

    // 判断匹配类型
    let matchType = 'different';
    let confidence = 0;

    if (coreMatchCount === totalCore) {
        matchType = 'exact';
        confidence = 95 + (envSimilarity * 5);
    } else if (coreMatchCount >= 4) {
        matchType = 'fuzzy_core';
        confidence = 80 + (coreMatchCount - 4) * 5 + (envSimilarity * 5);
    } else if (coreMatchCount >= 3) {
        matchType = 'fuzzy_core';
        confidence = 70 + (coreMatchCount - 3) * 5 + (envSimilarity * 5);
    } else if (coreMatchCount >= 2 && envSimilarity > 0.6) {
        matchType = 'fuzzy_env';
        confidence = 50 + envSimilarity * 20;
    }

    return {
        matchType,
        confidence: Math.min(100, Math.round(confidence)),
        coreMatches,
        coreMatchCount,
        envSimilarity: Math.round(envSimilarity * 100),
    };
}
