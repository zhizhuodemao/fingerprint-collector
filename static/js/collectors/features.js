/**
 * Features Collector
 * 收集浏览器特性支持情况
 */

/**
 * 收集浏览器特性
 * @returns {Object} 特性支持情况
 */
export function collectFeatures() {
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

/**
 * 收集时间相关信息
 * @returns {Object} 时间信息
 */
export function collectTiming() {
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

/**
 * 收集存储信息
 * @returns {Object} 存储支持情况
 */
export function collectStorage() {
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

/**
 * 收集插件信息
 * @returns {Object} 插件信息
 */
export function collectPlugins() {
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

/**
 * 收集 MIME 类型
 * @returns {Object} MIME 类型信息
 */
export function collectMimeTypes() {
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
