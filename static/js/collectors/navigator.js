/**
 * Navigator Collector
 * 收集浏览器 Navigator 相关信息
 */

/**
 * 收集网络连接信息
 * @returns {Object|null} 连接信息
 */
function collectConnection() {
    const conn = navigator.connection || navigator.mozConnection || navigator.webkitConnection;
    if (!conn) return null;
    return {
        effectiveType: conn.effectiveType,
        downlink: conn.downlink,
        rtt: conn.rtt,
        saveData: conn.saveData,
    };
}

/**
 * 收集权限 API 信息
 * @returns {Object} 权限信息
 */
function collectPermissions() {
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

/**
 * 收集 Navigator 信息
 * @returns {Object} Navigator 指纹数据
 */
export function collectNavigator() {
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
        connection: collectConnection(),
        permissions: collectPermissions(),
    };
}
