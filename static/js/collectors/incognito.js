/**
 * Incognito Detection
 * 检测浏览器无痕/隐私模式
 */

/**
 * 获取浏览器名称
 * @returns {string} 浏览器名称
 */
export function getBrowserName() {
    const ua = navigator.userAgent;
    if (ua.includes('Firefox')) return 'Firefox';
    if (ua.includes('Edg/')) return 'Edge';
    if (ua.includes('OPR/') || ua.includes('Opera')) return 'Opera';
    if (ua.includes('Brave')) return 'Brave';
    if (ua.includes('Chrome')) return 'Chrome';
    if (ua.includes('Safari')) return 'Safari';
    return 'Unknown';
}

/**
 * 检测无痕模式
 * @returns {Promise<Object>} 检测结果
 */
export async function detectIncognito() {
    const result = {
        isIncognito: false,
        confidence: 'low',
        browserName: getBrowserName(),
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
                if (quota && quota < 300000000) {
                    incognitoSignals++;
                }

                // 更精确的检测：对比 performance.memory
                if (window.performance && window.performance.memory) {
                    const heapLimit = window.performance.memory.jsHeapSizeLimit;
                    result.checks.storageQuotaLimit = heapLimit;
                    checksPerformed++;
                    if (quota < heapLimit * 2) {
                        incognitoSignals++;
                    }
                }
            }

            // 方法2: webkitRequestFileSystem
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

            if (incognitoSignals > 0) {
                result.isIncognito = true;
                result.confidence = incognitoSignals >= 2 ? 'high' : 'medium';
            } else if (checksPerformed > 0) {
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
