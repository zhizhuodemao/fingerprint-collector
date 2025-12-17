/**
 * Automation Detection
 * 检测自动化/机器人特征
 */

/**
 * 检测自动化特征
 * @returns {Object} 自动化检测结果
 */
export function detectAutomation() {
    const checks = {
        // Webdriver 检测
        webdriver: navigator.webdriver,
        webdriverUndefined: navigator.webdriver === undefined,

        // Chrome 自动化特征
        chromeDriver: !!window.cdc_adoQpoasnfa76pfcZLmcfl_Array,
        chromeDriverUnderscore: !!window._cdc_adoQpoasnfa76pfcZLmcfl_,
        domAutomation: !!window.domAutomation,
        domAutomationController: !!window.domAutomationController,

        // Selenium
        seleniumDocumentKey: !!document.__selenium_evaluate ||
            !!document.__selenium_unwrapped ||
            !!document.__webdriver_evaluate ||
            !!document.__driver_evaluate ||
            !!document.__webdriver_script_function ||
            !!document.__webdriver_script_func ||
            !!document.__webdriver_script_fn ||
            !!document.$chrome_asyncScriptInfo ||
            !!document.$cdc_asdjflasutopfhvcZLmcfl_,

        seleniumWindowKey: !!window._selenium ||
            !!window._Selenium_IDE_Recorder ||
            !!window.callSelenium ||
            !!window.__webdriver_unwrapped ||
            !!window.__selenium_unwrapped,

        // Puppeteer / Playwright
        puppeteer: !!(window._pptrhack || window.__pptr_injected || document.__pptr_injected),

        // PhantomJS
        phantomJS: !!(window.callPhantom || window._phantom || window.phantom),

        // Nightmare
        nightmare: !!window.__nightmare,

        // HeadlessChrome
        headless: /HeadlessChrome/.test(navigator.userAgent),

        // Permissions 异常
        permissionsInconsistent: false,

        // 插件数量异常
        pluginsLengthZero: navigator.plugins.length === 0,

        // Languages 异常
        languagesLengthZero: (navigator.languages || []).length === 0,

        // Chrome 对象检测
        chromeNotExist: typeof window.chrome === 'undefined',
        chromeRuntimeNotExist: !window.chrome?.runtime,

        // 触控事件检测
        touchSupportInconsistent: false,

        // 分辨率异常
        screenResolutionZero: screen.width === 0 || screen.height === 0,
    };

    // 检测 Permission 异常
    if (navigator.permissions) {
        navigator.permissions.query({ name: 'notifications' }).then(result => {
            if (Notification.permission !== 'denied' && result.state === 'denied') {
                checks.permissionsInconsistent = true;
            }
        }).catch(() => {});
    }

    // 触控检测
    const maxTouchPoints = navigator.maxTouchPoints || 0;
    const touchEvent = 'ontouchstart' in window;
    if ((maxTouchPoints > 0) !== touchEvent) {
        checks.touchSupportInconsistent = true;
    }

    // 计算检测评分
    const automationScore = Object.values(checks).filter(v => v === true).length;

    return {
        checks: checks,
        score: automationScore,
        isLikelyAutomated: automationScore > 3,
    };
}
