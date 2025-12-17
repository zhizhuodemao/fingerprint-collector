/**
 * Screen Collector
 * 收集屏幕相关信息
 */

/**
 * 收集屏幕信息
 * @returns {Object} 屏幕指纹数据
 */
export function collectScreen() {
    const screen = window.screen;
    return {
        width: screen.width,
        height: screen.height,
        availWidth: screen.availWidth,
        availHeight: screen.availHeight,
        colorDepth: screen.colorDepth,
        pixelDepth: screen.pixelDepth,
        devicePixelRatio: window.devicePixelRatio,
        orientation: screen.orientation ? {
            type: screen.orientation.type,
            angle: screen.orientation.angle,
        } : null,
        innerWidth: window.innerWidth,
        innerHeight: window.innerHeight,
        outerWidth: window.outerWidth,
        outerHeight: window.outerHeight,
        screenX: window.screenX,
        screenY: window.screenY,
    };
}
