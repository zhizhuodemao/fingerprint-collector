/**
 * Fonts Collector
 * 检测已安装字体
 */

// 测试字体列表
const TEST_FONTS = [
    'Arial', 'Arial Black', 'Arial Narrow', 'Calibri', 'Cambria',
    'Cambria Math', 'Comic Sans MS', 'Consolas', 'Courier', 'Courier New',
    'Georgia', 'Helvetica', 'Impact', 'Lucida Console', 'Lucida Sans Unicode',
    'Microsoft Sans Serif', 'MS Gothic', 'MS PGothic', 'MS Sans Serif',
    'MS Serif', 'Palatino Linotype', 'Segoe Print', 'Segoe Script',
    'Segoe UI', 'Segoe UI Light', 'Segoe UI Semibold', 'Segoe UI Symbol',
    'Tahoma', 'Times', 'Times New Roman', 'Trebuchet MS', 'Verdana',
    'Wingdings', 'Wingdings 2', 'Wingdings 3',
    // 中文字体
    'SimHei', 'SimSun', 'NSimSun', 'FangSong', 'KaiTi', 'Microsoft YaHei',
    'Microsoft JhengHei', 'PMingLiU', 'MingLiU',
    // macOS 字体
    'Apple Braille', 'Apple Chancery', 'Apple Color Emoji', 'Apple SD Gothic Neo',
    'Apple Symbols', 'AppleGothic', 'AppleMyungjo', 'Avenir', 'Avenir Next',
    'Baskerville', 'Big Caslon', 'Brush Script MT', 'Chalkboard',
    'Chalkboard SE', 'Chalkduster', 'Charter', 'Cochin', 'Copperplate',
    'Didot', 'Futura', 'Geneva', 'Gill Sans', 'Helvetica Neue',
    'Herculanum', 'Hoefler Text', 'Lucida Grande', 'Luminari', 'Marker Felt',
    'Menlo', 'Monaco', 'Noteworthy', 'Optima', 'Palatino', 'Papyrus',
    'Phosphate', 'PingFang SC', 'PingFang TC', 'PingFang HK',
    'Rockwell', 'Savoye LET', 'SignPainter', 'Skia', 'Snell Roundhand',
    'STHeiti', 'STXihei', 'Zapfino',
];

const BASE_FONTS = ['monospace', 'sans-serif', 'serif'];

/**
 * 收集字体指纹
 * @returns {Object} 字体指纹数据
 */
export function collectFonts() {
    const testString = 'mmmmmmmmmmlli';
    const testSize = '72px';

    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d');

    // 获取基础字体宽度
    const getWidth = (font) => {
        ctx.font = `${testSize} ${font}`;
        return ctx.measureText(testString).width;
    };

    const baseWidths = {};
    BASE_FONTS.forEach(font => {
        baseWidths[font] = getWidth(font);
    });

    // 检测字体
    const detectedFonts = [];
    TEST_FONTS.forEach(font => {
        for (const baseFont of BASE_FONTS) {
            const width = getWidth(`'${font}', ${baseFont}`);
            if (width !== baseWidths[baseFont]) {
                detectedFonts.push(font);
                break;
            }
        }
    });

    // 显示字体
    const fontsDiv = document.getElementById('fontsInfo');
    if (fontsDiv) {
        fontsDiv.innerHTML = detectedFonts.map(f =>
            `<span class="font-tag detected">${f}</span>`
        ).join('');
    }

    return {
        detected: detectedFonts,
        count: detectedFonts.length,
    };
}
