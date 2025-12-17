/**
 * Canvas Collector
 * 收集 Canvas 指纹
 * 参考 FingerprintJS 实现
 */

import { murmurHash3 } from '../utils/murmur.js';

/**
 * 检测 Canvas winding 规则支持
 * @param {CanvasRenderingContext2D} ctx
 * @returns {boolean}
 */
function detectWinding(ctx) {
    ctx.rect(0, 0, 10, 10);
    ctx.rect(2, 2, 6, 6);
    return !ctx.isPointInPath(5, 5, 'evenodd');
}

/**
 * 绘制文本测试图案（与 FingerprintJS 兼容）
 * @param {HTMLCanvasElement} canvas
 * @param {CanvasRenderingContext2D} ctx
 */
function drawTextPattern(canvas, ctx) {
    canvas.width = 240;
    canvas.height = 60;

    ctx.textBaseline = 'alphabetic';
    ctx.fillStyle = '#f60';
    ctx.fillRect(100, 1, 62, 20);

    ctx.fillStyle = '#069';
    ctx.font = '11pt "Times New Roman"';
    // 使用与 FingerprintJS 相同的测试字符串（包含 emoji）
    const text = `Cwm fjordbank gly ${String.fromCharCode(55357, 56835)}`;
    ctx.fillText(text, 2, 15);

    ctx.fillStyle = 'rgba(102, 204, 0, 0.2)';
    ctx.font = '18pt Arial';
    ctx.fillText(text, 4, 45);
}

/**
 * 绘制几何测试图案（与 FingerprintJS 兼容）
 * @param {HTMLCanvasElement} canvas
 * @param {CanvasRenderingContext2D} ctx
 */
function drawGeometryPattern(canvas, ctx) {
    canvas.width = 122;
    canvas.height = 110;

    ctx.globalCompositeOperation = 'multiply';

    // 绘制三个重叠的圆
    const circles = [
        ['#f2f', 40, 40],
        ['#2ff', 80, 40],
        ['#ff2', 60, 80],
    ];

    for (const [color, x, y] of circles) {
        ctx.fillStyle = color;
        ctx.beginPath();
        ctx.arc(x, y, 40, 0, 2 * Math.PI, true);
        ctx.closePath();
        ctx.fill();
    }

    // 绘制 evenodd 填充的圆环
    ctx.fillStyle = '#f9c';
    ctx.arc(60, 60, 60, 0, 2 * Math.PI, true);
    ctx.arc(60, 60, 20, 0, 2 * Math.PI, true);
    ctx.fill('evenodd');
}

/**
 * 收集 Canvas 指纹
 * @returns {Object} Canvas 指纹数据
 */
export async function collectCanvas() {
    const canvas = document.createElement('canvas');
    canvas.width = 1;
    canvas.height = 1;
    const ctx = canvas.getContext('2d');

    if (!ctx || !canvas.toDataURL) {
        return {
            winding: false,
            geometry: 'unsupported',
            text: 'unsupported',
        };
    }

    // 检测 winding 支持
    const winding = detectWinding(ctx);

    // 绘制文本图案并获取哈希
    drawTextPattern(canvas, ctx);
    const textDataURL = canvas.toDataURL();

    // 检查稳定性
    const textDataURL2 = canvas.toDataURL();
    if (textDataURL !== textDataURL2) {
        return {
            winding,
            geometry: 'unstable',
            text: 'unstable',
        };
    }

    // 绘制几何图案并获取哈希
    drawGeometryPattern(canvas, ctx);
    const geometryDataURL = canvas.toDataURL();

    // 计算哈希
    const textHash = murmurHash3(textDataURL);
    const geometryHash = murmurHash3(geometryDataURL);

    // 显示预览（使用几何图案，更直观）
    const preview = document.getElementById('canvasPreview');
    if (preview) {
        preview.innerHTML = '';
        // 创建新 canvas 用于预览
        const previewCanvas = document.createElement('canvas');
        previewCanvas.width = 122;
        previewCanvas.height = 110;
        const previewCtx = previewCanvas.getContext('2d');
        if (previewCtx) {
            drawGeometryPattern(previewCanvas, previewCtx);
            preview.appendChild(previewCanvas);
        }
    }

    return {
        winding,
        geometry: geometryHash,
        text: textHash,
        // 兼容旧版本
        hash: geometryHash,
        dataURL: geometryDataURL.substring(0, 100) + '...',
    };
}
