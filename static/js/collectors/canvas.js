/**
 * Canvas Collector
 * 收集 Canvas 指纹
 */

import { calculateHash } from '../utils/hash.js';

/**
 * 收集 Canvas 指纹
 * @returns {Promise<Object>} Canvas 指纹数据
 */
export async function collectCanvas() {
    const canvas = document.createElement('canvas');
    canvas.width = 300;
    canvas.height = 150;
    const ctx = canvas.getContext('2d');

    // 绘制文本和图形
    ctx.textBaseline = 'top';
    ctx.font = '14px Arial';
    ctx.fillStyle = '#f60';
    ctx.fillRect(125, 1, 62, 20);

    ctx.fillStyle = '#069';
    ctx.fillText('Fingerprint Canvas Test 🎨', 2, 15);

    ctx.fillStyle = 'rgba(102, 204, 0, 0.7)';
    ctx.fillText('Hello, World!', 4, 45);

    // 绘制渐变
    const gradient = ctx.createLinearGradient(0, 0, 300, 0);
    gradient.addColorStop(0, 'red');
    gradient.addColorStop(0.5, 'green');
    gradient.addColorStop(1, 'blue');
    ctx.fillStyle = gradient;
    ctx.fillRect(0, 80, 300, 30);

    // 绘制圆弧
    ctx.beginPath();
    ctx.arc(50, 120, 20, 0, Math.PI * 2, true);
    ctx.closePath();
    ctx.fillStyle = '#ff6b6b';
    ctx.fill();

    // 绘制贝塞尔曲线
    ctx.beginPath();
    ctx.moveTo(100, 100);
    ctx.bezierCurveTo(130, 80, 160, 140, 200, 120);
    ctx.strokeStyle = '#00d4ff';
    ctx.lineWidth = 3;
    ctx.stroke();

    const dataURL = canvas.toDataURL();
    const hash = await calculateHash(dataURL);

    // 显示预览
    const preview = document.getElementById('canvasPreview');
    if (preview) {
        preview.innerHTML = '';
        preview.appendChild(canvas);
    }

    return {
        dataURL: dataURL.substring(0, 100) + '...',
        hash: hash,
        width: canvas.width,
        height: canvas.height,
    };
}
