/**
 * Status UI Module
 * 管理状态显示和指纹视觉效果
 */

/**
 * 设置状态
 * @param {string} message - 状态消息
 * @param {string} type - 状态类型: 'loading' | 'success' | 'error'
 */
export function setStatus(message, type = 'loading') {
    const status = document.getElementById('status');
    const statusText = status.querySelector('.status-text');
    const fingerprintVisual = document.getElementById('fingerprintVisual');
    const statusIcon = document.getElementById('statusIcon');

    statusText.textContent = message;
    status.className = `status-bar visible ${type}`;

    // Update fingerprint visual
    fingerprintVisual.className = 'fingerprint-rings';
    if (type === 'loading') {
        fingerprintVisual.classList.add('collecting');
        statusIcon.textContent = '...';
    } else if (type === 'success') {
        fingerprintVisual.classList.add('success');
        statusIcon.textContent = '✓';
    } else if (type === 'error') {
        statusIcon.textContent = '✗';
    }
}
