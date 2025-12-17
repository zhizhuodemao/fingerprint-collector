/**
 * Toast UI Module
 * 管理 Toast 提示
 */

/**
 * 显示 TLS 提示 Toast
 * @param {Object} config - 配置对象
 */
export function showTlsToast(config) {
    const toast = document.getElementById('tlsToast');
    const toastLink = document.getElementById('tlsToastLink');
    const toastClose = document.getElementById('toastClose');

    if (!toast) return;

    // 检查是否已经接受过证书
    const tlsCertAccepted = localStorage.getItem('tlsCertAccepted');
    if (tlsCertAccepted) {
        return;
    }

    // 设置 TLS 链接
    const tlsUrl = config?.tls_url || 'https://localhost:8443';
    toastLink.href = tlsUrl;

    // 延迟显示 toast
    setTimeout(() => {
        toast.classList.add('visible');
    }, 1000);

    // 关闭按钮
    toastClose.addEventListener('click', () => {
        toast.classList.remove('visible');
    });

    // 点击链接后标记为已接受
    toastLink.addEventListener('click', () => {
        localStorage.setItem('tlsCertAccepted', 'true');
        setTimeout(() => {
            toast.classList.remove('visible');
        }, 500);
    });
}

/**
 * 更新 TLS 链接
 * @param {Object} config - 配置对象
 */
export function updateTlsLink(config) {
    const tlsLink = document.querySelector('.card-note a');
    if (tlsLink && config) {
        tlsLink.href = config.tls_url;
        tlsLink.textContent = config.tls_url;
    }
}
