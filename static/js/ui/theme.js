/**
 * Theme Manager
 * 管理深色/浅色模式切换
 */

const THEME_KEY = 'fingerprint-theme';

/**
 * 获取系统主题偏好
 * @returns {string} 'dark' | 'light'
 */
function getSystemTheme() {
    return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
}

/**
 * 获取保存的主题
 * @returns {string|null} 'dark' | 'light' | null
 */
function getSavedTheme() {
    return localStorage.getItem(THEME_KEY);
}

/**
 * 保存主题偏好
 * @param {string} theme - 'dark' | 'light'
 */
function saveTheme(theme) {
    localStorage.setItem(THEME_KEY, theme);
}

/**
 * 应用主题
 * @param {string} theme - 'dark' | 'light'
 */
function applyTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
}

/**
 * 获取当前主题
 * @returns {string} 'dark' | 'light'
 */
export function getCurrentTheme() {
    const saved = getSavedTheme();
    if (saved) return saved;
    return getSystemTheme();
}

/**
 * 切换主题
 * @returns {string} 新主题
 */
export function toggleTheme() {
    const current = getCurrentTheme();
    const next = current === 'dark' ? 'light' : 'dark';
    applyTheme(next);
    saveTheme(next);
    return next;
}

/**
 * 初始化主题
 * 根据保存的偏好或系统设置应用主题
 */
export function initTheme() {
    const theme = getCurrentTheme();
    applyTheme(theme);

    // 监听系统主题变化
    window.matchMedia('(prefers-color-scheme: dark)').addEventListener('change', (e) => {
        // 只有没有手动设置主题时才自动切换
        if (!getSavedTheme()) {
            applyTheme(e.matches ? 'dark' : 'light');
        }
    });
}

/**
 * 创建主题切换按钮 HTML
 * @returns {string} HTML 字符串
 */
export function createThemeToggleHTML() {
    return `
        <button class="theme-toggle" id="themeToggle" aria-label="Toggle theme">
            <span class="theme-toggle-thumb">
                <svg class="sun-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <circle cx="12" cy="12" r="5"/>
                    <line x1="12" y1="1" x2="12" y2="3"/>
                    <line x1="12" y1="21" x2="12" y2="23"/>
                    <line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/>
                    <line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/>
                    <line x1="1" y1="12" x2="3" y2="12"/>
                    <line x1="21" y1="12" x2="23" y2="12"/>
                    <line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/>
                    <line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/>
                </svg>
                <svg class="moon-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
                    <path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/>
                </svg>
            </span>
        </button>
    `;
}

/**
 * 绑定主题切换按钮事件
 */
export function bindThemeToggle() {
    const toggle = document.getElementById('themeToggle');
    if (toggle) {
        toggle.addEventListener('click', toggleTheme);
    }
}
