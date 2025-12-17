/**
 * Math Collector
 * 收集数学计算精度指纹
 * 参考 FingerprintJS 实现
 *
 * 原理：不同 CPU/浏览器引擎的浮点运算存在微小差异
 * 这种差异是硬件级别的，非常稳定，不受 HTTPS 影响
 */

const M = Math;

// Polyfill 版本的数学函数（用于对比）
const acoshPf = (x) => M.log(x + M.sqrt(x * x - 1));
const asinhPf = (x) => M.log(x + M.sqrt(x * x + 1));
const atanhPf = (x) => M.log((1 + x) / (1 - x)) / 2;
const sinhPf = (x) => M.exp(x) - 1 / M.exp(x) / 2;
const coshPf = (x) => (M.exp(x) + 1 / M.exp(x)) / 2;
const tanhPf = (x) => (M.exp(2 * x) - 1) / (M.exp(2 * x) + 1);
const expm1Pf = (x) => M.exp(x) - 1;
const log1pPf = (x) => M.log(1 + x);
const powPI = (x) => M.pow(M.PI, x);

/**
 * 收集数学指纹（与 FingerprintJS 兼容）
 * @returns {Object} 数学指纹数据
 */
export function collectMath() {
    const acos = M.acos || (() => 0);
    const acosh = M.acosh || (() => 0);
    const asin = M.asin || (() => 0);
    const asinh = M.asinh || (() => 0);
    const atanh = M.atanh || (() => 0);
    const atan = M.atan || (() => 0);
    const sin = M.sin || (() => 0);
    const sinh = M.sinh || (() => 0);
    const cos = M.cos || (() => 0);
    const cosh = M.cosh || (() => 0);
    const tan = M.tan || (() => 0);
    const tanh = M.tanh || (() => 0);
    const exp = M.exp || (() => 0);
    const expm1 = M.expm1 || (() => 0);
    const log1p = M.log1p || (() => 0);

    // 与 FingerprintJS 相同的测试值
    const value = {
        // 反三角函数
        acos: acos(0.12312423423423424),
        acosh: acosh(1e308),
        acoshPf: acoshPf(1e154),
        asin: asin(0.12312423423423424),
        asinh: asinh(1),
        asinhPf: asinhPf(1),
        atanh: atanh(0.5),
        atanhPf: atanhPf(0.5),
        atan: atan(0.5),

        // 三角函数
        sin: sin(-1e300),
        sinh: sinh(1),
        sinhPf: sinhPf(1),
        cos: cos(10.000000000123),
        cosh: cosh(1),
        coshPf: coshPf(1),
        tan: tan(-1e300),
        tanh: tanh(1),
        tanhPf: tanhPf(1),

        // 指数/对数函数
        exp: exp(1),
        expm1: expm1(1),
        expm1Pf: expm1Pf(1),
        log1p: log1p(10),
        log1pPf: log1pPf(10),

        // 幂函数
        powPI: powPI(-100),
    };

    // 生成指纹字符串（用于快速比较）
    const fingerprint = Object.values(value)
        .map(v => String(v).slice(0, 15))
        .join('|');

    return {
        value,
        fingerprint,
    };
}
