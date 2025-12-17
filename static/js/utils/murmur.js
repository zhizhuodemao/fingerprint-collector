/**
 * MurmurHash3 128-bit 实现
 * 从 FingerprintJS 提取并优化
 * 比 SHA-256 更快，更适合指纹生成
 */

const x64Add = (t, e) => {
    const n = t[0] >>> 16,
        o = 65535 & t[0],
        i = t[1] >>> 16,
        r = 65535 & t[1],
        a = e[0] >>> 16,
        c = 65535 & e[0],
        s = e[1] >>> 16;
    let u = 0, l = 0, d = 0, m = 0;
    m += r + (65535 & e[1]);
    d += m >>> 16;
    m &= 65535;
    d += i + s;
    l += d >>> 16;
    d &= 65535;
    l += o + c;
    u += l >>> 16;
    l &= 65535;
    u += n + a;
    u &= 65535;
    t[0] = u << 16 | l;
    t[1] = d << 16 | m;
};

const x64Multiply = (t, e) => {
    const n = t[0] >>> 16,
        o = 65535 & t[0],
        i = t[1] >>> 16,
        r = 65535 & t[1],
        a = e[0] >>> 16,
        c = 65535 & e[0],
        s = e[1] >>> 16,
        u = 65535 & e[1];
    let l = 0, d = 0, m = 0, f = 0;
    f += r * u;
    m += f >>> 16;
    f &= 65535;
    m += i * u;
    d += m >>> 16;
    m &= 65535;
    m += r * s;
    d += m >>> 16;
    m &= 65535;
    d += o * u;
    l += d >>> 16;
    d &= 65535;
    d += i * s;
    l += d >>> 16;
    d &= 65535;
    d += r * c;
    l += d >>> 16;
    d &= 65535;
    l += n * u + o * s + i * c + r * a;
    l &= 65535;
    t[0] = l << 16 | d;
    t[1] = m << 16 | f;
};

const x64Rotl = (t, e) => {
    const n = t[0];
    e %= 64;
    if (32 === e) {
        t[0] = t[1];
        t[1] = n;
    } else if (e < 32) {
        t[0] = n << e | t[1] >>> 32 - e;
        t[1] = t[1] << e | n >>> 32 - e;
    } else {
        e -= 32;
        t[0] = t[1] << e | n >>> 32 - e;
        t[1] = n << e | t[1] >>> 32 - e;
    }
};

const x64LeftShift = (t, e) => {
    e %= 64;
    if (0 !== e) {
        if (e < 32) {
            t[0] = t[1] >>> 32 - e;
            t[1] = t[1] << e;
        } else {
            t[0] = t[1] << e - 32;
            t[1] = 0;
        }
    }
};

const x64Xor = (t, e) => {
    t[0] ^= e[0];
    t[1] ^= e[1];
};

const x64Fmix = (t) => {
    const c1 = [4283543511, 3981806797];
    const c2 = [3301882366, 444984403];
    const e = [0, t[0] >>> 1];
    x64Xor(t, e);
    x64Multiply(t, c1);
    e[1] = t[0] >>> 1;
    x64Xor(t, e);
    x64Multiply(t, c2);
    e[1] = t[0] >>> 1;
    x64Xor(t, e);
};

/**
 * MurmurHash3 128-bit
 * @param {string} key - 要哈希的字符串
 * @param {number} seed - 种子值（默认 0）
 * @returns {string} 32 字符的十六进制字符串
 */
export function murmurHash3(key, seed = 0) {
    // 将字符串转换为字节数组
    const bytes = (() => {
        const e = new Uint8Array(key.length);
        for (let n = 0; n < key.length; n++) {
            const o = key.charCodeAt(n);
            if (o > 127)
                return (new TextEncoder()).encode(key);
            e[n] = o;
        }
        return e;
    })();

    const length = [0, bytes.length];
    const remainder = length[1] % 16;
    const blocks = length[1] - remainder;

    const h1 = [0, seed];
    const h2 = [0, seed];
    const k1 = [0, 0];
    const k2 = [0, 0];

    const c1 = [2277735313, 289559509];
    const c2 = [1291169091, 658871167];
    const c3 = [0, 5];
    const c4 = [0, 1390208809];
    const c5 = [0, 944331445];

    let i;
    for (i = 0; i < blocks; i += 16) {
        k1[0] = bytes[i + 4] | bytes[i + 5] << 8 | bytes[i + 6] << 16 | bytes[i + 7] << 24;
        k1[1] = bytes[i] | bytes[i + 1] << 8 | bytes[i + 2] << 16 | bytes[i + 3] << 24;
        k2[0] = bytes[i + 12] | bytes[i + 13] << 8 | bytes[i + 14] << 16 | bytes[i + 15] << 24;
        k2[1] = bytes[i + 8] | bytes[i + 9] << 8 | bytes[i + 10] << 16 | bytes[i + 11] << 24;

        x64Multiply(k1, c1);
        x64Rotl(k1, 31);
        x64Multiply(k1, c2);
        x64Xor(h1, k1);
        x64Rotl(h1, 27);
        x64Add(h1, h2);
        x64Multiply(h1, c3);
        x64Add(h1, c4);

        x64Multiply(k2, c2);
        x64Rotl(k2, 33);
        x64Multiply(k2, c1);
        x64Xor(h2, k2);
        x64Rotl(h2, 31);
        x64Add(h2, h1);
        x64Multiply(h2, c3);
        x64Add(h2, c5);
    }

    k1[0] = 0;
    k1[1] = 0;
    k2[0] = 0;
    k2[1] = 0;

    const temp = [0, 0];

    switch (remainder) {
        case 15:
            temp[1] = bytes[i + 14];
            x64LeftShift(temp, 48);
            x64Xor(k2, temp);
        case 14:
            temp[1] = bytes[i + 13];
            x64LeftShift(temp, 40);
            x64Xor(k2, temp);
        case 13:
            temp[1] = bytes[i + 12];
            x64LeftShift(temp, 32);
            x64Xor(k2, temp);
        case 12:
            temp[1] = bytes[i + 11];
            x64LeftShift(temp, 24);
            x64Xor(k2, temp);
        case 11:
            temp[1] = bytes[i + 10];
            x64LeftShift(temp, 16);
            x64Xor(k2, temp);
        case 10:
            temp[1] = bytes[i + 9];
            x64LeftShift(temp, 8);
            x64Xor(k2, temp);
        case 9:
            temp[1] = bytes[i + 8];
            x64Xor(k2, temp);
            x64Multiply(k2, c2);
            x64Rotl(k2, 33);
            x64Multiply(k2, c1);
            x64Xor(h2, k2);
        case 8:
            temp[1] = bytes[i + 7];
            x64LeftShift(temp, 56);
            x64Xor(k1, temp);
        case 7:
            temp[1] = bytes[i + 6];
            x64LeftShift(temp, 48);
            x64Xor(k1, temp);
        case 6:
            temp[1] = bytes[i + 5];
            x64LeftShift(temp, 40);
            x64Xor(k1, temp);
        case 5:
            temp[1] = bytes[i + 4];
            x64LeftShift(temp, 32);
            x64Xor(k1, temp);
        case 4:
            temp[1] = bytes[i + 3];
            x64LeftShift(temp, 24);
            x64Xor(k1, temp);
        case 3:
            temp[1] = bytes[i + 2];
            x64LeftShift(temp, 16);
            x64Xor(k1, temp);
        case 2:
            temp[1] = bytes[i + 1];
            x64LeftShift(temp, 8);
            x64Xor(k1, temp);
        case 1:
            temp[1] = bytes[i];
            x64Xor(k1, temp);
            x64Multiply(k1, c1);
            x64Rotl(k1, 31);
            x64Multiply(k1, c2);
            x64Xor(h1, k1);
    }

    x64Xor(h1, length);
    x64Xor(h2, length);
    x64Add(h1, h2);
    x64Add(h2, h1);
    x64Fmix(h1);
    x64Fmix(h2);
    x64Add(h1, h2);
    x64Add(h2, h1);

    return (
        ("00000000" + (h1[0] >>> 0).toString(16)).slice(-8) +
        ("00000000" + (h1[1] >>> 0).toString(16)).slice(-8) +
        ("00000000" + (h2[0] >>> 0).toString(16)).slice(-8) +
        ("00000000" + (h2[1] >>> 0).toString(16)).slice(-8)
    );
}

/**
 * 生成组件哈希（与 FingerprintJS 兼容的格式）
 * @param {Object} components - 组件对象
 * @returns {string} 32 字符的十六进制哈希
 */
export function hashComponents(components) {
    let str = "";
    for (const key of Object.keys(components).sort()) {
        const value = components[key];
        const serialized = value instanceof Error ? "error" : JSON.stringify(value);
        str += `${str ? "|" : ""}${key.replace(/([:|\\])/g, "\\$1")}:${serialized}`;
    }
    return murmurHash3(str);
}
