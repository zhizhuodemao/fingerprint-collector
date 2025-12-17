# 设备唯一性判定方案设计文档

## 1. 背景与问题

### 1.1 问题描述

在不同环境（HTTP/HTTPS、本地/服务器）下，同一浏览器生成的指纹 ID 不一致。

**具体表现：**
- 本地 `localhost:5000` (被视为安全上下文) 检测到的 API 可用性与
- 服务器 `http://222.73.60.30:5000` (非安全上下文) 不同

**差异字段示例：**
```json
// 本地 (localhost - 安全上下文)
{
    "getBattery": true,
    "bluetooth": true,
    "usb": true,
    "hid": true,
    "serial": true,
    "clipboard": true,
    "wakeLock": true,
    "serviceWorker": true
}

// 服务器 (HTTP - 非安全上下文)
{
    "getBattery": false,
    "bluetooth": false,
    "usb": false,
    "hid": false,
    "serial": false,
    "clipboard": false,
    "wakeLock": false,
    "serviceWorker": false
}
```

### 1.2 根本原因

现代浏览器出于安全考虑，很多 Web API 只在**安全上下文**（Secure Context）下可用：
- HTTPS 连接
- localhost / 127.0.0.1
- file:// 协议

普通 HTTP 连接被视为不安全，这些 API 会返回 `false` 或 `undefined`。

---

## 2. 解决方案：基于 FingerprintJS 的分层指纹架构

### 2.1 核心原则

参考 [Fingerprint.com](https://fingerprint.com/blog/browser-fingerprinting-techniques/) 的官方文档：

> "Good browser fingerprinting **weighs different signals based on their uniqueness and durability**"
>
> "Signals need to be **persistent**, so one tiny change does not completely change the identifier"

### 2.2 信号分层设计

```
┌─────────────────────────────────────────────────────────────────────────┐
│  第一层：核心信号 (Core Signals)                                         │
│  用途：生成稳定的 Device ID                                              │
│  特点：与硬件强相关、跨环境稳定、高熵值、不受 HTTPS 影响                   │
├─────────────────────────────────────────────────────────────────────────┤
│  • Audio Fingerprint     - 音频处理特征，与 CPU/音频硬件相关              │
│  • Canvas Fingerprint    - GPU/显卡驱动渲染差异                          │
│  • WebGL Renderer        - 显卡型号（如 "Apple M4 Pro"）                 │
│  • WebGL Vendor          - 显卡厂商（如 "Google Inc. (Apple)"）          │
│  • Math Fingerprint      - 数学计算精度，与 CPU/浏览器引擎相关            │
│  • Fonts                 - 安装的字体列表                                │
└─────────────────────────────────────────────────────────────────────────┘
                                    ↓
┌─────────────────────────────────────────────────────────────────────────┐
│  第二层：环境信号 (Environment Signals)                                  │
│  用途：辅助验证、提高精度                                                │
│  特点：相对稳定，但可能因用户设置变化                                     │
├─────────────────────────────────────────────────────────────────────────┤
│  • Screen Resolution     - 屏幕分辨率                                    │
│  • Color Depth           - 色深                                         │
│  • Device Memory         - 设备内存                                      │
│  • Hardware Concurrency  - CPU 核心数                                    │
│  • Timezone              - 时区                                         │
│  • Languages             - 语言设置                                      │
│  • Platform              - 平台（如 "MacIntel"）                         │
│  • Color Gamut           - 色域（如 "p3"）                               │
└─────────────────────────────────────────────────────────────────────────┘
                                    ↓
┌─────────────────────────────────────────────────────────────────────────┐
│  第三层：浏览器信号 (Browser Signals)                                    │
│  用途：区分不同浏览器、检测异常                                          │
├─────────────────────────────────────────────────────────────────────────┤
│  • Vendor                - 浏览器厂商                                    │
│  • Vendor Flavors        - 浏览器类型（chrome/firefox/safari）           │
│  • Plugins               - 插件列表                                      │
│  • Touch Support         - 触摸支持                                      │
│  • PDF Viewer Enabled    - PDF 查看器                                    │
└─────────────────────────────────────────────────────────────────────────┘
                                    ↓
┌─────────────────────────────────────────────────────────────────────────┐
│  排除层：不稳定信号 (Excluded Signals)                                   │
│  原因：受安全上下文、隐私设置、用户操作影响                               │
├─────────────────────────────────────────────────────────────────────────┤
│  ✗ getBattery, bluetooth, usb, hid, serial    - 需要 HTTPS              │
│  ✗ clipboard, wakeLock, serviceWorker         - 需要 HTTPS              │
│  ✗ sessionStorage, localStorage, indexedDB    - 受隐私模式影响           │
│  ✗ cookiesEnabled                             - 可被用户禁用             │
│  ✗ domBlockers                                - 受广告拦截器影响          │
│  ✗ reducedMotion, forcedColors                - 辅助功能设置             │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 3. 信号详细说明

### 3.1 核心信号权重分配

| 信号 | 权重 | 必需 | 稳定性 | 说明 |
|------|------|------|--------|------|
| audio | 20% | ✓ | ⭐⭐⭐ | 音频处理产生的浮点数特征 |
| canvasGeometry | 15% | ✓ | ⭐⭐⭐ | Canvas 绘制几何图形的渲染结果 |
| canvasText | 10% | - | ⭐⭐⭐ | Canvas 绘制文字的渲染结果 |
| webglRenderer | 20% | ✓ | ⭐⭐⭐ | 显卡型号，非常独特 |
| webglVendor | 10% | ✓ | ⭐⭐⭐ | 显卡厂商 |
| fonts | 10% | - | ⭐⭐ | 安装的字体列表 |
| fontPreferences | 5% | - | ⭐⭐ | 字体测量值 |
| math | 10% | ✓ | ⭐⭐⭐ | 数学计算精度特征 |

### 3.2 FingerprintJS 原始数据示例

从 `finger.json` 提取的关键字段：

```json
{
  "audio": {
    "value": 124.04348155876505,
    "duration": 2
  },
  "canvas": {
    "value": {
      "winding": true,
      "geometry": "data:image/png;base64,iVBORw0KGgo...",
      "text": "data:image/png;base64,iVBORw0KGgo..."
    }
  },
  "webGlBasics": {
    "value": {
      "version": "WebGL 1.0 (OpenGL ES 2.0 Chromium)",
      "vendor": "WebKit",
      "vendorUnmasked": "Google Inc. (Apple)",
      "renderer": "WebKit WebGL",
      "rendererUnmasked": "ANGLE (Apple, ANGLE Metal Renderer: Apple M4 Pro, Unspecified Version)"
    }
  },
  "fonts": {
    "value": ["Arial Unicode MS", "Gill Sans", "Helvetica Neue", "Menlo"]
  },
  "fontPreferences": {
    "value": {
      "default": 74.4296875,
      "apple": 74.4296875,
      "serif": 72.15625,
      "sans": 74.4296875,
      "mono": 66.53125
    }
  },
  "math": {
    "value": {
      "acos": 1.4473588658278522,
      "acosh": 709.889355822726,
      "asin": 0.12343746096704435,
      "asinh": 0.881373587019543,
      "sin": 0.8178819121159085,
      "cos": -0.8390715290095377,
      "tan": -1.4214488238747245,
      "exp": 2.718281828459045
    }
  },
  "screenResolution": {
    "value": [982, 1512]
  },
  "hardwareConcurrency": {
    "value": 14
  },
  "deviceMemory": {
    "value": 8
  },
  "timezone": {
    "value": "Asia/Shanghai"
  },
  "platform": {
    "value": "MacIntel"
  }
}
```

---

## 4. 实现方案

### 4.1 前端：信号收集与 ID 生成

```javascript
// static/js/utils/deviceId.js

/**
 * 收集稳定信号
 */
export async function collectStableSignals(fingerprint) {
    return {
        // === 核心信号 ===
        audio: fingerprint.audio?.fingerprint || fingerprint.audio?.value,
        canvasGeometry: await hashData(fingerprint.canvas?.geometry),
        canvasText: await hashData(fingerprint.canvas?.text),
        webglRenderer: fingerprint.webgl?.unmaskedRenderer,
        webglVendor: fingerprint.webgl?.unmaskedVendor,
        fonts: hashArray(fingerprint.fonts),
        fontPreferences: hashObject(fingerprint.fontPreferences),
        math: collectMathFingerprint(),

        // === 环境信号 ===
        screen: `${screen.width}x${screen.height}`,
        colorDepth: screen.colorDepth,
        deviceMemory: navigator.deviceMemory,
        hardwareConcurrency: navigator.hardwareConcurrency,
        timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
        languages: navigator.languages?.join(','),
        platform: navigator.platform,
    };
}

/**
 * 生成设备 ID
 */
export async function generateDeviceId(signals) {
    // 核心 ID（最稳定，跨环境一致）
    const coreData = {
        audio: signals.audio,
        canvas: `${signals.canvasGeometry}|${signals.canvasText}`,
        webgl: `${signals.webglVendor}|${signals.webglRenderer}`,
        math: signals.math,
    };

    // 扩展 ID（更精确）
    const extendedData = {
        ...coreData,
        fonts: signals.fonts,
        screen: signals.screen,
        timezone: signals.timezone,
        platform: signals.platform,
        cores: signals.hardwareConcurrency,
    };

    return {
        coreId: await sha256(JSON.stringify(coreData)),
        extendedId: await sha256(JSON.stringify(extendedData)),
        confidence: calculateConfidence(signals),
        signals: signals,
    };
}

/**
 * 数学特征收集
 */
function collectMathFingerprint() {
    const m = Math;
    const values = [
        m.acos(0.5),
        m.acosh(Math.E),
        m.asin(0.5),
        m.asinh(1),
        m.atanh(0.5),
        m.sin(1),
        m.sinh(1),
        m.cos(1),
        m.cosh(1),
        m.tan(1),
        m.tanh(1),
        m.exp(1),
        m.expm1(1),
        m.log1p(Math.E),
    ];
    return values.map(v => v.toString().slice(0, 15)).join('|');
}

/**
 * 计算置信度
 */
function calculateConfidence(signals) {
    const weights = {
        audio: 20, canvasGeometry: 15, canvasText: 10,
        webglRenderer: 20, webglVendor: 10,
        fonts: 10, math: 10,
        screen: 2, timezone: 2, platform: 1
    };

    let score = 0, maxScore = 0;
    for (const [key, weight] of Object.entries(weights)) {
        maxScore += weight;
        if (signals[key]) score += weight;
    }

    return Math.round((score / maxScore) * 100);
}
```

### 4.2 后端：设备匹配策略

```python
# app.py

import uuid

def match_device(new_fp, stored_fingerprints):
    """
    三层匹配策略：
    1. coreId 精确匹配 → 置信度 95%+，同一设备
    2. 核心信号 ≥3/4 匹配 → 置信度 70-90%，可能同一设备
    3. 环境信号相似度 > 0.6 → 置信度 50-70%，需人工确认
    """

    best_match = None
    best_score = 0

    for stored in stored_fingerprints:
        # 第一层：精确匹配
        if new_fp['coreId'] == stored['coreId']:
            extra = 5 if new_fp['extendedId'] == stored['extendedId'] else 0
            return {
                'match': True,
                'confidence': 95 + extra,
                'device_id': stored['device_id'],
                'match_type': 'exact'
            }

        # 第二层：核心信号模糊匹配
        core_matches = sum([
            new_fp['signals']['audio'] == stored['signals']['audio'],
            new_fp['signals']['canvasGeometry'] == stored['signals']['canvasGeometry'],
            new_fp['signals']['webglRenderer'] == stored['signals']['webglRenderer'],
            new_fp['signals']['math'] == stored['signals']['math'],
        ])

        if core_matches >= 3:
            score = 70 + (core_matches - 3) * 10
            if score > best_score:
                best_score = score
                best_match = {
                    'match': True,
                    'confidence': score,
                    'device_id': stored['device_id'],
                    'match_type': 'fuzzy_core'
                }

        # 第三层：环境信号相似度
        elif core_matches >= 2:
            env_sim = calculate_env_similarity(
                new_fp['signals'],
                stored['signals']
            )
            if env_sim > 0.6:
                score = 50 + env_sim * 20
                if score > best_score:
                    best_score = score
                    best_match = {
                        'match': True,
                        'confidence': score,
                        'device_id': stored['device_id'],
                        'match_type': 'fuzzy_env'
                    }

    if best_match:
        return best_match

    # 新设备
    return {
        'match': False,
        'confidence': 0,
        'device_id': str(uuid.uuid4()),
        'match_type': 'new'
    }


def calculate_env_similarity(sig1, sig2):
    """计算环境信号相似度"""
    env_keys = [
        'screen', 'colorDepth', 'deviceMemory',
        'hardwareConcurrency', 'timezone', 'platform', 'languages'
    ]

    matches = 0
    total = 0

    for key in env_keys:
        if key in sig1 and key in sig2:
            total += 1
            if sig1[key] == sig2[key]:
                matches += 1

    return matches / total if total > 0 else 0
```

---

## 5. 数据库设计

### 5.1 设备指纹表

```sql
CREATE TABLE device_fingerprints (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id TEXT UNIQUE NOT NULL,
    core_id TEXT NOT NULL,
    extended_id TEXT,

    -- 核心信号
    audio TEXT,
    canvas_geometry TEXT,
    canvas_text TEXT,
    webgl_renderer TEXT,
    webgl_vendor TEXT,
    fonts TEXT,
    math TEXT,

    -- 环境信号
    screen TEXT,
    color_depth INTEGER,
    device_memory INTEGER,
    hardware_concurrency INTEGER,
    timezone TEXT,
    languages TEXT,
    platform TEXT,

    -- 元数据
    confidence INTEGER,
    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    visit_count INTEGER DEFAULT 1,

    -- 索引
    INDEX idx_core_id (core_id),
    INDEX idx_device_id (device_id)
);
```

### 5.2 访问记录表

```sql
CREATE TABLE device_visits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id TEXT NOT NULL,
    ip_address TEXT,
    user_agent TEXT,
    match_type TEXT,
    confidence INTEGER,
    visit_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (device_id) REFERENCES device_fingerprints(device_id)
);
```

---

## 6. 测试验证

### 6.1 测试用例

| 场景 | 预期结果 |
|------|----------|
| 同一浏览器，localhost vs HTTP 服务器 | coreId 一致 |
| 同一浏览器，不同标签页 | coreId + extendedId 一致 |
| 同一浏览器，隐私模式 | coreId 一致，部分环境信号可能不同 |
| 同一设备，不同浏览器 | coreId 不同（浏览器引擎差异） |
| 不同设备，同型号 | coreId 不同（硬件序列差异） |

### 6.2 验证步骤

1. 在 localhost:5000 收集指纹，记录 coreId
2. 部署到服务器，使用 HTTP 访问
3. 同一浏览器访问，验证 coreId 是否一致
4. 如一致，方案验证成功

---

## 7. 参考资料

1. [Fingerprint.com - Browser Fingerprinting Techniques](https://fingerprint.com/blog/browser-fingerprinting-techniques/)
2. [FingerprintJS Open Source](https://github.com/nickersoft/fingerprintjs)
3. [AmIUnique](https://amiunique.org/)
4. [BrowserLeaks](https://browserleaks.com/)
5. [CreepJS](https://abrahamjuliot.github.io/creepjs/)

---

## 8. 更新日志

| 日期 | 版本 | 说明 |
|------|------|------|
| 2025-12-18 | v1.0 | 初始方案设计 |
