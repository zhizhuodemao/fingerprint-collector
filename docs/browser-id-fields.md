# Browser ID 依赖字段说明

Browser ID 是基于浏览器稳定特征生成的唯一标识符。本文档说明了 Browser ID 计算所依赖的字段，以及被排除的不稳定字段。

## 依赖的稳定字段

### 客户端字段 (client)

#### navigator
| 字段 | 说明 | 稳定性 |
|------|------|--------|
| `userAgent` | 浏览器 User-Agent 字符串 | 高 |
| `platform` | 操作系统平台 (如 MacIntel, Win32) | 高 |
| `language` | 首选语言 | 高 |
| `languages` | 语言列表 | 高 |
| `cookieEnabled` | Cookie 是否启用 | 高 |
| `doNotTrack` | DNT 设置 | 高 |
| `hardwareConcurrency` | CPU 核心数 | 高 |
| `deviceMemory` | 设备内存 (GB) | 高 |
| `maxTouchPoints` | 最大触控点数 | 高 |
| `vendor` | 浏览器厂商 | 高 |
| `vendorSub` | 厂商子版本 | 高 |
| `product` | 产品名称 | 高 |
| `productSub` | 产品子版本 | 高 |
| `appCodeName` | 应用代码名 | 高 |
| `appName` | 应用名称 | 高 |
| `appVersion` | 应用版本 | 高 |
| `oscpu` | 操作系统 CPU 信息 (Firefox) | 高 |
| `buildID` | 构建 ID (Firefox) | 高 |
| `pdfViewerEnabled` | PDF 查看器是否启用 | 高 |
| `webdriver` | 是否为 WebDriver 控制 | 高 |
| `permissions` | 权限 API 支持情况 | 高 |

#### screen
| 字段 | 说明 | 稳定性 |
|------|------|--------|
| `width` | 屏幕宽度 | 高 |
| `height` | 屏幕高度 | 高 |
| `colorDepth` | 色彩深度 | 高 |
| `pixelDepth` | 像素深度 | 高 |
| `devicePixelRatio` | 设备像素比 | 高 |
| `orientation` | 屏幕方向 (type, angle) | 高 |

#### canvas ⭐
| 字段 | 说明 | 稳定性 |
|------|------|--------|
| `hash` | Canvas 渲染结果的 SHA-256 哈希 | 高 |
| `width` | Canvas 宽度 | 高 |
| `height` | Canvas 高度 | 高 |
| `dataURL` | Canvas 数据 URL (前100字符) | 高 |

> ⭐ Canvas 指纹是区分不同设备的核心特征之一，基于 GPU 渲染差异产生唯一值。

#### webgl ⭐
| 字段 | 说明 | 稳定性 |
|------|------|--------|
| `supported` | WebGL 是否支持 | 高 |
| `version` | WebGL 版本 | 高 |
| `shadingLanguageVersion` | GLSL 版本 | 高 |
| `vendor` | WebGL 厂商 | 高 |
| `renderer` | WebGL 渲染器 | 高 |
| `unmaskedVendor` | 真实显卡厂商 | 高 |
| `unmaskedRenderer` | 真实显卡型号 | 高 |
| `maxTextureSize` | 最大纹理尺寸 | 高 |
| `maxViewportDims` | 最大视口尺寸 | 高 |
| `maxRenderbufferSize` | 最大渲染缓冲区 | 高 |
| `extensions` | 支持的扩展列表 | 高 |
| `webgl2Supported` | WebGL2 是否支持 | 高 |
| 其他 `max*` 字段 | 各种 WebGL 限制参数 | 高 |

> ⭐ `unmaskedRenderer` 包含真实显卡信息 (如 "ANGLE (Apple, ANGLE Metal Renderer: Apple M4 Pro)")，是高唯一性特征。

#### audio
| 字段 | 说明 | 稳定性 |
|------|------|--------|
| `supported` | Web Audio 是否支持 | 高 |
| `sampleRate` | 采样率 | 高 |
| `channelCount` | 音频通道数 | 高 |
| `maxChannelCount` | 最大通道数 | 高 |

#### fonts ⭐
| 字段 | 说明 | 稳定性 |
|------|------|--------|
| `detected` | 检测到的字体列表 | 高 |
| `count` | 检测到的字体数量 | 高 |

> ⭐ 字体列表是区分不同系统/用户的重要特征，不同系统安装的字体差异很大。

#### automation
| 字段 | 说明 | 稳定性 |
|------|------|--------|
| `checks.*` | 自动化检测项 (除 permissionsInconsistent) | 高 |
| `isLikelyAutomated` | 是否可能是自动化 | 高 |

#### features
| 字段 | 说明 | 稳定性 |
|------|------|--------|
| 全部 40+ 项 | 浏览器 API 支持检测 | 高 |

包括: `localStorage`, `sessionStorage`, `indexedDB`, `webGL`, `webGL2`, `webAudio`, `webRTC`, `serviceWorker`, `webAuthn`, `bluetooth`, `usb` 等。

#### storage
| 字段 | 说明 | 稳定性 |
|------|------|--------|
| `localStorageEnabled` | localStorage 是否启用 | 高 |
| `sessionStorageEnabled` | sessionStorage 是否启用 | 高 |
| `cookiesEnabled` | Cookies 是否启用 | 高 |

#### plugins
| 字段 | 说明 | 稳定性 |
|------|------|--------|
| `count` | 插件数量 | 高 |
| `list` | 插件列表 (name, filename, description) | 高 |

#### mimeTypes
| 字段 | 说明 | 稳定性 |
|------|------|--------|
| `count` | MIME 类型数量 | 高 |
| `list` | MIME 类型列表 | 高 |

### 服务器端字段 (server)

| 字段 | 说明 | 稳定性 |
|------|------|--------|
| `user_agent` | HTTP User-Agent 请求头 | 高 |
| `accept_language` | HTTP Accept-Language 请求头 | 高 |
| `accept_encoding` | HTTP Accept-Encoding 请求头 | 高 |

---

## 排除的不稳定字段

以下字段由于会随时间、网络状态、窗口状态等变化，已从 Browser ID 计算中排除：

### 基础字段
| 字段 | 排除原因 |
|------|----------|
| `timestamp` | 每次收集时间不同 |
| `hash` | 前端计算的哈希包含 timestamp |
| `timing` | 所有时间相关字段会变化 |
| `tls` | TLS 有 GREASE 随机值和扩展顺序随机化 |

### screen
| 字段 | 排除原因 |
|------|----------|
| `innerWidth`, `innerHeight` | 窗口大小会变化 |
| `outerWidth`, `outerHeight` | 窗口大小会变化 |
| `availWidth`, `availHeight` | 受系统任务栏等影响 |
| `screenX`, `screenY` | 窗口位置会随拖动变化 |

### navigator
| 字段 | 排除原因 |
|------|----------|
| `connection` (整个对象) | 网络状态会变化 |
| `connection.effectiveType` | 3g/4g/wifi 切换 |
| `connection.downlink` | 下载速度会变化 |
| `connection.rtt` | 网络延迟会变化 |

### audio
| 字段 | 排除原因 |
|------|----------|
| `fingerprint` | 浮点数计算可能有精度差异 |
| `baseLatency` | 音频延迟会变化 |
| `outputLatency` | 输出延迟会变化 |
| `state` | 首次可能是 timeout，后续是 collected |
| `error` | 错误信息可能变化 |

### storage
| 字段 | 排除原因 |
|------|----------|
| `indexedDBEnabled` | indexedDB.open() 是异步的，首次可能为 false |

### automation
| 字段 | 排除原因 |
|------|----------|
| `score` | 依赖于异步检测结果 |
| `checks.permissionsInconsistent` | 异步检测，返回后才设置值 |

---

## ID 生成算法

```python
stable_data = {
    'client': client,  # 移除不稳定字段后的客户端数据
    'user_agent': server.user_agent,
    'accept_language': server.accept_language,
    'accept_encoding': server.accept_encoding,
}
content = json.dumps(stable_data, sort_keys=True)
browser_id = sha256(content)[:16]
```

1. 收集客户端和服务器端数据
2. 移除所有不稳定字段
3. 使用 `sort_keys=True` 确保 JSON 序列化顺序一致
4. 计算 SHA-256 哈希
5. 取前 16 位作为 Browser ID

---

## 唯一性分析

### 高唯一性特征 (核心)
1. **Canvas Hash** - GPU 渲染差异
2. **WebGL unmaskedRenderer** - 真实显卡信息
3. **Fonts** - 安装的字体列表

### 中等唯一性特征
1. **Screen** - 分辨率和像素比
2. **Navigator** - 浏览器和系统信息
3. **Plugins/MimeTypes** - 插件配置

### 辅助特征
1. **Features** - API 支持情况
2. **Storage** - 存储配置
3. **Automation** - 自动化检测结果

---

*文档生成时间: 2025-12-17*
