# HTTP/2 指纹采集实现计划

## 一、理论基础

HTTP/2 指纹由 4 部分组成，都在连接建立时被动捕获：

```
┌─────────────────────────────────────────────────────────────┐
│                    HTTP/2 Connection                         │
├─────────────────────────────────────────────────────────────┤
│  1. SETTINGS Frame     →  客户端发送的初始参数配置            │
│  2. WINDOW_UPDATE      →  流控窗口大小                       │
│  3. PRIORITY Frame     →  流优先级信息                       │
│  4. HEADERS Frame      →  伪头部顺序 (:method, :path, etc)   │
└─────────────────────────────────────────────────────────────┘
```

### 指纹格式 (Akamai)

```
[SETTINGS]|WINDOW_UPDATE|PRIORITY|Pseudo-Header-Order
```

### 示例

| 浏览器 | 指纹 |
|--------|------|
| Chrome | `1:65536;3:1000;4:6291456\|15663105\|0\|m,a,s,p` |
| Firefox | `1:65536;4:131072;5:16384\|12517377\|3:0:201:0,5:0:101:0\|m,p,a,s` |

### 各字段含义

**1. SETTINGS Frame** - 客户端发送的初始参数
- `1` = HEADER_TABLE_SIZE (头部压缩表大小)
- `2` = ENABLE_PUSH (服务器推送)
- `3` = MAX_CONCURRENT_STREAMS (最大并发流)
- `4` = INITIAL_WINDOW_SIZE (初始窗口大小)
- `5` = MAX_FRAME_SIZE (最大帧大小)
- `6` = MAX_HEADER_LIST_SIZE (最大头部列表大小)

**2. WINDOW_UPDATE** - 流控窗口大小 (如果客户端未发送则为 0)

**3. PRIORITY** - 流优先级 `StreamID:Exclusivity:DependencyID:Weight`

**4. Pseudo-Header-Order** - 伪头部顺序
- `m` = `:method`
- `a` = `:authority`
- `s` = `:scheme`
- `p` = `:path`

## 二、技术挑战

Go 标准库 `net/http` 的 HTTP/2 实现不暴露底层帧数据：

```go
// 标准用法 - 无法获取原始帧
http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
    // r 中没有 SETTINGS、PRIORITY 等信息
})
```

**解决方案**：使用底层的 `golang.org/x/net/http2` 包，手动处理帧

## 三、实现步骤

### 步骤 1：创建自定义 HTTP/2 Server

不使用标准 `http.Server`，而是直接使用 `http2.Framer` 拦截帧

### 步骤 2：拦截 SETTINGS Frame

```go
type SettingsFrame struct {
    HeaderTableSize      uint32  // ID=1
    EnablePush           uint32  // ID=2
    MaxConcurrentStreams uint32  // ID=3
    InitialWindowSize    uint32  // ID=4
    MaxFrameSize         uint32  // ID=5
    MaxHeaderListSize    uint32  // ID=6
}
// 输出格式: "1:65536;3:1000;4:6291456"
```

### 步骤 3：拦截 WINDOW_UPDATE Frame

```go
// 捕获客户端发送的窗口更新值
// 如果未发送，记录为 0
windowUpdate := frame.Increment  // e.g., 15663105
```

### 步骤 4：拦截 PRIORITY Frame

```go
type PriorityFrame struct {
    StreamID   uint32
    Exclusive  bool    // 0 或 1
    StreamDep  uint32  // 依赖的流 ID
    Weight     uint8   // 权重 1-256
}
// 输出格式: "3:0:0:201,5:0:0:101"
```

### 步骤 5：提取伪头部顺序

```go
// 从 HEADERS frame 中提取顺序
// :method, :path, :authority, :scheme
// Chrome: m,a,s,p
// Firefox: m,p,a,s
```

### 步骤 6：组装指纹

```go
fingerprint := fmt.Sprintf("%s|%d|%s|%s",
    settingsStr,      // "1:65536;3:1000;4:6291456"
    windowUpdate,     // 15663105
    priorityStr,      // "0" 或 "3:0:0:201"
    headerOrderStr,   // "m,a,s,p"
)
```

## 四、架构设计

```
┌──────────────────────────────────────────────────────────┐
│                     TLS Server (Go)                       │
│                     localhost:8443                        │
├──────────────────────────────────────────────────────────┤
│  TLS Layer                                                │
│  ├── ClientHello 解析 → JA3/JA4 (已实现)                  │
│                                                          │
│  HTTP/2 Layer (新增)                                      │
│  ├── SETTINGS Frame   → 解析参数                          │
│  ├── WINDOW_UPDATE    → 记录窗口值                        │
│  ├── PRIORITY Frame   → 解析优先级                        │
│  └── HEADERS Frame    → 提取伪头部顺序                    │
│                                                          │
│  API Endpoint                                             │
│  └── GET /api/fingerprint                                │
│      返回: { ja3, ja4, http2: { akamai, akamai_hash } }  │
└──────────────────────────────────────────────────────────┘
```

## 五、参考实现

1. **[fingerproxy](https://github.com/wi1dcard/fingerproxy)** - Go 实现
2. **[nginx-http2-fingerprint](https://github.com/Xetera/nginx-http2-fingerprint)** - Nginx 模块
3. **[Akamai Whitepaper](https://blackhat.com/docs/eu-17/materials/eu-17-Shuster-Passive-Fingerprinting-Of-HTTP2-Clients-wp.pdf)** - 原始论文

## 六、文件改动

| 文件 | 改动 |
|------|------|
| `tls-server/main.go` | 重构，添加 HTTP/2 帧拦截 |
| `tls-server/http2.go` | 新增，HTTP/2 指纹提取逻辑 |
| `static/js/utils/api.js` | 更新，解析新的响应字段 |
| `static/js/app.js` | 更新，显示 HTTP/2 指纹 |

## 七、测试站点

- https://browserleaks.com/http2
- https://scrapfly.io/web-scraping-tools/http2-fingerprint
- https://privacycheck.sec.lrz.de/passive/fp_h2/fp_http2.html
