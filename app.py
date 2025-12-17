"""
浏览器指纹收集服务
- 前端收集: Canvas, WebGL, Audio, Screen, Navigator 等
- 后端收集: HTTP Headers, IP, 请求特征
- TLS 指纹: 通过内置 Go TLS 服务获取
"""

from flask import Flask, request, jsonify, render_template, send_from_directory
from flask_cors import CORS
from datetime import datetime
import hashlib
import json
import os
import requests
import subprocess
import signal
import sys
import atexit
import time
import sqlite3
from contextlib import contextmanager

app = Flask(__name__, static_folder='static', template_folder='templates')
CORS(app)

# 数据库路径
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'fingerprints.db')

# TLS 服务进程
tls_process = None

# 配置
TLS_SERVER_PORT = int(os.environ.get('TLS_PORT', 8443))
TLS_SERVER_HOST = os.environ.get('TLS_HOST', '0.0.0.0')
SERVER_HOST = os.environ.get('SERVER_HOST', '127.0.0.1')  # 用于前端显示的服务器地址


def get_tls_server_path():
    """获取 TLS 服务器可执行文件路径"""
    base_dir = os.path.dirname(os.path.abspath(__file__))
    tls_dir = os.path.join(base_dir, 'tls-server')

    # 根据平台选择可执行文件
    if sys.platform == 'darwin':
        return os.path.join(tls_dir, 'tls-server-darwin-arm64')
    elif sys.platform == 'linux':
        return os.path.join(tls_dir, 'tls-server-linux-amd64')
    elif sys.platform == 'win32':
        return os.path.join(tls_dir, 'tls-server-windows-amd64.exe')
    else:
        return os.path.join(tls_dir, 'tls-server-linux-amd64')


def start_tls_server():
    """启动 TLS 指纹服务"""
    global tls_process

    tls_server_path = get_tls_server_path()
    tls_dir = os.path.dirname(tls_server_path)

    if not os.path.exists(tls_server_path):
        print(f"[WARNING] TLS server not found at {tls_server_path}")
        return False

    cert_path = os.path.join(tls_dir, 'server.crt')
    key_path = os.path.join(tls_dir, 'server.key')

    if not os.path.exists(cert_path) or not os.path.exists(key_path):
        print(f"[WARNING] Certificate files not found in {tls_dir}")
        return False

    try:
        cmd = [
            tls_server_path,
            '-port', str(TLS_SERVER_PORT),
            '-host', TLS_SERVER_HOST,
            '-cert', cert_path,
            '-key', key_path,
        ]

        tls_process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            cwd=tls_dir,
        )

        # 等待服务启动
        time.sleep(0.5)

        if tls_process.poll() is None:
            print(f"[INFO] TLS Fingerprint Server started on https://{TLS_SERVER_HOST}:{TLS_SERVER_PORT}")
            return True
        else:
            print(f"[ERROR] TLS server failed to start")
            return False

    except Exception as e:
        print(f"[ERROR] Failed to start TLS server: {e}")
        return False


def stop_tls_server():
    """停止 TLS 指纹服务"""
    global tls_process
    if tls_process:
        print("[INFO] Stopping TLS server...")
        tls_process.terminate()
        try:
            tls_process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            tls_process.kill()
        tls_process = None


# 注册退出时清理
atexit.register(stop_tls_server)


def signal_handler(signum, frame):
    """处理信号"""
    stop_tls_server()
    sys.exit(0)


signal.signal(signal.SIGINT, signal_handler)
signal.signal(signal.SIGTERM, signal_handler)


# ============================================
# SQLite 数据库操作
# ============================================

@contextmanager
def get_db():
    """获取数据库连接"""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn
    finally:
        conn.close()


def init_db():
    """初始化数据库"""
    with get_db() as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS fingerprints (
                id TEXT PRIMARY KEY,
                data TEXT NOT NULL,
                ip TEXT,
                user_agent TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ''')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_created_at ON fingerprints(created_at DESC)')

        # 设备指纹表（用于设备唯一性判定）
        conn.execute('''
            CREATE TABLE IF NOT EXISTS device_fingerprints (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id TEXT UNIQUE NOT NULL,
                core_id TEXT NOT NULL,
                extended_id TEXT,
                audio TEXT,
                canvas_geometry TEXT,
                webgl_renderer TEXT,
                webgl_vendor TEXT,
                fonts TEXT,
                math TEXT,
                screen TEXT,
                timezone TEXT,
                platform TEXT,
                hardware_concurrency INTEGER,
                confidence INTEGER,
                first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                visit_count INTEGER DEFAULT 1
            )
        ''')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_core_id ON device_fingerprints(core_id)')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_device_id ON device_fingerprints(device_id)')

        # 设备访问记录表
        conn.execute('''
            CREATE TABLE IF NOT EXISTS device_visits (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id TEXT NOT NULL,
                ip_address TEXT,
                user_agent TEXT,
                match_type TEXT,
                confidence INTEGER,
                visit_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (device_id) REFERENCES device_fingerprints(device_id)
            )
        ''')
        conn.execute('CREATE INDEX IF NOT EXISTS idx_device_visits_device_id ON device_visits(device_id)')
        conn.commit()
    print(f"[INFO] Database initialized at {DB_PATH}")


def save_fingerprint(fp_id, fingerprint_data):
    """保存指纹到数据库"""
    with get_db() as conn:
        server = fingerprint_data.get('server', {})
        conn.execute(
            'INSERT OR REPLACE INTO fingerprints (id, data, ip, user_agent, created_at) VALUES (?, ?, ?, ?, ?)',
            (
                fp_id,
                json.dumps(fingerprint_data),
                server.get('ip'),
                server.get('user_agent'),
                datetime.now().isoformat()
            )
        )
        conn.commit()


def get_fingerprint(fp_id):
    """根据 ID 获取指纹"""
    with get_db() as conn:
        row = conn.execute('SELECT data FROM fingerprints WHERE id = ?', (fp_id,)).fetchone()
        if row:
            return json.loads(row['data'])
        return None


def get_all_fingerprints(limit=100):
    """获取所有指纹"""
    with get_db() as conn:
        rows = conn.execute(
            'SELECT data FROM fingerprints ORDER BY created_at DESC LIMIT ?',
            (limit,)
        ).fetchall()
        return [json.loads(row['data']) for row in rows]


def get_fingerprint_count():
    """获取指纹总数"""
    with get_db() as conn:
        row = conn.execute('SELECT COUNT(*) as count FROM fingerprints').fetchone()
        return row['count']


def delete_fingerprint(fp_id):
    """删除指纹"""
    with get_db() as conn:
        cursor = conn.execute('DELETE FROM fingerprints WHERE id = ?', (fp_id,))
        conn.commit()
        return cursor.rowcount > 0


def delete_all_fingerprints():
    """清空所有指纹"""
    with get_db() as conn:
        cursor = conn.execute('DELETE FROM fingerprints')
        conn.commit()
        return cursor.rowcount


# ============================================
# 设备匹配相关函数
# ============================================

def match_device(device_id_data):
    """
    设备匹配逻辑
    三层匹配策略：
    1. coreId 精确匹配 → 置信度 95%+，同一设备
    2. 核心信号 ≥3/4 匹配 → 置信度 70-90%，可能同一设备
    3. 环境信号相似度 > 0.6 → 置信度 50-70%，需人工确认
    """
    if not device_id_data:
        return None

    core_id = device_id_data.get('coreId') or device_id_data.get('fullCoreId', '')[:32]
    signals = device_id_data.get('signals', {})

    with get_db() as conn:
        # 第一层：精确匹配 core_id
        row = conn.execute(
            'SELECT * FROM device_fingerprints WHERE core_id = ?',
            (core_id,)
        ).fetchone()

        if row:
            # 找到匹配，更新访问记录
            conn.execute(
                'UPDATE device_fingerprints SET last_seen = ?, visit_count = visit_count + 1 WHERE core_id = ?',
                (datetime.now().isoformat(), core_id)
            )
            conn.commit()

            return {
                'match': True,
                'match_type': 'exact',
                'confidence': 95 + (5 if device_id_data.get('extendedId') == row['extended_id'] else 0),
                'device_id': row['device_id'],
                'first_seen': row['first_seen'],
                'visit_count': row['visit_count'] + 1,
            }

        # 第二层：模糊匹配核心信号
        all_devices = conn.execute('SELECT * FROM device_fingerprints').fetchall()

        best_match = None
        best_score = 0

        for device in all_devices:
            core_matches = sum([
                signals.get('audio') == device['audio'],
                signals.get('canvasGeometry') == device['canvas_geometry'],
                signals.get('webglRenderer') == device['webgl_renderer'],
                signals.get('math') == device['math'],
            ])

            if core_matches >= 3:
                score = 70 + (core_matches - 3) * 10
                if score > best_score:
                    best_score = score
                    best_match = {
                        'match': True,
                        'match_type': 'fuzzy_core',
                        'confidence': score,
                        'device_id': device['device_id'],
                        'first_seen': device['first_seen'],
                        'visit_count': device['visit_count'],
                        'core_matches': core_matches,
                    }

            # 第三层：环境信号相似度
            elif core_matches >= 2:
                env_matches = sum([
                    signals.get('screen') == device['screen'],
                    signals.get('timezone') == device['timezone'],
                    signals.get('platform') == device['platform'],
                    signals.get('hardwareConcurrency') == device['hardware_concurrency'],
                ])
                env_total = 4
                env_similarity = env_matches / env_total

                if env_similarity > 0.6:
                    score = 50 + env_similarity * 20
                    if score > best_score:
                        best_score = score
                        best_match = {
                            'match': True,
                            'match_type': 'fuzzy_env',
                            'confidence': int(score),
                            'device_id': device['device_id'],
                            'first_seen': device['first_seen'],
                            'visit_count': device['visit_count'],
                            'core_matches': core_matches,
                            'env_similarity': env_similarity,
                        }

        if best_match:
            # 更新匹配设备的访问记录
            conn.execute(
                'UPDATE device_fingerprints SET last_seen = ?, visit_count = visit_count + 1 WHERE device_id = ?',
                (datetime.now().isoformat(), best_match['device_id'])
            )
            conn.commit()
            best_match['visit_count'] += 1
            return best_match

    # 新设备
    return {
        'match': False,
        'match_type': 'new',
        'confidence': 0,
        'device_id': None,
    }


def save_device_fingerprint(device_id_data, ip_address, user_agent):
    """保存设备指纹"""
    if not device_id_data:
        return None

    core_id = device_id_data.get('coreId') or device_id_data.get('fullCoreId', '')[:32]
    extended_id = device_id_data.get('extendedId') or device_id_data.get('fullExtendedId', '')[:32]
    signals = device_id_data.get('signals', {})

    # 使用 fullCoreId 作为 device_id（更稳定）
    device_id = device_id_data.get('fullCoreId', core_id)

    with get_db() as conn:
        try:
            conn.execute('''
                INSERT INTO device_fingerprints (
                    device_id, core_id, extended_id,
                    audio, canvas_geometry, webgl_renderer, webgl_vendor,
                    fonts, math, screen, timezone, platform, hardware_concurrency,
                    confidence
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                device_id,
                core_id,
                extended_id,
                signals.get('audio'),
                signals.get('canvasGeometry'),
                signals.get('webglRenderer'),
                signals.get('webglVendor'),
                signals.get('fonts'),
                signals.get('math'),
                signals.get('screen'),
                signals.get('timezone'),
                signals.get('platform'),
                signals.get('hardwareConcurrency'),
                device_id_data.get('confidence', 0),
            ))
            conn.commit()
            return device_id
        except sqlite3.IntegrityError:
            # 设备已存在，更新
            conn.execute('''
                UPDATE device_fingerprints SET
                    extended_id = ?, last_seen = ?, visit_count = visit_count + 1
                WHERE device_id = ?
            ''', (extended_id, datetime.now().isoformat(), device_id))
            conn.commit()
            return device_id


def record_device_visit(device_id, ip_address, user_agent, match_type, confidence):
    """记录设备访问"""
    with get_db() as conn:
        conn.execute('''
            INSERT INTO device_visits (device_id, ip_address, user_agent, match_type, confidence)
            VALUES (?, ?, ?, ?, ?)
        ''', (device_id, ip_address, user_agent, match_type, confidence))
        conn.commit()


# 初始化数据库
init_db()


def get_client_ip():
    """获取客户端真实 IP"""
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    elif request.headers.get('X-Real-IP'):
        return request.headers.get('X-Real-IP')
    else:
        return request.remote_addr


def get_ip_info(ip):
    """查询 IP 详细信息（地区、ISP、纯净度、时区等）"""
    # 本地 IP 不查询
    if ip in ('127.0.0.1', 'localhost', '::1') or ip.startswith('192.168.') or ip.startswith('10.'):
        return {
            'ip': ip,
            'type': 'local',
            'country': '本地网络',
            'country_code': 'LOCAL',
            'region': '-',
            'city': '-',
            'isp': '本地',
            'org': '-',
            'timezone': 'Local',
            'is_proxy': False,
            'is_vpn': False,
            'is_datacenter': False,
            'is_mobile': False,
            'risk_score': 0,
            'risk_level': '安全',
        }

    try:
        # 使用 ip-api.com（免费，支持代理检测和时区）
        resp = requests.get(
            f'http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,regionName,city,isp,org,proxy,hosting,mobile,timezone',
            timeout=5
        )
        data = resp.json()

        if data.get('status') == 'success':
            # 计算风险分数
            risk_score = 0
            if data.get('proxy'):
                risk_score += 40
            if data.get('hosting'):
                risk_score += 30
            if data.get('mobile'):
                risk_score += 10

            if risk_score >= 50:
                risk_level = '高风险'
            elif risk_score >= 20:
                risk_level = '中风险'
            else:
                risk_level = '低风险'

            return {
                'ip': ip,
                'type': 'public',
                'country': data.get('country', '未知'),
                'country_code': data.get('countryCode', ''),
                'region': data.get('regionName', '未知'),
                'city': data.get('city', '未知'),
                'isp': data.get('isp', '未知'),
                'org': data.get('org', '未知'),
                'timezone': data.get('timezone', '未知'),
                'is_proxy': data.get('proxy', False),
                'is_vpn': data.get('proxy', False),
                'is_datacenter': data.get('hosting', False),
                'is_mobile': data.get('mobile', False),
                'risk_score': risk_score,
                'risk_level': risk_level,
            }
    except Exception as e:
        print(f'[WARN] IP info query failed: {e}')

    return {
        'ip': ip,
        'type': 'unknown',
        'country': '查询失败',
        'country_code': '',
        'region': '-',
        'city': '-',
        'isp': '-',
        'org': '-',
        'timezone': '-',
        'is_proxy': None,
        'is_vpn': None,
        'is_datacenter': None,
        'is_mobile': None,
        'risk_score': -1,
        'risk_level': '未知',
    }


def collect_server_fingerprint():
    """服务器端收集的指纹信息"""
    headers = dict(request.headers)

    # 移除敏感信息
    headers.pop('Cookie', None)
    headers.pop('Authorization', None)

    return {
        'ip': get_client_ip(),
        'method': request.method,
        'path': request.path,
        'http_version': request.environ.get('SERVER_PROTOCOL', ''),
        'headers': headers,
        'accept': request.headers.get('Accept', ''),
        'accept_language': request.headers.get('Accept-Language', ''),
        'accept_encoding': request.headers.get('Accept-Encoding', ''),
        'user_agent': request.headers.get('User-Agent', ''),
        'sec_ch_ua': request.headers.get('Sec-Ch-Ua', ''),
        'sec_ch_ua_mobile': request.headers.get('Sec-Ch-Ua-Mobile', ''),
        'sec_ch_ua_platform': request.headers.get('Sec-Ch-Ua-Platform', ''),
        'sec_fetch_site': request.headers.get('Sec-Fetch-Site', ''),
        'sec_fetch_mode': request.headers.get('Sec-Fetch-Mode', ''),
        'sec_fetch_dest': request.headers.get('Sec-Fetch-Dest', ''),
        'connection': request.headers.get('Connection', ''),
        'collected_at': datetime.now().isoformat(),
    }


def generate_browser_fingerprint_id(data):
    """生成浏览器指纹 ID（基于 Canvas, WebGL, Audio 等稳定特征）"""
    client = data.get('client', {}).copy()

    # 移除变化字段
    client.pop('timestamp', None)
    client.pop('hash', None)
    client.pop('timing', None)
    client.pop('tls', None)  # TLS 单独处理
    client.pop('incognito', None)  # 无痕模式检测结果不影响 ID

    # 移除 screen 中的窗口相关字段（会随窗口变化）
    if 'screen' in client:
        screen = client['screen'].copy() if isinstance(client['screen'], dict) else {}
        screen.pop('innerWidth', None)
        screen.pop('innerHeight', None)
        screen.pop('outerWidth', None)
        screen.pop('outerHeight', None)
        screen.pop('availWidth', None)
        screen.pop('availHeight', None)
        screen.pop('screenX', None)  # 窗口位置会随拖动变化
        screen.pop('screenY', None)
        client['screen'] = screen

    # 移除 navigator 中不稳定的字段
    if 'navigator' in client and isinstance(client['navigator'], dict):
        navigator = client['navigator'].copy()
        navigator.pop('connection', None)  # effectiveType/downlink/rtt 都会随网络变化
        navigator.pop('languages', None)  # 无痕模式会简化 languages 数组
        navigator.pop('doNotTrack', None)  # 无痕模式可能改变 DNT 设置
        client['navigator'] = navigator

    # 移除 audio 中不稳定的字段
    if 'audio' in client and isinstance(client['audio'], dict):
        audio = client['audio'].copy()
        audio.pop('fingerprint', None)  # 浮点数计算可能有细微差异
        audio.pop('baseLatency', None)  # 延迟会变化
        audio.pop('outputLatency', None)
        audio.pop('state', None)  # 第一次可能是 timeout，后续是 collected
        audio.pop('error', None)  # 错误信息可能变化
        client['audio'] = audio

    # 移除 storage 中异步检测的字段
    if 'storage' in client and isinstance(client['storage'], dict):
        storage = client['storage'].copy()
        storage.pop('indexedDBEnabled', None)  # indexedDB.open() 是异步的，第一次可能为 false
        client['storage'] = storage

    # 移除 automation 中不稳定的字段
    if 'automation' in client and isinstance(client['automation'], dict):
        automation = client['automation'].copy()
        automation.pop('score', None)  # score 依赖于异步检测的结果
        if 'checks' in automation and isinstance(automation['checks'], dict):
            checks = automation['checks'].copy()
            checks.pop('permissionsInconsistent', None)  # 异步检测，返回后才设置
            checks.pop('languagesLengthZero', None)  # 依赖 languages 数组，无痕模式下不同
            automation['checks'] = checks
        client['automation'] = automation

    stable_data = {
        'client': client,
        'user_agent': data.get('server', {}).get('user_agent', ''),
        # 'accept_language' 可能在无痕模式下不同，不纳入计算
        'accept_encoding': data.get('server', {}).get('accept_encoding', ''),
    }
    content = json.dumps(stable_data, sort_keys=True)
    return hashlib.sha256(content.encode()).hexdigest()[:16]


def generate_tls_fingerprint_id(tls_data):
    """生成 TLS 指纹 ID（基于稳定的 TLS 特征，排除 GREASE 和随机值，排序以消除顺序差异）"""
    if not tls_data:
        return None

    # 只提取稳定字段，并排序以消除顺序随机化的影响
    stable_tls = {
        'tls_version': tls_data.get('tls_version'),
        'cipher_suite': tls_data.get('cipher_suite'),
        # 过滤掉 GREASE 值的 ciphers（保持顺序，因为 cipher 优先级有意义）
        'ciphers_stable': [c for c in tls_data.get('ciphers', []) if 'GREASE' not in c],
        # 过滤掉 GREASE 值的 extensions，并排序（Chrome 会随机化顺序）
        'extensions_stable': sorted([e.get('name') for e in tls_data.get('extensions', []) if 'GREASE' not in e.get('name', '')]),
        # 过滤掉 GREASE 的 supported_groups
        'groups_stable': [g for g in tls_data.get('supported_groups', []) if 'GREASE' not in g],
        # 过滤掉 GREASE 的 supported_versions
        'versions_stable': [v for v in tls_data.get('supported_versions', []) if 'GREASE' not in v],
    }

    content = json.dumps(stable_tls, sort_keys=True)
    return hashlib.sha256(content.encode()).hexdigest()[:16]


def generate_combined_fingerprint_id(browser_id, tls_id):
    """生成综合指纹 ID（浏览器 + TLS）"""
    if not browser_id:
        return None
    combined = browser_id + (tls_id or '')
    return hashlib.sha256(combined.encode()).hexdigest()[:16]


@app.route('/')
def index():
    """主页 - 指纹收集页面"""
    return render_template('index.html')


@app.route('/history')
def history():
    """历史记录页面"""
    return render_template('history.html')


@app.route('/api-docs')
def api_docs():
    """API 文档页面"""
    return render_template('api.html')


@app.route('/static/<path:filename>')
def serve_static(filename):
    return send_from_directory('static', filename)


@app.route('/api/collect', methods=['POST'])
def collect_fingerprint():
    """接收前端收集的指纹并合并服务端数据"""
    try:
        client_fp = request.json or {}
        server_fp = collect_server_fingerprint()

        # 合并指纹
        full_fingerprint = {
            'client': client_fp,
            'server': server_fp,
        }

        # 生成浏览器指纹 ID
        browser_id = generate_browser_fingerprint_id(full_fingerprint)

        # TLS 指纹 ID（如果有的话）
        tls_data = client_fp.get('tls')
        tls_id = generate_tls_fingerprint_id(tls_data) if tls_data else None

        # 综合指纹 ID
        combined_id = generate_combined_fingerprint_id(browser_id, tls_id)

        # 设备ID处理
        device_id_data = client_fp.get('deviceId')
        device_match = None
        device_id = None

        if device_id_data:
            # 设备匹配
            device_match = match_device(device_id_data)

            if device_match and device_match.get('match'):
                # 匹配到已有设备
                device_id = device_match['device_id']
            else:
                # 新设备，保存
                device_id = save_device_fingerprint(
                    device_id_data,
                    server_fp.get('ip'),
                    server_fp.get('user_agent')
                )
                if device_match:
                    device_match['device_id'] = device_id

            # 记录访问
            if device_id:
                record_device_visit(
                    device_id,
                    server_fp.get('ip'),
                    server_fp.get('user_agent'),
                    device_match.get('match_type', 'new') if device_match else 'new',
                    device_match.get('confidence', 0) if device_match else 0
                )

        # 使用浏览器 ID 作为主 ID
        full_fingerprint['id'] = browser_id
        full_fingerprint['browser_id'] = browser_id
        full_fingerprint['tls_id'] = tls_id
        full_fingerprint['combined_id'] = combined_id

        # 存储到 SQLite
        save_fingerprint(browser_id, full_fingerprint)

        response_data = {
            'success': True,
            'id': browser_id,
            'browser_id': browser_id,
            'tls_id': tls_id,
            'combined_id': combined_id,
            'fingerprint': full_fingerprint,
        }

        # 添加设备匹配信息
        if device_match:
            response_data['device_match'] = device_match

        return jsonify(response_data)

    except Exception as e:
        return jsonify({'success': False, 'error': str(e)}), 500


@app.route('/api/fingerprint/<fp_id>', methods=['GET'])
def get_fingerprint_by_id(fp_id):
    """获取已存储的指纹"""
    fp = get_fingerprint(fp_id)
    if fp:
        return jsonify({'success': True, 'fingerprint': fp})
    return jsonify({'success': False, 'error': 'Not found'}), 404


@app.route('/api/fingerprints', methods=['GET'])
def list_fingerprints():
    """列出所有指纹"""
    return jsonify({
        'success': True,
        'count': get_fingerprint_count(),
        'fingerprints': get_all_fingerprints(limit=100)
    })


@app.route('/api/fingerprint/<fp_id>/delete', methods=['GET', 'POST'])
def delete_fingerprint_by_id(fp_id):
    """删除指定指纹"""
    if delete_fingerprint(fp_id):
        return jsonify({'success': True, 'message': f'Fingerprint {fp_id} deleted'})
    return jsonify({'success': False, 'error': 'Fingerprint not found'}), 404


@app.route('/api/fingerprints/delete', methods=['GET', 'POST'])
def clear_all_fingerprints():
    """清空所有指纹"""
    count = delete_all_fingerprints()
    return jsonify({
        'success': True,
        'message': f'Deleted {count} fingerprint(s)'
    })


@app.route('/api/server-info', methods=['GET'])
def server_info():
    """仅返回服务端收集的信息（用于测试）"""
    return jsonify(collect_server_fingerprint())


@app.route('/api/ip-info', methods=['GET'])
def ip_info():
    """获取客户端 IP 详细信息（地区、ISP、纯净度等）"""
    client_ip = get_client_ip()
    info = get_ip_info(client_ip)
    return jsonify({
        'success': True,
        'ip_info': info,
    })


@app.route('/api/ip-info/<ip>', methods=['GET'])
def ip_info_by_ip(ip):
    """查询指定 IP 的详细信息"""
    info = get_ip_info(ip)
    return jsonify({
        'success': True,
        'ip_info': info,
    })


@app.route('/api/tls-check', methods=['GET'])
def tls_check():
    """
    检查 TLS 服务状态
    """
    global tls_process
    is_running = tls_process is not None and tls_process.poll() is None

    return jsonify({
        'tls_server_running': is_running,
        'tls_server_port': TLS_SERVER_PORT,
        'tls_server_url': f'https://{SERVER_HOST}:{TLS_SERVER_PORT}',
        'message': 'TLS server is running' if is_running else 'TLS server is not running',
    })


@app.route('/api/tls', methods=['GET'])
def get_tls_fingerprint():
    """
    获取客户端的 TLS 指纹
    用户需要先访问 TLS 服务器建立连接，然后通过此接口获取指纹
    """
    client_ip = get_client_ip()

    try:
        # 从本地 TLS 服务获取指纹
        tls_url = f'https://127.0.0.1:{TLS_SERVER_PORT}/api/fingerprint'
        resp = requests.get(tls_url, timeout=5, verify=False)
        data = resp.json()

        return jsonify({
            'success': True,
            'client_ip': client_ip,
            'fingerprint': data.get('fingerprint'),
            'note': 'TLS fingerprint from local Go server'
        })

    except requests.exceptions.ConnectionError:
        return jsonify({
            'success': False,
            'error': 'TLS server is not running',
            'suggestion': 'Start the server with TLS support'
        }), 503

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500


@app.route('/api/config', methods=['GET'])
def get_config():
    """
    返回服务器配置，供前端使用
    """
    return jsonify({
        'server_host': SERVER_HOST,
        'tls_port': TLS_SERVER_PORT,
        'tls_url': f'https://{SERVER_HOST}:{TLS_SERVER_PORT}',
        'api_url': f'https://{SERVER_HOST}:{TLS_SERVER_PORT}/api/fingerprint',
    })


if __name__ == '__main__':
    # 启动 TLS 指纹服务
    print('[INFO] Starting services...')
    start_tls_server()

    print(f'[INFO] Fingerprint Collector running on http://0.0.0.0:5000')
    print(f'[INFO] TLS Server: https://{SERVER_HOST}:{TLS_SERVER_PORT}')
    print(f'[INFO] Set SERVER_HOST env to change the public hostname (current: {SERVER_HOST})')

    # 启动 Flask（关闭 reloader 避免启动两次 TLS 服务）
    app.run(host='0.0.0.0', port=5000, debug=True, use_reloader=False)
