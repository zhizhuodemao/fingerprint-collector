/**
 * WebRTC Collector
 * 通过 WebRTC 检测 IP 地址
 */

/**
 * 通过 WebRTC 获取本地和公网 IP
 * @returns {Promise<Object>} IP 地址信息
 */
export function getWebRtcIps() {
    return new Promise((resolve, reject) => {
        const ips = { local: [], public: [] };
        const seen = new Set();

        // 检查 WebRTC 是否支持
        if (!window.RTCPeerConnection) {
            reject(new Error('WebRTC not supported'));
            return;
        }

        const pc = new RTCPeerConnection({
            iceServers: [
                { urls: 'stun:stun.l.google.com:19302' },
                { urls: 'stun:stun1.l.google.com:19302' },
            ]
        });

        pc.createDataChannel('');

        pc.onicecandidate = (event) => {
            if (!event.candidate) {
                pc.close();
                resolve(ips);
                return;
            }

            const candidate = event.candidate.candidate;
            // 解析 IP 地址
            const ipRegex = /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/;
            const match = candidate.match(ipRegex);

            if (match && !seen.has(match[1])) {
                const ip = match[1];
                seen.add(ip);

                // 判断是本地 IP 还是公网 IP
                if (isPrivateIp(ip)) {
                    ips.local.push(ip);
                } else {
                    ips.public.push(ip);
                }
            }
        };

        pc.createOffer()
            .then(offer => pc.setLocalDescription(offer))
            .catch(reject);

        // 超时处理
        setTimeout(() => {
            pc.close();
            resolve(ips);
        }, 3000);
    });
}

/**
 * 判断是否为私有 IP
 * @param {string} ip - IP 地址
 * @returns {boolean} 是否为私有 IP
 */
function isPrivateIp(ip) {
    return ip.startsWith('10.') ||
        ip.startsWith('192.168.') ||
        ip.startsWith('172.16.') ||
        ip.startsWith('172.17.') ||
        ip.startsWith('172.18.') ||
        ip.startsWith('172.19.') ||
        ip.startsWith('172.2') ||
        ip.startsWith('172.30.') ||
        ip.startsWith('172.31.') ||
        ip === '127.0.0.1';
}
