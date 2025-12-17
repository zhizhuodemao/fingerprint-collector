/**
 * Audio Collector
 * 收集音频指纹
 */

/**
 * 收集音频指纹
 * @returns {Promise<Object>} 音频指纹数据
 */
export async function collectAudio() {
    try {
        const audioContext = new (window.AudioContext || window.webkitAudioContext)();

        // 创建音频节点
        const oscillator = audioContext.createOscillator();
        const analyser = audioContext.createAnalyser();
        const gainNode = audioContext.createGain();
        const scriptProcessor = audioContext.createScriptProcessor(4096, 1, 1);

        // 设置参数
        oscillator.type = 'triangle';
        oscillator.frequency.setValueAtTime(10000, audioContext.currentTime);
        gainNode.gain.setValueAtTime(0, audioContext.currentTime);

        // 连接节点
        oscillator.connect(analyser);
        analyser.connect(scriptProcessor);
        scriptProcessor.connect(gainNode);
        gainNode.connect(audioContext.destination);

        // 收集音频数据
        let audioData = [];
        let resolved = false;

        return new Promise((resolve) => {
            const cleanup = () => {
                if (resolved) return;
                resolved = true;
                try { oscillator.stop(); } catch (e) {}
                if (audioContext.state !== 'closed') {
                    audioContext.close().catch(() => {});
                }
            };

            scriptProcessor.onaudioprocess = (event) => {
                if (resolved) return;

                const inputData = event.inputBuffer.getChannelData(0);
                for (let i = 0; i < inputData.length; i++) {
                    if (inputData[i] !== 0) {
                        audioData.push(inputData[i]);
                    }
                }

                if (audioData.length > 100) {
                    const sum = audioData.slice(0, 100).reduce((a, b) => a + Math.abs(b), 0);
                    const result = {
                        supported: true,
                        sampleRate: audioContext.sampleRate,
                        state: 'collected',
                        fingerprint: sum.toString(),
                        baseLatency: audioContext.baseLatency,
                        outputLatency: audioContext.outputLatency,
                        channelCount: audioContext.destination.channelCount,
                        maxChannelCount: audioContext.destination.maxChannelCount,
                    };
                    cleanup();
                    resolve(result);
                }
            };

            oscillator.start(0);

            // 超时处理
            setTimeout(() => {
                if (resolved) return;
                const result = {
                    supported: true,
                    sampleRate: audioContext.sampleRate,
                    state: 'timeout',
                    fingerprint: audioData.length > 0 ?
                        audioData.slice(0, 100).reduce((a, b) => a + Math.abs(b), 0).toString() : null,
                };
                cleanup();
                resolve(result);
            }, 1000);
        });
    } catch (error) {
        return {
            supported: false,
            error: error.message,
        };
    }
}
