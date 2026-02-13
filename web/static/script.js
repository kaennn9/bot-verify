// Advanced Security & Verification Script
class SecurityChecker {
    constructor() {
        this.fingerprint = '';
        this.vpnDetected = false;
        this.proxyDetected = false;
        this.botScore = 0;
    }

    async init() {
        // Get URL parameters
        const params = new URLSearchParams(window.location.search);
        const code = params.get('code');
        const userId = params.get('user');

        if (!code || !userId) {
            this.showError('Invalid verification link', 'Missing parameters');
            return;
        }

        document.getElementById('code').value = code;
        document.getElementById('user_id').value = userId;

        // Run security checks
        await this.runSecurityChecks();
        
        // Load user data
        await this.loadUserData(code);
        
        // Setup form
        this.setupForm();
    }

    async runSecurityChecks() {
        // 1. Browser Fingerprinting
        await this.generateFingerprint();
        
        // 2. VPN/Proxy Detection
        await this.detectVPN();
        
        // 3. Bot Detection
        await this.detectBot();
        
        // 4. Check if all passed
        if (this.botScore > 70) {
            this.showChallenge();
        } else {
            this.enableSubmit();
        }
    }

    async generateFingerprint() {
        const components = [
            navigator.userAgent,
            navigator.language,
            screen.colorDepth,
            screen.availWidth + 'x' + screen.availHeight,
            new Date().getTimezoneOffset(),
            !!window.sessionStorage,
            !!window.localStorage,
            navigator.hardwareConcurrency || 'unknown',
            navigator.platform
        ];

        // Canvas fingerprinting
        try {
            const canvas = document.createElement('canvas');
            const ctx = canvas.getContext('2d');
            ctx.textBaseline = 'top';
            ctx.font = '14px Arial';
            ctx.fillText('Double Counter', 2, 2);
            components.push(canvas.toDataURL());
        } catch (e) {
            components.push('canvas-blocked');
        }

        // WebGL fingerprinting
        try {
            const gl = document.createElement('canvas').getContext('webgl');
            if (gl) {
                const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
                if (debugInfo) {
                    components.push(gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL));
                    components.push(gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL));
                }
            }
        } catch (e) {}

        // Generate hash
        const str = components.join('###');
        this.fingerprint = await this.hashString(str);
        document.getElementById('fingerprint').value = this.fingerprint;
        
        this.updateCheck('fingerprintCheck', 'passed', '✅ Fingerprint generated');
    }

    async detectVPN() {
        try {
            // Check for common VPN indicators
            const response = await fetch('https://ipapi.co/json/');
            const data = await response.json();
            
            // Check for hosting provider / datacenter
            if (data.org && /(hosting|datacenter|cloud|server|vpn|proxy)/i.test(data.org)) {
                this.vpnDetected = true;
                this.proxyDetected = true;
            }
            
            // Check for mismatched timezone
            const tzOffset = new Date().getTimezoneOffset();
            const expectedTz = this.getTimezoneOffset(data.timezone);
            if (Math.abs(tzOffset - expectedTz) > 60) {
                this.vpnDetected = true;
            }

            document.getElementById('vpn_status').value = this.vpnDetected ? 'detected' : 'clean';
            document.getElementById('proxy_status').value = this.proxyDetected ? 'detected' : 'clean';
            
            if (this.vpnDetected) {
                this.updateCheck('vpnCheck', 'failed', '⚠️ VPN/Proxy detected');
                this.botScore += 30;
            } else {
                this.updateCheck('vpnCheck', 'passed', '✅ No VPN detected');
            }
        } catch (e) {
            this.updateCheck('vpnCheck', 'failed', '⚠️ Check failed');
            this.botScore += 10;
        }
    }

    async detectBot() {
        let score = 0;
        
        // Check for automation indicators
        if (navigator.webdriver) score += 50;
        if (window.callPhantom || window._phantom) score += 50;
        if (window.Buffer || window.process) score += 40;
        if (navigator.plugins.length === 0) score += 20;
        if (navigator.languages === undefined) score += 20;
        
        // Mouse movement check
        let mouseMoved = false;
        document.addEventListener('mousemove', () => { mouseMoved = true; }, { once: true });
        
        setTimeout(() => {
            if (!mouseMoved) score += 15;
        }, 1000);

        // Check for headless chrome
        if (/HeadlessChrome/.test(navigator.userAgent)) score += 50;
        
        this.botScore = score;
        
        if (score > 50) {
            this.updateCheck('browserCheck', 'failed', '⚠️ Suspicious browser detected');
        } else {
            this.updateCheck('browserCheck', 'passed', '✅ Browser verified');
        }
    }

    showChallenge() {
        document.getElementById('challengeBox').style.display = 'block';
        const container = document.getElementById('captchaContainer');
        
        // Generate emoji challenge
        const emojis = ['🐶', '🐱', '🐭', '🐹', '🐰', '🦊', '🐻', '🐼'];
        const target = emojis[Math.floor(Math.random() * emojis.length)];
        const options = this.shuffle([...emojis]).slice(0, 6);
        
        if (!options.includes(target)) {
            options[Math.floor(Math.random() * options.length)] = target;
        }

        container.innerHTML = `<p>Click on: <strong>${target}</strong></p>`;
        
        options.forEach(emoji => {
            const div = document.createElement('div');
            div.className = 'captcha-item';
            div.textContent = emoji;
            div.onclick = () => {
                if (emoji === target) {
                    div.classList.add('selected');
                    this.challengePassed = true;
                    this.enableSubmit();
                    container.innerHTML = '<p style="color: green;">✅ Challenge passed!</p>';
                } else {
                    div.style.animation = 'shake 0.5s';
                    this.challengePassed = false;
                }
            };
            container.appendChild(div);
        });
    }

    async loadUserData(code) {
        try {
            const response = await fetch(`/api/check/${code}`);
            const data = await response.json();
            
            if (!data.found) {
                window.location.href = '/failed.html?error=Invalid or expired code';
                return;
            }

            document.getElementById('serverName').textContent = data.server || 'Unknown Server';
            document.getElementById('username').textContent = data.username || 'Unknown';
            document.getElementById('userId').textContent = `ID: ${data.user_id || '...'}`;
            document.getElementById('avatar').src = data.avatar_url || '';
        } catch (e) {
            console.error('Failed to load user data:', e);
        }
    }

    setupForm() {
        document.getElementById('verifyForm').addEventListener('submit', async (e) => {
            e.preventDefault();
            await this.submitVerification();
        });
    }

    async submitVerification() {
        const btn = document.getElementById('submitBtn');
        const loading = document.getElementById('loading');
        const status = document.getElementById('status');

        btn.disabled = true;
        btn.classList.add('loading');
        loading.style.display = 'block';
        status.style.display = 'none';

        try {
            const response = await fetch('/api/verify', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    code: document.getElementById('code').value,
                    user_id: document.getElementById('user_id').value,
                    fingerprint: this.fingerprint,
                    vpn_status: document.getElementById('vpn_status').value,
                    proxy_status: document.getElementById('proxy_status').value,
                    user_agent: navigator.userAgent,
                    screen_resolution: `${screen.width}x${screen.height}`,
                    timezone: Intl.DateTimeFormat().resolvedOptions().timeZone
                })
            });

            const result = await response.json();

            if (result.success) {
                window.location.href = `/success.html?server=${encodeURIComponent(result.server)}`;
            } else {
                status.className = 'status error';
                status.textContent = '❌ ' + result.error;
                status.style.display = 'block';
                btn.disabled = false;
                btn.classList.remove('loading');
            }
        } catch (error) {
            status.className = 'status error';
            status.textContent = '❌ Network error. Please try again.';
            status.style.display = 'block';
            btn.disabled = false;
            btn.classList.remove('loading');
        }

        loading.style.display = 'none';
    }

    updateCheck(id, status, text) {
        const el = document.getElementById(id);
        el.className = `check-item ${status}`;
        el.querySelector('span:last-child').textContent = text;
    }

    enableSubmit() {
        const btn = document.getElementById('submitBtn');
        btn.disabled = false;
        btn.querySelector('.btn-text').textContent = '✅ Complete Verification';
    }

    showError(title, details) {
        window.location.href = `/failed.html?error=${encodeURIComponent(title)}&details=${encodeURIComponent(details)}`;
    }

    async hashString(str) {
        const buf = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
        return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
    }

    getTimezoneOffset(timezone) {
        const now = new Date();
        const tzDate = new Date(now.toLocaleString('en-US', { timeZone: timezone }));
        const utcDate = new Date(now.toLocaleString('en-US', { timeZone: 'UTC' }));
        return (tzDate - utcDate) / 60000;
    }

    shuffle(array) {
        for (let i = array.length - 1; i > 0; i--) {
            const j = Math.floor(Math.random() * (i + 1));
            [array[i], array[j]] = [array[j], array[i]];
        }
        return array;
    }
}
document.addEventListener('DOMContentLoaded', () => {
    new SecurityChecker().init();
});