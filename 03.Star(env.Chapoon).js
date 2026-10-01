import { connect } from 'cloudflare:sockets';

const Config = {

  proxyIPs: ['nima.nscl.ir:443', 'di.nscl.ir:443', 'tr.diam4.ggff.net:443'],
  
  socks5: {
    enabled: false,
    relayMode: false,
    address: '',
  },

  fromEnv(env) {
    const rawProxy = env.PROXYIP || this.proxyIPs.join(',');
    const proxyList = rawProxy.split(',').map((s) => s.trim()).filter(Boolean);
    const selectedProxyIP =
      proxyList[Math.floor(Math.random() * proxyList.length)] || this.proxyIPs[0];
    const [proxyHost, proxyPort = '443'] = selectedProxyIP.split(':');

    return {
      userID: env.UUID || '',
      proxyIP: proxyHost,
      proxyPort: proxyPort,
      proxyAddress: selectedProxyIP,
      proxyPool: proxyList.length ? proxyList : [...this.proxyIPs],
      socks5: {
        enabled: !!env.SOCKS5,
        relayMode: env.SOCKS5_RELAY === 'true' || this.socks5.relayMode,
        address: env.SOCKS5 || this.socks5.address,
      },
    };
  },
}; 
const CONST = {
  ED_PARAMS: { ed: 2560, eh: 'Sec-WebSocket-Protocol' },
  AT_SYMBOL: '@',
  VLESS_PROTOCOL: 'vless',
  WS_READY_STATE_OPEN: 1,
  WS_READY_STATE_CLOSING: 2,
};

const CIPHER_SUITES = 'TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256';

const DEFAULT_FRAGMENT = {
    tcp: [
        { type: 'fragment', settings: { packets: 'tlshello', lengths: ['0', '104', '1'], delays: ['0'], maxSplit: '0' } },
        { type: 'fragment', settings: { packets: '1-1', lengths: ['114', '1'], delays: ['1'], maxSplit: '11' } },
    ],
};

const IPV4_REGEX = /^\d{1,3}(\.\d{1,3}){3}$/;

async function resolveIPv4(hostname) {
    if (IPV4_REGEX.test(hostname)) return hostname;
    try {
        const resp = await fetch(
            `https://1.1.1.1/dns-query?name=${encodeURIComponent(hostname)}&type=A`,
            { headers: { accept: "application/dns-json" } }
        );
        const data = await resp.json();
        const answer = (data.Answer || []).find((a) => a.type === 1);
        return answer ? answer.data : null;
    } catch (error) {
        return null;
    }
}

function toNAT64Address(ipv4) {
    if (!ipv4 || !IPV4_REGEX.test(ipv4)) return null;
    const octets = ipv4.split(".").map(Number);
    if (octets.some((n) => n < 0 || n > 255)) return null;
    const hex = octets.map((n) => n.toString(16).padStart(2, "0"));
    return `64:ff9b::${hex[0]}${hex[1]}:${hex[2]}${hex[3]}`;
}

const MAX_LOGIN_ATTEMPTS = 5;
const LOGIN_WINDOW_MS = 15 * 60 * 1000;

async function checkAuth(env, req) {
    try {
        const cookieHeader = req.headers.get('Cookie');
        let sessionToken;

        if (cookieHeader) {
            const cookies = Object.fromEntries(cookieHeader.split(';').map(c => {
                const idx = c.indexOf('=');
                const k = c.slice(0, idx).trim();
                const v = idx >= 0 ? c.slice(idx + 1).trim() : '';
                return [k, v];
            }));
            sessionToken = cookies.session_token;
        }

        if (!sessionToken) {
            const auth = req.headers.get('Authorization') || req.headers.get('authorization');
            if (auth && auth.startsWith('Bearer ')) {
                sessionToken = auth.slice(7).trim();
            }
        }

        if (!sessionToken) return false;

        const storedToken = await env.Chapoon.get('session_token');
        return sessionToken === storedToken;
    } catch (error) {
        return false;
    }
}

async function setSessionToken(env, token) {
    await env.Chapoon.put('session_token', token);
}

async function clearSessionToken(env) {
    await env.Chapoon.delete('session_token');
}

async function saveToKV(env, configData) {
  try {
    await env.Chapoon.put('user_config', JSON.stringify(configData));
    return { success: true };
  } catch (error) {
    return { success: false, error: error.message };
  }
}

async function loadFromKV(env) {
  const defaults = {
    userID: '',
    custom_ips: []
  };

  try {
    const data = await env.Chapoon.get('user_config', 'json');
    return Object.assign({}, defaults, data || {});
  } catch (error) {
    return defaults;
  }
}

async function getFragmentConfig(env) {
    try {
        const raw = await env.Chapoon.get('fragment_config');
        if (raw) {
            const parsed = JSON.parse(raw);
            if (parsed && typeof parsed === 'object' && Array.isArray(parsed.tcp)) {
                return parsed;
            }
        }
    } catch (error) {
        console.error('Error loading fragment config:', error);
    }
    return DEFAULT_FRAGMENT;
}

async function handleFragmentApi(request, env) {
    const json = (obj, status = 200) => new Response(JSON.stringify(obj), {
        status,
        headers: { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' },
    });

    if (!(await checkAuth(env, request))) return json({ error: 'Unauthorized' }, 401);

    try {
        if (request.method === 'GET') {
            return json({ config: await getFragmentConfig(env) });
        }

        if (request.method === 'POST') {
            const body = await request.json();
            let config = body && body.config;
            if (typeof config === 'string') {
                try { config = JSON.parse(config); } catch (e) {
                    return json({ error: 'Invalid JSON' }, 400);
                }
            }
            if (!config || typeof config !== 'object' || !Array.isArray(config.tcp) || config.tcp.length === 0) {
                return json({ error: 'Fragment must contain a non-empty "tcp" array' }, 400);
            }
            await env.Chapoon.put('fragment_config', JSON.stringify(config));
            return json({ success: true, config });
        }

        if (request.method === 'DELETE') {
            await env.Chapoon.delete('fragment_config');
            return json({ success: true, config: DEFAULT_FRAGMENT });
        }

        return json({ error: 'Method not allowed' }, 405);
    } catch (error) {
        return json({ error: 'Server error: ' + error.message }, 500);
    }
}

async function checkRateLimit(env, ip) {
    const key = `rate_limit_${ip}`;
    const attempts = await env.Chapoon.get(key);
    if (attempts && parseInt(attempts) >= MAX_LOGIN_ATTEMPTS) {
        throw new Error('Too many failed attempts. Try again in 15 minutes.');
    }
    return attempts ? parseInt(attempts) : 0;
}

async function incrementRateLimit(env, ip) {
    const key = `rate_limit_${ip}`;
    const current = await env.Chapoon.get(key);
    const newCount = current ? parseInt(current) + 1 : 1;
    await env.Chapoon.put(key, newCount.toString(), { expirationTtl: LOGIN_WINDOW_MS / 1000 });
    return newCount;
}

function showSetupPage() {
    const html = `<!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Setup Admin Password</title>
        <style>
            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }
            
            :root {
                --background-primary: #2a2421;
                --background-secondary: #35302c;
                --background-tertiary: #413b35;
                --border-color: #5a4f45;
                --text-primary: #e5dfd6;
                --text-secondary: #b3a89d;
                --text-accent: #ffffff;
                --accent-primary: #be9b7b;
                --accent-secondary: #d4b595;
                --status-error: #e05d44;
                --border-radius: 8px;
            }
            
            body {
                font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
                background-color: var(--background-primary);
                color: var(--text-primary);
                min-height: 100vh;
                display: flex;
                justify-content: center;
                align-items: center;
                padding: 20px;
                line-height: 1.5;
            }
            
            .auth-container {
                width: 100%;
                max-width: 400px;
            }
            
            .auth-card {
                background: var(--background-secondary);
                padding: 40px 30px;
                border-radius: var(--border-radius);
                border: 1px solid var(--border-color);
                box-shadow: 0 8px 25px rgba(0, 0, 0, 0.2);
                text-align: center;
            }
            
            .auth-icon {
                font-size: 3rem;
                margin-bottom: 20px;
                color: var(--accent-secondary);
            }
            
            .auth-title {
                font-size: 1.8rem;
                color: var(--text-accent);
                margin-bottom: 10px;
                font-weight: 400;
            }
            
            .auth-subtitle {
                color: var(--text-secondary);
                margin-bottom: 30px;
                font-size: 0.9rem;
            }
            
            .auth-form-group {
                margin-bottom: 20px;
            }
            
            .input-with-icon {
                position: relative;
            }
            
            .input-with-icon input {
                width: 100%;
                padding: 15px 50px 15px 15px;
                border: 1px solid var(--border-color);
                border-radius: var(--border-radius);
                background: var(--background-tertiary);
                color: var(--text-primary);
                font-size: 16px;
                transition: all 0.3s ease;
            }
            
            .input-with-icon input:focus {
                outline: none;
                border-color: var(--accent-primary);
                box-shadow: 0 0 0 3px rgba(190, 155, 123, 0.1);
            }
            
            .password-toggle {
                position: absolute;
                right: 15px;
                top: 50%;
                transform: translateY(-50%);
                background: none;
                border: none;
                cursor: pointer;
                font-size: 17px;
                color: var(--text-secondary);
            }
            
            .auth-submit-btn {
                width: 100%;
                padding: 15px;
                background: var(--accent-primary);
                color: #2a2421;
                border: none;
                border-radius: var(--border-radius);
                font-size: 16px;
                font-weight: 600;
                cursor: pointer;
                transition: all 0.3s ease;
            }
            
            .auth-submit-btn:hover {
                background: var(--accent-secondary);
                transform: translateY(-2px);
            }
            
            .error-message {
                color: var(--status-error);
                margin: 15px 0;
                padding: 12px;
                background: rgba(224, 93, 68, 0.1);
                border: 1px solid rgba(224, 93, 68, 0.3);
                border-radius: var(--border-radius);
                display: none;
            }
            
            @media (max-width: 480px) {
                .auth-card {
                    padding: 30px 20px;
                }
                
                body {
                    padding: 10px;
                }
            }
        </style>
    </head>
    <body>
        <div class="auth-container">
            <div class="auth-card">
                <div class="auth-icon">🔐</div>
                <h1 class="auth-title">Set Admin Password</h1>
                <p class="auth-subtitle">Create a secure password for admin access</p>
                
                <form method="POST" action="/setup" onsubmit="return validatePasswords()">
                    <div class="auth-form-group">
                        <div class="input-with-icon">
                            <input type="password" id="password" name="password" placeholder="Enter password" required>
                            <button type="button" onclick="togglePassword('password')" class="password-toggle">🙈</button>
                        </div>
                    </div>
                    
                    <div class="auth-form-group">
                        <div class="input-with-icon">
                            <input type="password" id="confirmPassword" name="confirmPassword" placeholder="Confirm password" required>
                            <button type="button" onclick="togglePassword('confirmPassword')" class="password-toggle">🙈</button>
                        </div>
                    </div>
                    
                    <div id="passwordError" class="error-message">Passwords do not match</div>
                    
                    <button type="submit" class="auth-submit-btn">Save Password</button>
                </form>
            </div>
        </div>
        
        <script>
            function validatePasswords() {
                const password = document.getElementById('password').value;
                const confirmPassword = document.getElementById('confirmPassword').value;
                const errorDiv = document.getElementById('passwordError');
                
                if (password !== confirmPassword) {
                    errorDiv.style.display = 'block';
                    return false;
                }
                errorDiv.style.display = 'none';
                return true;
            }

            function togglePassword(inputId) {
                const input = document.getElementById(inputId);
                const button = input.parentNode.querySelector('.password-toggle');
                
                if (input.type === 'password') {
                    input.type = 'text';
                    button.textContent = '🙉';
                } else {
                    input.type = 'password';
                    button.textContent = '🙈';
                }
            }
        </script>
    </body>
    </html>`;
    
    return new Response(html, { 
        headers: { 
            'Content-Type': 'text/html; charset=utf-8' 
        } 
    });
}

function showLoginPage(error = '') {
    const html = `<!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Login 🌟 Star</title>
        <style>
            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }
            
            :root {
                --background-primary: #2a2421;
                --background-secondary: #35302c;
                --background-tertiary: #413b35;
                --border-color: #5a4f45;
                --text-primary: #e5dfd6;
                --text-secondary: #b3a89d;
                --text-accent: #ffffff;
                --accent-primary: #be9b7b;
                --accent-secondary: #d4b595;
                --status-error: #e05d44;
                --border-radius: 8px;
            }
            
            body {
                font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, sans-serif;
                background-color: var(--background-primary);
                color: var(--text-primary);
                min-height: 100vh;
                display: flex;
                justify-content: center;
                align-items: center;
                padding: 20px;
                line-height: 1.5;
            }
            
            .auth-container {
                max-width: 400px;
            }
            
            .auth-card {
                background: var(--background-secondary);
                padding: 40px 30px;
                border-radius: var(--border-radius);
                border: 1px solid var(--border-color);
                box-shadow: 0 8px 25px rgba(0, 0, 0, 0.2);
                text-align: center;
            }
            
            .auth-icon {
                font-size: 3rem;
                margin-bottom: 20px;
                color: var(--accent-secondary);
            }
            
            .auth-title {
                font-size: 1.8rem;
                color: var(--text-accent);
                margin-bottom: 10px;
                font-weight: 400;
            }
            
            .auth-subtitle {
                color: var(--text-secondary);
                margin-bottom: 30px;
                font-size: 0.9rem;
            }
            
            .auth-form-group {
                margin-bottom: 20px;
            }
            
            .input-with-icon {
                position: relative;
            }
            
            .input-with-icon input {
                width: 100%;
                padding: 15px 50px 15px 15px;
                border: 1px solid var(--border-color);
                border-radius: var(--border-radius);
                background: var(--background-tertiary);
                color: var(--text-primary);
                font-size: 16px;
                transition: all 0.3s ease;
            }
            
            .input-with-icon input:focus {
                outline: none;
                border-color: var(--accent-primary);
                box-shadow: 0 0 0 3px rgba(190, 155, 123, 0.1);
            }
            
            .password-toggle {
                position: absolute;
                right: 15px;
                top: 50%;
                transform: translateY(-50%);
                background: none;
                border: none;
                cursor: pointer;
                font-size: 17px;
                color: var(--text-secondary);
            }
            
            .auth-submit-btn {
                width: 100%;
                padding: 15px;
                background: var(--accent-primary);
                color: #2a2421;
                border: none;
                border-radius: var(--border-radius);
                font-size: 16px;
                font-weight: 600;
                cursor: pointer;
                transition: all 0.3s ease;
            }
            
            .auth-submit-btn:hover {
                background: var(--accent-secondary);
                transform: translateY(-2px);
            }
            
            .auth-error {
                color: var(--status-error);
                margin: 15px 0;
                padding: 12px;
                background: rgba(224, 93, 68, 0.1);
                border: 1px solid rgba(224, 93, 68, 0.3);
                border-radius: var(--border-radius);
            }
            
            @media (max-width: 480px) {
                .auth-card {
                    padding: 30px 20px;
                }
                
                body {
                    padding: 10px;
                }
            }
        </style>
    </head>
    <body>
        <div class="auth-container">
            <div class="auth-card">
                <h1 class="auth-title">Welcome</h1>
                ${error ? `<div class="auth-error">${error}</div>` : ''}
                
                <form method="POST" action="/login">
                    <div class="auth-form-group">
                        <div class="input-with-icon">
                            <input type="password" id="password" name="password" placeholder="Enter admin password" required>
                            <button type="button" onclick="togglePassword('password')" class="password-toggle">🙈</button>
                        </div>
                    </div>
                    
                    <button type="submit" class="auth-submit-btn">Login</button>
                </form>
            </div>
        </div>
        
        <script>
            function togglePassword(inputId) {
                const input = document.getElementById(inputId);
                const button = input.parentNode.querySelector('.password-toggle');
                
                if (input.type === 'password') {
                    input.type = 'text';
                    button.textContent = '🙉';
                } else {
                    input.type = 'password';
                    button.textContent = '🙈';
                }
            }
        </script>
    </body>
    </html>`;
    
    return new Response(html, { 
        headers: { 
            'Content-Type': 'text/html; charset=utf-8' 
        } 
    });
}

function generateRandomPath(length = 12, query = '') {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';
  for (let i = 0; i < length; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return `/${result}${query ? `?${query}` : ''}`;
}

const CORE_PRESETS = {
  xray: {
    tls: { path: () => generateRandomPath(12, 'ed=2048'), security: 'tls',  fp: 'chrome',  alpn: 'http/1.1', extra: {} },
    tcp: { path: () => generateRandomPath(12, 'ed=2048'), security: 'none', fp: 'chrome',                extra: {} },
  },
};

function createVlessLink({
  userID, address, port, host, path,
  security, sni, fp, alpn, extra = {}, name, enhanced = false,
}) {
  const params = new URLSearchParams({
    type: 'ws',
    host,
    path,
  });

  if (security) params.set('security', security);
  if (sni)      params.set('sni',      sni);
  if (fp)       params.set('fp',       fp);
  if (alpn)     params.set('alpn',     alpn);

  if (enhanced) {
    if (security === 'tls') params.set('cs', CIPHER_SUITES);
        params.set('fm', JSON.stringify(globalThis.fragmentConfig || DEFAULT_FRAGMENT));
  }

  for (const [k, v] of Object.entries(extra)) params.set(k, v);

  return `vless://${userID}@${address}:${port}?${params.toString()}#${encodeURIComponent(name)}`;
}

function buildLink({ core, proto, userID, hostName, address, port, tag, index = 0 }) {
  const p = CORE_PRESETS[core][proto];
  const fps = ['chrome', 'unsafe'];
  const selectedFp = fps[index % fps.length];
  
  return createVlessLink({
    userID,
    address,
    port,
    host: hostName,
    path: p.path(),
    security: p.security,
    sni: p.security === 'tls' ? hostName : undefined,
    fp: selectedFp,
    alpn: p.alpn,
    extra: p.extra,
    name: tag,
    enhanced: true,
  });
}

const pick = (/** @type {string | any[]} */ arr) => arr[Math.floor(Math.random() * arr.length)];

async function handleIpSubscription(core, userID, hostName, env) {
    globalThis.fragmentConfig = await getFragmentConfig(env);
  const httpsPorts = [443, 8443, 2053, 2083, 2087, 2096];
  const httpPorts = [80];
  
  const allPorts = [...httpsPorts, ...httpPorts];
  
  let links = [];

  let githubIPs = [];
  try {
    const r = await fetch('https://raw.githubusercontent.com/NiREvil/vless/refs/heads/main/Cloudflare-IPs.json');
    if (r.ok) {
      const json = await r.json();
      const allIPsFromGithub = [...(json.ipv4 || [])].map(x => x.ip);
      const uniqueIPs = [...new Set(allIPsFromGithub)];
      githubIPs = uniqueIPs;
    }
  } catch (e) { 
    console.error('Fetch IP list failed', e); 
  }

  const backupIPs = [
'\u0073\u0074\u0061\u0074\u0069\u0063\u002E\u0063\u006C\u006F\u0075\u0064\u0066\u006C\u0061\u0072\u0065\u0069\u006E\u0073\u0069\u0067\u0068\u0074\u0073\u002E\u0063\u006F\u006D',
'\u0077\u0077\u0077\u002E\u0076\u0069\u0073\u0061\u0073\u006F\u0075\u0074\u0068\u0065\u0061\u0073\u0074\u0065\u0075\u0072\u006F\u0070\u0065\u002E\u0063\u006F\u006D',
'\u0077\u0068\u0061\u0074\u0069\u0073\u006D\u0079\u0069\u0070\u0061\u0064\u0064\u0072\u0065\u0073\u0073\u002E\u0063\u006F\u006D',
'\u0071\u0061\u002E\u0076\u0069\u0073\u0061\u006D\u0069\u0064\u0064\u006C\u0065\u0065\u0061\u0073\u0074\u002E\u0063\u006F\u006D',
'\u0077\u0077\u0077\u002E\u0064\u0069\u0067\u0069\u0074\u0061\u006C\u006F\u0063\u0065\u0061\u006E\u002E\u0063\u006F\u006D',
'\u006C\u006F\u0067\u002E\u0062\u0070\u006D\u0069\u006E\u0065\u0063\u0072\u0061\u0066\u0074\u002E\u0063\u006F\u006D',
'\u0063\u0072\u0065\u0061\u0074\u0069\u0076\u0065\u0063\u006F\u006D\u006D\u006F\u006E\u0073\u002E\u006F\u0072\u0067',
'\u0073\u006B\u0079\u002E\u0072\u0065\u0074\u0068\u0069\u006E\u006B\u0064\u006E\u0073\u002E\u0063\u006F\u006D',
'\u0077\u0077\u0077\u002E\u0077\u0068\u0061\u0074\u0069\u0073\u006D\u0079\u0069\u0070\u002E\u0063\u006F\u006D',
'\u0077\u0077\u0077\u002E\u0067\u006C\u0061\u0073\u0073\u0064\u006F\u006F\u0072\u002E\u0063\u006F\u006D',
'\u0077\u0077\u0077\u002E\u0069\u0070\u0063\u0068\u0069\u0063\u006B\u0065\u006E\u002E\u0063\u006F\u006D',
'\u0077\u0077\u0077\u002E\u0073\u0070\u0065\u0065\u0064\u0074\u0065\u0073\u0074\u002E\u006E\u0065\u0074',
'\u0077\u0077\u0077\u002E\u0076\u0069\u0073\u0061\u0065\u0075\u0072\u006F\u0070\u0065\u002E\u0063\u0068',
'\u0077\u0077\u0077\u002E\u0076\u0069\u0073\u0061\u0065\u0075\u0072\u006F\u0070\u0065\u002E\u0061\u0074',
'\u0077\u0077\u0077\u002E\u0076\u0069\u0073\u0061\u006B\u006F\u0072\u0065\u0061\u002E\u0063\u006F\u006D',
'\u0063\u0066\u0069\u0070\u002E\u0031\u0033\u0032\u0033\u0031\u0032\u0033\u002E\u0078\u0079\u007A',
'\u0063\u0066\u0069\u0070\u002E\u0078\u0078\u0078\u0078\u0078\u0078\u0078\u0078\u002E\u0074\u006B',
'\u006D\u0079\u0061\u006E\u006D\u0061\u0072\u002E\u0076\u0069\u0073\u0061\u002E\u0063\u006F\u006D',
'\u0077\u0077\u0077\u002E\u0069\u0070\u0061\u0064\u0064\u0072\u0065\u0073\u0073\u002E\u006D\u0079',
'\u0061\u0066\u0072\u0069\u0063\u0061\u002E\u0076\u0069\u0073\u0061\u002E\u0063\u006F\u006D',
'\u0061\u0075\u0074\u0068\u002E\u0076\u0065\u0072\u0063\u0065\u006C\u002E\u0063\u006F\u006D',
'\u0077\u0077\u0077\u002E\u0067\u0069\u0074\u0062\u006F\u006F\u006B\u002E\u0063\u006F\u006D',
'\u0077\u0077\u0077\u002E\u0075\u0064\u0061\u0063\u0069\u0074\u0079\u002E\u0063\u006F\u006D',
'\u0077\u0077\u0077\u002E\u0076\u0069\u0073\u0061\u002E\u0063\u006F\u006D\u002E\u0062\u0072',
'\u0077\u0077\u0077\u002E\u0076\u0069\u0073\u0061\u002E\u0063\u006F\u006D\u002E\u0068\u006B',
'\u0077\u0077\u0077\u002E\u0076\u0069\u0073\u0061\u002E\u0063\u006F\u006D\u002E\u006D\u0074',
'\u0077\u0077\u0077\u002E\u0076\u0069\u0073\u0061\u002E\u0063\u006F\u006D\u002E\u0073\u0067',
'\u0077\u0077\u0077\u002E\u0076\u0069\u0073\u0061\u002E\u0063\u006F\u006D\u002E\u0074\u0077',
'\u0064\u006E\u0073\u0063\u0068\u0065\u0063\u006B\u0065\u0072\u002E\u006F\u0072\u0067',
'\u0074\u0061\u0073\u0074\u0065\u0061\u0074\u006C\u0061\u0073\u002E\u0063\u006F\u006D',
'\u0074\u006F\u0079\u002D\u0070\u0065\u006F\u0070\u006C\u0065\u002E\u0063\u006F\u006D',
'\u0077\u0077\u0077\u002E\u0067\u0063\u006F\u002E\u0067\u006F\u0076\u002E\u0071\u0061',
'\u0077\u0077\u0077\u002E\u0076\u0069\u0073\u0061\u002E\u0063\u006F\u002E\u006A\u0070',
'\u0077\u0077\u0077\u002E\u007A\u0073\u0075\u002E\u0067\u006F\u0076\u002E\u0075\u0061',
'\u0077\u0077\u0077\u002E\u0066\u006F\u0072\u006E\u0065\u0078\u002E\u0063\u006F\u006D',
'\u0063\u0066\u002E\u0030\u0039\u0030\u0032\u0032\u0037\u002E\u0078\u0079\u007A',
'\u0067\u006F\u002E\u0069\u006E\u006D\u006F\u0062\u0069\u002E\u0063\u006F\u006D',
'\u0069\u0070\u006C\u006F\u0063\u0061\u0074\u0069\u006F\u006E\u002E\u0069\u006F',
'\u0073\u0069\u006E\u0067\u0061\u0070\u006F\u0072\u0065\u002E\u0063\u006F\u006D',
'\u0073\u0070\u0065\u0065\u0064\u0074\u0065\u0073\u0074\u002E\u006F\u0072\u0067',
'\u0073\u0074\u006F\u0072\u0065\u002E\u0075\u0062\u0069\u002E\u0063\u006F\u006D',
'\u0077\u0077\u0077\u002E\u0063\u0064\u006E\u006A\u0073\u002E\u0063\u006F\u006D',
'\u0077\u0077\u0077\u002E\u0069\u0070\u0067\u0065\u0074\u002E\u006E\u0065\u0074',
'\u0077\u0077\u0077\u002E\u0070\u0063\u006D\u0061\u0067\u002E\u0063\u006F\u006D',
'\u0077\u0077\u0077\u002E\u0075\u0064\u0065\u006D\u0079\u002E\u0063\u006F\u006D',
'\u0063\u0069\u0073\u002E\u0076\u0069\u0073\u0061\u002E\u0063\u006F\u006D',
'\u0067\u0061\u006D\u0065\u0072\u002E\u0063\u006F\u006D\u002E\u0074\u0077',
'\u0069\u006C\u006F\u0076\u0065\u0070\u0064\u0066\u002E\u0063\u006F\u006D',
'\u006A\u0073\u0064\u0065\u006C\u0069\u0076\u0072\u002E\u0063\u006F\u006D',
'\u006D\u0061\u006C\u0061\u0079\u0073\u0069\u0061\u002E\u0063\u006F\u006D',
'\u0073\u0069\u006C\u006B\u0062\u006F\u006F\u006B\u002E\u0063\u006F\u006D',
'\u0073\u0074\u0065\u0061\u006D\u0064\u0062\u002E\u0069\u006E\u0066\u006F',
'\u0075\u0073\u0061\u002E\u0076\u0069\u0073\u0061\u002E\u0063\u006F\u006D',
'\u0077\u0077\u0077\u002E\u0076\u0069\u0073\u0061\u002E\u0063\u006F\u006D',
'\u0063\u0068\u0061\u0074\u0067\u0070\u0074\u002E\u0063\u006F\u006D',
'\u006C\u0061\u0072\u0061\u0076\u0065\u006C\u002E\u0063\u006F\u006D',
'\u0077\u0077\u0077\u002E\u0077\u0074\u006F\u002E\u006F\u0072\u0067',
'\u0063\u006F\u0064\u0065\u0070\u0065\u006E\u002E\u0069\u006F',
'\u0067\u0075\u0072\u002E\u0067\u006F\u0076\u002E\u0075\u0061',
'\u0069\u0070\u0076\u0034\u002E\u0069\u0070\u002E\u0073\u0062',
'\u006C\u0062\u002E\u006E\u0073\u0063\u006C\u002E\u0069\u0072',
'\u006C\u0069\u006E\u006B\u0065\u0072\u0064\u002E\u0069\u006F',
'\u006D\u0065\u0064\u0069\u0075\u006D\u002E\u0063\u006F\u006D',
'\u006D\u0066\u0061\u002E\u0067\u006F\u0076\u002E\u0075\u0061',
'\u006E\u006F\u0064\u0065\u006A\u0073\u002E\u006F\u0072\u0067',
'\u0072\u0075\u0073\u0073\u0069\u0061\u002E\u0063\u006F\u006D',
'\u0077\u0077\u0077\u002E\u0067\u006F\u0076\u002E\u0073\u0065',
'\u0077\u0077\u0077\u002E\u0067\u006F\u0076\u002E\u0075\u0061',
'\u0061\u006D\u0061\u0072\u0066\u0061\u002E\u0069\u0072',
'\u0063\u0064\u006E\u006A\u0073\u002E\u0063\u006F\u006D', 
'\u0068\u0061\u0072\u0062\u006F\u0072\u002E\u0069\u006F',
'\u006A\u0061\u0070\u0061\u006E\u002E\u0063\u006F\u006D',
'\u006E\u0070\u006D\u006A\u0073\u002E\u0063\u006F\u006D',
'\u0075\u006E\u0070\u006B\u0067\u002E\u0063\u006F\u006D',
'\u0063\u0073\u0067\u006F\u002E\u0063\u006F\u006D',
'\u0069\u0063\u006F\u006F\u006B\u002E\u0068\u006B',
'\u0069\u0063\u006F\u006F\u006B\u002E\u0074\u0077',
'\u0066\u0062\u0069\u002E\u0067\u006F\u0076',
'\u0073\u006B\u006B\u002E\u006D\u006F\u0065',
'\u0074\u0069\u006D\u0065\u002E\u0069\u0073',
'\u0069\u0070\u002E\u0067\u0073',
'\u0069\u0070\u002E\u0073\u0062',

  '\u0031\u0037\u0032\u002E\u0036\u0036\u002E\u0034\u0036\u002E\u0032\u0034\u0033',
  '\u0031\u0037\u0032\u002E\u0036\u0036\u002E\u0034\u0037\u002E\u0033\u0032',
  '\u0031\u0037\u0032\u002E\u0036\u0036\u002E\u0034\u0036\u002E\u0031\u0034\u0030',
  '\u0031\u0037\u0032\u002E\u0036\u0036\u002E\u0034\u0035\u002E\u0031\u0038\u0038',
  '\u0031\u0037\u0032\u002E\u0036\u0036\u002E\u0033\u002E\u0031\u0034\u0036',
  '\u0031\u0037\u0032\u002E\u0036\u0036\u002E\u0034\u0035\u002E\u0032\u0030\u0033',
  '\u0031\u0037\u0032\u002E\u0036\u0037\u002E\u0031\u0039\u0030\u002E\u0038\u0037',
  '\u0031\u0037\u0032\u002E\u0036\u0037\u002E\u0032\u0030\u0034\u002E\u0038\u0034',
  '\u0031\u0037\u0032\u002E\u0036\u0037\u002E\u0036\u0038\u002E\u0031\u0035\u0037',
  '\u0031\u0037\u0032\u002E\u0036\u0037\u002E\u0031\u0039\u0032\u002E\u0032\u0031\u0031',
  '\u0031\u0037\u0032\u002E\u0036\u0037\u002E\u0032\u0031\u0036\u002E\u0037\u0033',
  '\u0031\u0037\u0032\u002E\u0036\u0036\u002E\u0034\u0032\u002E\u0033\u0033',
  '\u0031\u0037\u0032\u002E\u0036\u0036\u002E\u0034\u0032\u002E\u0031\u0031\u0030',
  '\u0031\u0037\u0032\u002E\u0036\u0036\u002E\u0034\u0030\u002E\u0031\u0037\u0038',
  '\u0031\u0037\u0032\u002E\u0036\u0036\u002E\u0034\u0031\u002E\u0032\u0034\u0039',
  '\u0031\u0037\u0032\u002E\u0036\u0036\u002E\u0034\u0031\u002E\u0032\u0030\u0034',
  '\u0031\u0037\u0032\u002E\u0036\u0036\u002E\u0034\u0030\u002E\u0031\u0036\u0035',
  '\u0031\u0037\u0032\u002E\u0036\u0036\u002E\u0034\u0035\u002E\u0031\u0038\u0035',
  '\u0031\u0037\u0032\u002E\u0036\u0036\u002E\u0034\u0034\u002E\u0031\u0037\u0034',
  '\u0031\u0037\u0032\u002E\u0036\u0036\u002E\u0034\u0032\u002E\u0031\u0034\u0032',
  '\u0031\u0037\u0032\u002E\u0036\u0036\u002E\u0034\u0031\u002E\u0032\u0034\u0035',
  '\u0031\u0038\u0038\u002E\u0031\u0031\u0034\u002E\u0039\u0038\u002E\u0036\u0034',
  '\u0031\u0038\u0038\u002E\u0031\u0031\u0034\u002E\u0039\u0039\u002E\u0036\u0034',
  '\u0031\u0038\u0038\u002E\u0031\u0031\u0034\u002E\u0039\u0038\u002E\u0031\u0031\u0035',
  '\u0020\u0031\u0038\u0038\u002E\u0031\u0031\u0034\u002E\u0039\u0036\u002E\u0031\u0033\u0030',
  '\u0031\u0038\u0038\u002E\u0031\u0031\u0034\u002E\u0039\u0038\u002E\u0036\u0031',
  '\u0031\u0038\u0038\u002E\u0031\u0031\u0034\u002E\u0039\u0039\u002E\u0032\u0033\u0036',
  '\u0031\u0038\u0038\u002E\u0031\u0031\u0034\u002E\u0039\u0038\u002E\u0031\u0030\u0038',
  '\u0031\u0038\u0038\u002E\u0031\u0031\u0034\u002E\u0039\u0039\u002E\u0031\u0031\u0038',
  '\u0031\u0038\u0038\u002E\u0031\u0031\u0034\u002E\u0039\u0037\u002E\u0031\u0030\u0038',
  '\u0031\u0038\u0038\u002E\u0031\u0031\u0034\u002E\u0039\u0038\u002E\u0032\u0030\u0038',
  '\u0031\u0038\u0038\u002E\u0031\u0031\u0034\u002E\u0039\u0039\u002E\u0033\u0036',
  '\u0031\u0038\u0038\u002E\u0031\u0031\u0034\u002E\u0039\u0039\u002E\u0032\u0030\u0036',
  '\u0031\u0038\u0038\u002E\u0031\u0031\u0034\u002E\u0039\u0038\u002E\u0031\u0039\u0037',
  '\u0031\u0038\u0038\u002E\u0031\u0031\u0034\u002E\u0039\u0038\u002E\u0032\u0030\u0033',
  '\u0031\u0038\u0038\u002E\u0031\u0031\u0034\u002E\u0039\u0038\u002E\u0032\u0034\u0032',
  '\u0031\u0038\u0038\u002E\u0031\u0031\u0034\u002E\u0039\u0036\u002E\u0032\u0030\u0034',
  '\u0031\u0038\u0038\u002E\u0031\u0031\u0034\u002E\u0039\u0036\u002E\u0031\u0033\u0034',
  '\u0031\u0038\u0038\u002E\u0031\u0031\u0034\u002E\u0039\u0037\u002E\u0031\u0030\u0037',
  '\u0031\u0038\u0038\u002E\u0031\u0031\u0034\u002E\u0039\u0037\u002E\u0032\u0031',
  '\u0031\u0038\u0038\u002E\u0031\u0031\u0034\u002E\u0039\u0038\u002E\u0031\u0034\u0034',
  '\u0031\u0038\u0038\u002E\u0031\u0031\u0034\u002E\u0039\u0036\u002E\u0031\u0032\u0033',
  '\u0031\u0038\u0038\u002E\u0031\u0031\u0034\u002E\u0039\u0037\u002E\u0032\u0035\u0030',
  '\u0031\u0038\u0038\u002E\u0031\u0031\u0034\u002E\u0039\u0038\u002E\u0031\u0035\u0032',
  '\u0031\u0038\u0038\u002E\u0031\u0031\u0034\u002E\u0039\u0036\u002E\u0031\u0036\u0035',
  '\u0031\u0038\u0038\u002E\u0031\u0031\u0034\u002E\u0039\u0037\u002E\u0037\u0030',
  '\u0031\u0038\u0038\u002E\u0031\u0031\u0034\u002E\u0039\u0038\u002E\u0032\u0031\u0035',
  '\u0031\u0038\u0038\u002E\u0031\u0031\u0034\u002E\u0039\u0037\u002E\u0036\u0035',
  '\u0031\u0038\u0038\u002E\u0031\u0031\u0034\u002E\u0039\u0036\u002E\u0031\u0038\u0034',
  '\u0031\u0038\u0038\u002E\u0031\u0031\u0034\u002E\u0039\u0037\u002E\u0031\u0037\u0034',
  '\u0031\u0038\u0038\u002E\u0031\u0031\u0034\u002E\u0039\u0039\u002E\u0031\u0030\u0031',
  '\u0031\u0038\u0038\u002E\u0031\u0031\u0034\u002E\u0039\u0036\u002E\u0031\u0037\u0034',
  '\u0031\u0038\u0038\u002E\u0031\u0031\u0034\u002E\u0039\u0037\u002E\u0035\u0037',
  '\u0031\u0038\u0038\u002E\u0031\u0031\u0034\u002E\u0039\u0038\u002E\u0039\u0038',
  '\u0031\u0038\u0038\u002E\u0031\u0031\u0034\u002E\u0039\u0039\u002E\u0031\u0033\u0035',
  '\u0031\u0038\u0038\u002E\u0031\u0031\u0034\u002E\u0039\u0037\u002E\u0032\u0034',
  '\u0032\u0033\u002E\u0032\u0032\u0037\u002E\u0033\u0038\u002E\u0031\u0033\u0035',
  '\u0038\u0039\u002E\u0031\u0031\u0036\u002E\u0032\u0035\u0030\u002E\u0031\u0032\u0031',
  '\u0031\u0038\u0035\u002E\u0038\u002E\u0031\u0032\u0039\u002E\u0031\u0038\u0037',
  '\u0031\u0038\u0035\u002E\u0031\u0034\u0036\u002E\u0031\u0037\u0033\u002E\u0031\u0039\u0035',
  '\u0031\u0038\u0035\u002E\u0031\u0034\u0036\u002E\u0031\u0037\u0033\u002E\u0034\u0035',
  '\u0031\u0038\u0035\u002E\u0031\u0034\u0036\u002E\u0031\u0037\u0033\u002E\u0031\u0032\u0038',
  '\u0031\u0038\u0035\u002E\u0031\u0034\u0036\u002E\u0031\u0037\u0033\u002E\u0038',
  '\u0031\u0038\u0035\u002E\u0031\u0034\u0036\u002E\u0031\u0037\u0033\u002E\u0032\u0034\u0032',
  '\u0031\u0038\u0035\u002E\u0031\u0034\u0036\u002E\u0031\u0037\u0033\u002E\u0031\u0036\u0030',
  '\u0031\u0038\u0035\u002E\u0031\u0034\u0036\u002E\u0031\u0037\u0033\u002E\u0036\u0037',
  '\u0031\u0038\u0035\u002E\u0031\u0034\u0036\u002E\u0031\u0037\u0033\u002E\u0031\u0037\u0039',
  '\u0031\u0038\u0035\u002E\u0031\u0034\u0036\u002E\u0031\u0037\u0033\u002E\u0032\u0032\u0034',
  '\u0031\u0038\u0035\u002E\u0031\u0034\u0036\u002E\u0031\u0037\u0033\u002E\u0032\u0033\u0032',
  '\u0031\u0038\u0035\u002E\u0031\u0034\u0038\u002E\u0031\u0030\u0037\u002E\u0034\u0039',
  '\u0031\u0038\u0035\u002E\u0031\u0034\u0038\u002E\u0031\u0030\u0037\u002E\u0031\u0038\u0036',
  '\u0031\u0038\u0035\u002E\u0031\u0034\u0038\u002E\u0031\u0030\u0037\u002E\u0031\u0036\u0033',
  '\u0031\u0038\u0035\u002E\u0031\u0034\u0038\u002E\u0031\u0030\u0037\u002E\u0032\u0034\u0031',
  '\u0031\u0038\u0035\u002E\u0031\u0034\u0038\u002E\u0031\u0030\u0037\u002E\u0038\u0037',
  '\u0031\u0038\u0035\u002E\u0031\u0034\u0038\u002E\u0031\u0030\u0035\u002E\u0032\u0033',
  '\u0031\u0039\u0030\u002E\u0039\u0033\u002E\u0032\u0034\u0037\u002E\u0032\u0033\u0038',
  '\u0031\u0039\u0035\u002E\u0038\u0035\u002E\u0035\u0039\u002E\u0039\u0036',
  '\u0031\u0039\u0039\u002E\u0033\u0034\u002E\u0032\u0032\u0038\u002E\u0031\u0038\u0034',
  '\u0032\u0030\u0036\u002E\u0032\u0033\u0038\u002E\u0032\u0033\u0036\u002E\u0033\u0036',
  '\u0032\u0030\u0038\u002E\u0038\u0036\u002E\u0031\u0036\u0038\u002E\u0032\u0031\u0030',
  '\u0031\u0030\u0034\u002E\u0032\u0035\u002E\u0039\u0037\u002E\u0039\u0038',
  '\u0031\u0030\u0034\u002E\u0032\u0035\u002E\u0039\u0035\u002E\u0031\u0036\u0037',
  '\u0031\u0030\u0034\u002E\u0031\u0037\u002E\u0031\u0036\u0037\u002E\u0031\u0034',
  '\u0031\u0030\u0034\u002E\u0031\u0037\u002E\u0036\u0031\u002E\u0031\u0030\u0039',
  '\u0031\u0030\u0034\u002E\u0032\u0037\u002E\u0031\u0036\u002E\u0036\u0039',
  '\u0031\u0030\u0034\u002E\u0031\u0036\u002E\u0032\u0030\u0036\u002E\u0033\u0037',
  '\u0031\u0030\u0034\u002E\u0031\u0036\u002E\u0031\u0031\u0039\u002E\u0035\u0034',
  '\u0031\u0030\u0034\u002E\u0031\u0037\u002E\u0037\u0034\u002E\u0036\u0033',
  '\u0031\u0030\u0034\u002E\u0031\u0036\u002E\u0031\u0032\u0036\u002E\u0039\u0030',
  '\u0031\u0030\u0034\u002E\u0031\u0036\u002E\u0031\u0035\u0034\u002E\u0032\u0032\u0032',
  '\u0031\u0030\u0034\u002E\u0031\u0037\u002E\u0031\u0036\u0031\u002E\u0034\u0031',
  '\u0031\u0030\u0034\u002E\u0031\u0037\u002E\u0031\u0036\u0030\u002E\u0031\u0034\u0035',
  '\u0031\u0030\u0034\u002E\u0031\u0039\u002E\u0031\u0039\u0034\u002E\u0031\u0033\u0031',
  '\u0031\u0030\u0034\u002E\u0031\u0038\u002E\u0038\u0037\u002E\u0031\u0038\u0032',
  '\u0031\u0030\u0034\u002E\u0032\u0035\u002E\u0032\u0030\u0035\u002E\u0034\u0034',
  '\u0031\u0030\u0034\u002E\u0031\u0036\u002E\u0032\u0035\u0034\u002E\u0032\u0030',
  '\u0031\u0030\u0034\u002E\u0031\u0037\u002E\u0033\u0036\u002E\u0036\u0032',
  '\u0031\u0030\u0034\u002E\u0031\u0037\u002E\u0031\u0039\u0030\u002E\u0039\u0032',
  '\u0031\u0030\u0034\u002E\u0031\u0038\u002E\u0031\u0032\u0034\u002E\u0039\u0031',
  '\u0031\u0030\u0034\u002E\u0031\u0039\u002E\u0032\u0031\u0039\u002E\u0031\u0038\u0035',
  '\u0031\u0030\u0034\u002E\u0031\u0039\u002E\u0032\u0031\u0039\u002E\u0038\u0039',
  '\u0031\u0030\u0034\u002E\u0032\u0034\u002E\u0033\u0033\u002E\u0031\u0032\u0036',
  '\u0031\u0030\u0034\u002E\u0031\u0038\u002E\u0032\u0034\u0039\u002E\u0033\u0033',
  '\u0031\u0030\u0034\u002E\u0031\u0039\u002E\u0039\u0036\u002E\u0032\u0030\u0033',
  '\u0031\u0030\u0034\u002E\u0031\u0038\u002E\u0034\u0034\u002E\u0031\u0032\u0037',
  '\u0031\u0030\u0034\u002E\u0031\u0038\u002E\u0032\u0034\u0039\u002E\u0038\u0037',
  '\u0031\u0030\u0034\u002E\u0031\u0038\u002E\u0034\u0034\u002E\u0031\u0039\u0035',
  '\u0031\u0030\u0034\u002E\u0031\u0036\u002E\u0031\u0035\u0030\u002E\u0032\u0031\u0034',
  '\u0031\u0030\u0034\u002E\u0031\u0036\u002E\u0032\u0032\u0031\u002E\u0032\u0034\u0038',
  '\u0031\u0030\u0034\u002E\u0032\u0037\u002E\u0031\u0032\u0036\u002E\u0032\u0035\u0030',
  '\u0031\u0030\u0034\u002E\u0032\u0037\u002E\u0031\u0032\u0036\u002E\u0033\u0035',
  '\u0031\u0030\u0034\u002E\u0031\u0036\u002E\u0031\u0032\u0030\u002E\u0031\u0031\u0034',
  '\u0031\u0030\u0034\u002E\u0032\u0031\u002E\u0032\u0031\u0036\u002E\u0032\u0036',
  '\u0031\u0030\u0034\u002E\u0032\u0031\u002E\u0038\u0033\u002E\u0036\u0032',
  '\u0031\u0030\u0034\u002E\u0032\u0034\u002E\u0035\u0038\u002E\u0031\u0033',
  '\u0031\u0030\u0034\u002E\u0031\u0036\u002E\u0031\u0035\u0030\u002E\u0039\u0034',
  '\u0031\u0030\u0034\u002E\u0031\u0037\u002E\u0036\u0031\u002E\u0031\u0034\u0030',
  '\u0031\u0030\u0034\u002E\u0031\u0037\u002E\u0033\u0034\u002E\u0039\u0033',
  '\u0031\u0030\u0034\u002E\u0032\u0034\u002E\u0031\u0039\u0037\u002E\u0032\u0030',
  '\u0031\u0030\u0034\u002E\u0032\u0036\u002E\u0031\u0033\u002E\u0035\u0034',
  '\u0031\u0030\u0034\u002E\u0032\u0031\u002E\u0032\u0031\u002E\u0035\u0039',
  '\u0031\u0030\u0034\u002E\u0032\u0034\u002E\u0031\u0039\u0036\u002E\u0032\u0030',
  '\u0031\u0030\u0034\u002E\u0032\u0031\u002E\u0039\u0030\u002E\u0032\u0031\u0030',
  '\u0031\u0030\u0034\u002E\u0032\u0031\u002E\u0036\u0039\u002E\u0034\u0034',
  '\u0031\u0030\u0034\u002E\u0032\u0036\u002E\u0036\u002E\u0033\u0037',
  '\u0031\u0030\u0034\u002E\u0032\u0035\u002E\u0037\u0036\u002E\u0032\u0039',
  '\u0031\u0030\u0034\u002E\u0032\u0034\u002E\u0031\u0035\u0037\u002E\u0032\u0033\u0034',
  '\u0031\u0030\u0034\u002E\u0032\u0035\u002E\u0032\u0033\u0038\u002E\u0031\u0033\u0037',
  '\u0031\u0030\u0034\u002E\u0032\u0034\u002E\u0032\u0030\u0036\u002E\u0031\u0032\u0030',
  '\u0031\u0030\u0034\u002E\u0031\u0036\u002E\u0032\u0033\u0035\u002E\u0031\u0030\u0034',
  '\u0031\u0030\u0034\u002E\u0032\u0034\u002E\u0032\u0030\u0033\u002E\u0037\u0033',
  '\u0031\u0030\u0034\u002E\u0032\u0034\u002E\u0031\u0036\u0033\u002E\u0038\u0032',
  '\u0031\u0030\u0034\u002E\u0032\u0034\u002E\u0032\u0030\u0036\u002E\u0031\u0033\u0036',
  '\u0031\u0030\u0034\u002E\u0032\u0034\u002E\u0031\u0036\u0038\u002E\u0031\u0034\u0034',
  '\u0031\u0030\u0034\u002E\u0032\u0034\u002E\u0032\u0031\u0030\u002E\u0031\u0035\u0030',
  '\u0031\u0030\u0034\u002E\u0031\u0036\u002E\u0031\u0038\u0038\u002E\u0031\u0031\u0034',
  '\u0031\u0030\u0034\u002E\u0032\u0034\u002E\u0031\u0037\u0037\u002E\u0031\u0033\u0038',
  '\u0031\u0030\u0034\u002E\u0032\u0037\u002E\u0032\u0035\u002E\u0031\u0032\u0039',
  '\u0031\u0030\u0034\u002E\u0031\u0037\u002E\u0038\u0034\u002E\u0032\u0030',
  '\u0031\u0030\u0034\u002E\u0032\u0031\u002E\u0037\u0033\u002E\u0031\u0035\u0033',
  '\u0031\u0030\u0034\u002E\u0032\u0031\u002E\u0032\u0034\u002E\u0031\u0035',
  '\u0031\u0030\u0034\u002E\u0032\u0034\u002E\u0031\u0037\u0031\u002E\u0031\u0038\u0030',
  '\u0031\u0030\u0034\u002E\u0032\u0037\u002E\u0031\u0033\u002E\u0032\u0033\u0036',
  '\u0031\u0030\u0034\u002E\u0031\u0037\u002E\u0031\u0036\u0032\u002E\u0035\u0033',
  '\u0031\u0030\u0034\u002E\u0032\u0034\u002E\u0031\u0038\u0039\u002E\u0038\u0032',
  '\u0031\u0030\u0034\u002E\u0031\u0036\u002E\u0031\u0035\u0032\u002E\u0032\u0032\u0033',
  '\u0031\u0030\u0034\u002E\u0032\u0037\u002E\u0038\u002E\u0031\u0037\u0030',
  '\u0031\u0030\u0034\u002E\u0031\u0036\u002E\u0032\u0035\u0034\u002E\u0031\u0032\u0032',
  '\u0031\u0030\u0034\u002E\u0031\u0037\u002E\u0031\u0033\u0038\u002E\u0031\u0038\u0032',
  '\u0031\u0030\u0034\u002E\u0031\u0038\u002E\u0039\u0036\u002E\u0031\u0031\u0039',
  '\u0031\u0030\u0034\u002E\u0031\u0037\u002E\u0033\u0035\u002E\u0037\u0038',
  '\u0031\u0030\u0034\u002E\u0031\u0036\u002E\u0031\u0036\u0032\u002E\u0035\u0031',
  '\u0031\u0030\u0034\u002E\u0031\u0036\u002E\u0031\u0030\u0035\u002E\u0031\u0030\u0031',
  '\u0031\u0030\u0034\u002E\u0031\u0039\u002E\u0031\u0039\u0035\u002E\u0039\u0030',
  '\u0031\u0030\u0034\u002E\u0031\u0038\u002E\u0032\u0030\u0038\u002E\u0038\u0036',
  '\u0031\u0030\u0034\u002E\u0031\u0036\u002E\u0032\u0030\u0038\u002E\u0038\u0036',
  '\u0031\u0036\u0032\u002E\u0031\u0035\u0039\u002E\u0031\u002E\u0039\u0034',
  '\u0031\u0036\u0032\u002E\u0031\u0035\u0039\u002E\u0033\u0036\u002E\u0032\u0030',
  '\u0031\u0036\u0032\u002E\u0031\u0035\u0039\u002E\u0033\u0036\u002E\u0035',
  '\u0031\u0037\u0032\u002E\u0036\u0037\u002E\u0032\u0031\u0034\u002E\u0032\u0034\u0036',
  '\u0031\u0037\u0032\u002E\u0036\u0037\u002E\u0031\u0036\u0031\u002E\u0031\u0030\u0034',
  '\u0031\u0037\u0032\u002E\u0036\u0037\u002E\u0036\u0036\u002E\u0031\u0037\u0037',
  '\u0031\u0037\u0032\u002E\u0036\u0036\u002E\u0034\u0031\u002E\u0039\u0037',
  '\u0031\u0037\u0032\u002E\u0036\u0036\u002E\u0034\u0037\u002E\u0038\u0038',
  '\u0031\u0037\u0032\u002E\u0036\u0036\u002E\u0034\u0034\u002E\u0031\u0036\u0038',
  '\u0031\u0037\u0032\u002E\u0036\u0036\u002E\u0034\u0037\u002E\u0031\u0034\u0031',
  '\u0031\u0037\u0032\u002E\u0036\u0036\u002E\u0034\u0034\u002E\u0031\u0031\u0035',
  '\u0031\u0037\u0032\u002E\u0036\u0036\u002E\u0034\u0031\u002E\u0031\u0033\u0036',
  '\u0031\u0037\u0032\u002E\u0036\u0036\u002E\u0034\u0035\u002E\u0031\u0037\u0034',
  '\u0031\u0037\u0032\u002E\u0036\u0036\u002E\u0034\u0031\u002E\u0031\u0039\u0030',
  '\u0031\u0037\u0032\u002E\u0036\u0036\u002E\u0034\u0034\u002E\u0031\u0033\u0034',
  '\u0031\u0037\u0032\u002E\u0036\u0036\u002E\u0034\u0032\u002E\u0031\u0032\u0037',
  '\u0031\u0037\u0032\u002E\u0036\u0036\u002E\u0034\u0030\u002E\u0037\u0032',
  '\u0031\u0037\u0032\u002E\u0036\u0036\u002E\u0034\u0030\u002E\u0034\u0034',
  '\u0031\u0037\u0032\u002E\u0036\u0036\u002E\u0034\u0031\u002E\u0032\u0031\u0030',
  '\u0031\u0037\u0032\u002E\u0036\u0036\u002E\u0034\u0032\u002E\u0037\u0037',
  '\u0031\u0037\u0032\u002E\u0036\u0036\u002E\u0034\u0034\u002E\u0031\u0034\u0030',
  '\u0031\u0037\u0032\u002E\u0036\u0036\u002E\u0034\u0034\u002E\u0032\u0034\u0036',
  '\u0031\u0037\u0032\u002E\u0036\u0036\u002E\u0033\u002E\u0031\u0033\u0034',
  '\u0031\u0037\u0032\u002E\u0036\u0036\u002E\u0034\u0032\u002E\u0038\u0032',
  '\u0031\u0037\u0032\u002E\u0036\u0036\u002E\u0030\u002E\u0034\u0034',
  '\u0031\u0037\u0032\u002E\u0036\u0036\u002E\u0034\u0032\u002E\u0035\u0039',
  '\u0031\u0037\u0032\u002E\u0036\u0036\u002E\u0034\u0034\u002E\u0031\u0033\u0036',
  '\u0031\u0037\u0032\u002E\u0036\u0036\u002E\u0034\u0037\u002E\u0032\u0038',
  '\u0031\u0037\u0032\u002E\u0036\u0036\u002E\u0034\u0032\u002E\u0031\u0033\u0039',
  '\u0031\u0037\u0032\u002E\u0036\u0036\u002E\u0034\u0034\u002E\u0031\u0031\u0038',
  '\u0031\u0037\u0032\u002E\u0036\u0036\u002E\u0034\u0031\u002E\u0033\u0036',
  '\u0031\u0037\u0032\u002E\u0036\u0036\u002E\u0033\u002E\u0037\u0032',
  '\u0031\u0037\u0032\u002E\u0036\u0036\u002E\u0034\u0034\u002E\u0031\u0036\u0030',
  '\u0031\u0037\u0032\u002E\u0036\u0036\u002E\u0034\u0035\u002E\u0031\u0035\u0039',
  '\u0031\u0037\u0032\u002E\u0036\u0036\u002E\u0034\u0036\u002E\u0032\u0032\u0036',
  '\u0031\u0037\u0032\u002E\u0036\u0036\u002E\u0034\u0030\u002E\u0032\u0030\u0039',
  '\u0031\u0037\u0032\u002E\u0036\u0036\u002E\u0034\u0032\u002E\u0037\u0031',
  '\u0031\u0037\u0032\u002E\u0036\u0036\u002E\u0034\u0031\u002E\u0039',
  '\u0031\u0037\u0032\u002E\u0036\u0036\u002E\u0034\u0031\u002E\u0031\u0031',
  '\u0031\u0037\u0032\u002E\u0036\u0036\u002E\u0034\u0036\u002E\u0038\u0037',
  '\u0031\u0037\u0032\u002E\u0036\u0036\u002E\u0034\u0031\u002E\u0032\u0033\u0035',
  '\u0031\u0037\u0032\u002E\u0036\u0036\u002E\u0034\u0032\u002E\u0034\u0030',
  '\u0031\u0037\u0032\u002E\u0036\u0036\u002E\u0034\u0037\u002E\u0031',
  '\u0031\u0037\u0032\u002E\u0036\u0036\u002E\u0034\u0032\u002E\u0033',
  '\u0031\u0030\u0034\u002E\u0031\u0036\u002E\u0031\u0034\u002E\u0039\u0039',
  '\u0031\u0030\u0034\u002E\u0031\u0036\u002E\u0031\u0032\u0030\u002E\u0032\u0032\u0032',
  '\u0031\u0030\u0034\u002E\u0031\u0036\u002E\u0031\u0032\u0035\u002E\u0032\u0034\u0032',
  '\u0031\u0030\u0034\u002E\u0031\u0036\u002E\u0031\u0032\u0036\u002E\u0031\u0037\u0038',
  '\u0031\u0030\u0034\u002E\u0031\u0036\u002E\u0031\u0033\u0035\u002E\u0031\u0034\u0037',
  '\u0031\u0030\u0034\u002E\u0031\u0036\u002E\u0031\u0033\u0036\u002E\u0037\u0038',
  '\u0031\u0030\u0034\u002E\u0031\u0036\u002E\u0031\u0034\u0030\u002E\u0031\u0035\u0035',
  '\u0031\u0030\u0034\u002E\u0031\u0036\u002E\u0031\u0034\u0032\u002E\u0032\u0030\u0035',
  '\u0031\u0030\u0034\u002E\u0031\u0036\u002E\u0031\u0036\u0030\u002E\u0031\u0033\u0037',
  '\u0031\u0030\u0034\u002E\u0031\u0036\u002E\u0031\u0039\u0038\u002E\u0037\u0038',
  '\u0031\u0030\u0034\u002E\u0031\u0036\u002E\u0032\u0030\u0031\u002E\u0031\u0035\u0038',
  '\u0031\u0030\u0034\u002E\u0031\u0036\u002E\u0032\u0030\u0032\u002E\u0031\u0037',
  '\u0031\u0030\u0034\u002E\u0031\u0036\u002E\u0032\u0031\u0030\u002E\u0032\u0034\u0030',
  '\u0031\u0030\u0034\u002E\u0031\u0036\u002E\u0032\u0031\u0033\u002E\u0031\u0035',
  '\u0031\u0030\u0034\u002E\u0031\u0036\u002E\u0032\u0032\u0036\u002E\u0032\u0034\u0037',
  '\u0031\u0030\u0034\u002E\u0031\u0036\u002E\u0032\u0033\u0033\u002E\u0032\u0032\u0036',
  '\u0031\u0030\u0034\u002E\u0031\u0036\u002E\u0032\u0034\u0030\u002E\u0031\u0034\u0036',
  '\u0031\u0030\u0034\u002E\u0031\u0036\u002E\u0032\u0034\u0033\u002E\u0035\u0039',
  '\u0031\u0030\u0034\u002E\u0031\u0036\u002E\u0032\u0034\u0036\u002E\u0031\u0033\u0030',
  '\u0031\u0030\u0034\u002E\u0031\u0036\u002E\u0032\u0034\u0038\u002E\u0031\u0038\u0031',
  '\u0031\u0030\u0034\u002E\u0031\u0036\u002E\u0032\u0035\u0032\u002E\u0032\u0032\u0031',
  '\u0031\u0030\u0034\u002E\u0031\u0036\u002E\u0035\u0034\u002E\u0031\u0035\u0030',
  '\u0031\u0030\u0034\u002E\u0031\u0036\u002E\u0031\u0034\u0032\u002E\u0032\u0030\u0035',
  '\u0031\u0030\u0034\u002E\u0031\u0036\u002E\u0034\u0036\u002E\u0039\u0036',
  '\u0031\u0030\u0034\u002E\u0031\u0037\u002E\u0031\u0031\u0033\u002E\u0031\u0030\u0031',
  '\u0031\u0030\u0034\u002E\u0031\u0037\u002E\u0031\u0033\u0037\u002E\u0031\u0033\u0032',
  '\u0031\u0030\u0034\u002E\u0031\u0037\u002E\u0031\u0034\u0033\u002E\u0031\u0032\u0031',
  '\u0031\u0030\u0034\u002E\u0031\u0037\u002E\u0031\u0035\u0038\u002E\u0031\u0035\u0030',
  '\u0031\u0030\u0034\u002E\u0031\u0037\u002E\u0031\u0037\u0032\u002E\u0039\u0037',
  '\u0031\u0030\u0034\u002E\u0031\u0037\u002E\u0031\u0038\u0030\u002E\u0031\u0034\u0033',
  '\u0031\u0030\u0034\u002E\u0031\u0037\u002E\u0031\u0038\u0033\u002E\u0037\u0033',
  '\u0031\u0030\u0034\u002E\u0031\u0037\u002E\u0031\u0038\u0034\u002E\u0031\u0031\u0031',
  '\u0031\u0030\u0034\u002E\u0031\u0037\u002E\u0031\u0039\u0035\u002E\u0031\u0033\u0036',
  '\u0031\u0030\u0034\u002E\u0031\u0037\u002E\u0031\u0039\u0037\u002E\u0032\u0030\u0033',
  '\u0031\u0030\u0034\u002E\u0031\u0037\u002E\u0032\u0031\u0038\u002E\u0033\u0030',
  '\u0031\u0030\u0034\u002E\u0031\u0037\u002E\u0032\u0031\u0038\u002E\u0038\u0035',
  '\u0031\u0030\u0034\u002E\u0031\u0037\u002E\u0032\u0033\u0039\u002E\u0031\u0036\u0036',
  '\u0031\u0030\u0034\u002E\u0031\u0037\u002E\u0033\u0035\u002E\u0032\u0032\u0037',
  '\u0031\u0030\u0034\u002E\u0031\u0037\u002E\u0033\u0038\u002E\u0034\u0032',
  '\u0031\u0030\u0034\u002E\u0031\u0037\u002E\u0035\u0033\u002E\u0037\u0038',
  '\u0031\u0030\u0034\u002E\u0031\u0037\u002E\u0036\u0032\u002E\u0031\u0036\u0034',
  '\u0031\u0030\u0034\u002E\u0031\u0037\u002E\u0036\u0034\u002E\u0032\u0035\u0032',
  '\u0031\u0030\u0034\u002E\u0031\u0037\u002E\u0036\u0039\u002E\u0031\u0032\u0039',
  '\u0031\u0030\u0034\u002E\u0031\u0037\u002E\u0037\u0031\u002E\u0031\u0034\u0031',
  '\u0031\u0030\u0034\u002E\u0031\u0037\u002E\u0037\u0035\u002E\u0036\u0035',
  '\u0031\u0030\u0034\u002E\u0031\u0037\u002E\u0038\u0030\u002E\u0032\u0032\u0030',
  '\u0031\u0030\u0034\u002E\u0031\u0037\u002E\u0038\u0030\u002E\u0032\u0032\u0037',
  '\u0031\u0030\u0034\u002E\u0031\u0037\u002E\u0038\u0031\u002E\u0031\u0033\u0038',
  '\u0031\u0030\u0034\u002E\u0031\u0037\u002E\u0038\u0031\u002E\u0039',
  '\u0031\u0030\u0034\u002E\u0031\u0037\u002E\u0038\u0033\u002E\u0033',
  '\u0031\u0030\u0034\u002E\u0031\u0037\u002E\u0038\u0037\u002E\u0032\u0030\u0038',
  '\u0031\u0030\u0034\u002E\u0031\u0038\u002E\u0031\u0030\u0038\u002E\u0032\u0033\u0037',
  '\u0031\u0030\u0034\u002E\u0031\u0038\u002E\u0031\u0031\u0030\u002E\u0032\u0035\u0035',
  '\u0031\u0030\u0034\u002E\u0031\u0038\u002E\u0031\u0032\u0033\u002E\u0031\u0030\u0031',
  '\u0031\u0030\u0034\u002E\u0031\u0038\u002E\u0031\u0037\u002E\u0031\u0033\u0036',
  '\u0031\u0030\u0034\u002E\u0031\u0038\u002E\u0031\u0037\u0032\u002E\u0032\u0037',
  '\u0031\u0030\u0034\u002E\u0031\u0038\u002E\u0031\u0037\u0033\u002E\u0031\u0032\u0034',
  '\u0031\u0030\u0034\u002E\u0031\u0038\u002E\u0031\u0037\u0033\u002E\u0031\u0037\u0035',
  '\u0031\u0030\u0034\u002E\u0031\u0038\u002E\u0031\u0038\u0038\u002E\u0032\u0031\u0032',
  '\u0031\u0030\u0034\u002E\u0031\u0038\u002E\u0031\u0039\u0035\u002E\u0033',
  '\u0031\u0030\u0034\u002E\u0031\u0038\u002E\u0032\u0030\u0032\u002E\u0031\u0030\u0038',
  '\u0031\u0030\u0034\u002E\u0031\u0038\u002E\u0032\u0030\u0032\u002E\u0032\u0033\u0032',
  '\u0031\u0030\u0034\u002E\u0031\u0038\u002E\u0032\u0030\u0033\u002E\u0032\u0033\u0032',
  '\u0031\u0030\u0034\u002E\u0031\u0038\u002E\u0032\u0035\u002E\u0031\u0034\u0031',
  '\u0031\u0030\u0034\u002E\u0031\u0038\u002E\u0032\u0035\u0033\u002E\u0031\u0034\u0035',
  '\u0031\u0030\u0034\u002E\u0031\u0038\u002E\u0032\u0035\u0034\u002E\u0039\u0031',
  '\u0031\u0030\u0034\u002E\u0031\u0038\u002E\u0032\u0036\u002E\u0032\u0034\u0031',
  '\u0031\u0030\u0034\u002E\u0031\u0038\u002E\u0032\u0037\u002E\u0031\u0030\u0036',
  '\u0031\u0030\u0034\u002E\u0031\u0038\u002E\u0034\u0037\u002E\u0031\u0033\u0033',
  '\u0031\u0030\u0034\u002E\u0031\u0038\u002E\u0037\u0036\u002E\u0032\u0034\u0039',
  '\u0031\u0030\u0034\u002E\u0031\u0038\u002E\u0038\u0030\u002E\u0037\u0038',
  '\u0031\u0030\u0034\u002E\u0031\u0038\u002E\u0038\u0037\u002E\u0031\u0032\u0035',
  '\u0031\u0030\u0034\u002E\u0031\u0039\u002E\u0031\u0030\u0031\u002E\u0032\u0034\u0032',
  '\u0031\u0030\u0034\u002E\u0031\u0039\u002E\u0031\u0030\u0035\u002E\u0031\u0037\u0032',
  '\u0031\u0030\u0034\u002E\u0031\u0039\u002E\u0031\u0030\u0037\u002E\u0031\u0034\u0032',
  '\u0031\u0030\u0034\u002E\u0031\u0039\u002E\u0031\u0031\u0037\u002E\u0032\u0032\u0035',
  '\u0031\u0030\u0034\u002E\u0031\u0039\u002E\u0031\u0032\u002E\u0031\u0037\u0030',
  '\u0031\u0030\u0034\u002E\u0031\u0039\u002E\u0031\u0032\u0032\u002E\u0033\u0038',
  '\u0031\u0030\u0034\u002E\u0031\u0039\u002E\u0031\u0034\u0030\u002E\u0032\u0030\u0033',
  '\u0031\u0030\u0034\u002E\u0031\u0039\u002E\u0031\u0034\u0034\u002E\u0032\u0033\u0032',
  '\u0031\u0030\u0034\u002E\u0031\u0039\u002E\u0031\u0036\u0036\u002E\u0031\u0031',
  '\u0031\u0030\u0034\u002E\u0031\u0039\u002E\u0031\u0038\u0034\u002E\u0032\u0032\u0036',
  '\u0031\u0030\u0034\u002E\u0031\u0039\u002E\u0031\u0038\u0039\u002E\u0034\u0031',
  '\u0031\u0030\u0034\u002E\u0031\u0039\u002E\u0031\u0039\u0031\u002E\u0038\u0039',
  '\u0031\u0030\u0034\u002E\u0031\u0039\u002E\u0031\u0039\u0038\u002E\u0031\u0030\u0031',
  '\u0031\u0030\u0034\u002E\u0031\u0039\u002E\u0032\u0031\u0035\u002E\u0031\u0032\u0035',
  '\u0031\u0030\u0034\u002E\u0031\u0039\u002E\u0032\u0033\u0034\u002E\u0035\u0039',
  '\u0031\u0030\u0034\u002E\u0031\u0039\u002E\u0032\u0035\u0030\u002E\u0032\u0030',
  '\u0031\u0030\u0034\u002E\u0031\u0039\u002E\u0032\u0035\u0035\u002E\u0035\u0031',
  '\u0031\u0030\u0034\u002E\u0031\u0039\u002E\u0036\u0034\u002E\u0034\u0035',
  '\u0031\u0030\u0034\u002E\u0031\u0039\u002E\u0038\u002E\u0033\u0035',
  '\u0031\u0030\u0034\u002E\u0031\u0039\u002E\u0038\u0035\u002E\u0035\u0032',
  '\u0031\u0030\u0034\u002E\u0031\u0039\u002E\u0039\u0034\u002E\u0032\u0033\u0038',
  '\u0031\u0030\u0034\u002E\u0031\u0039\u002E\u0031\u0030\u002E\u0031\u0036\u0033',
  '\u0031\u0030\u0034\u002E\u0031\u0039\u002E\u0031\u0030\u0034\u002E\u0032\u0034\u0036',
  '\u0031\u0030\u0034\u002E\u0031\u0039\u002E\u0031\u0031\u0037\u002E\u0032\u0032\u0035',
  '\u0031\u0030\u0034\u002E\u0031\u0039\u002E\u0031\u0032\u0032\u002E\u0033\u0038',
  '\u0031\u0030\u0034\u002E\u0031\u0039\u002E\u0031\u0034\u0034\u002E\u0032\u0033\u0032',
  '\u0031\u0030\u0034\u002E\u0031\u0039\u002E\u0031\u0036\u0036\u002E\u0031\u0031',
  '\u0031\u0030\u0034\u002E\u0031\u0039\u002E\u0031\u0038\u0034\u002E\u0032\u0032\u0036',
  '\u0031\u0030\u0034\u002E\u0031\u0039\u002E\u0031\u0038\u0039\u002E\u0034\u0031',
  '\u0031\u0030\u0034\u002E\u0031\u0039\u002E\u0031\u0039\u0031\u002E\u0038\u0039',
  '\u0031\u0030\u0034\u002E\u0031\u0039\u002E\u0031\u0039\u0038\u002E\u0031\u0030\u0031',
  '\u0031\u0030\u0034\u002E\u0031\u0039\u002E\u0032\u0031\u0035\u002E\u0031\u0032\u0035',
  '\u0031\u0030\u0034\u002E\u0031\u0039\u002E\u0032\u0033\u0034\u002E\u0035\u0039',
  '\u0031\u0030\u0034\u002E\u0031\u0039\u002E\u0032\u0035\u0030\u002E\u0032\u0030',
  '\u0031\u0030\u0034\u002E\u0031\u0039\u002E\u0032\u0035\u0035\u002E\u0035\u0031',
  '\u0031\u0030\u0034\u002E\u0031\u0039\u002E\u0036\u0034\u002E\u0034\u0035',
  '\u0031\u0030\u0034\u002E\u0031\u0039\u002E\u0038\u002E\u0033\u0035',
  '\u0031\u0030\u0034\u002E\u0031\u0039\u002E\u0038\u0035\u002E\u0035\u0032',
  '\u0031\u0030\u0034\u002E\u0031\u0039\u002E\u0039\u0034\u002E\u0032\u0033\u0038',
  '\u0031\u0030\u0034\u002E\u0032\u0030\u002E\u0032\u0032\u002E\u0032\u0031\u0031',
  '\u0031\u0030\u0034\u002E\u0032\u0030\u002E\u0033\u002E\u0039\u0035',
  '\u0031\u0030\u0034\u002E\u0032\u0030\u002E\u0034\u0039\u002E\u0031\u0030',
  '\u0031\u0030\u0034\u002E\u0032\u0031\u002E\u0031\u0030\u0039\u002E\u0032\u0033\u0030',
  '\u0031\u0030\u0034\u002E\u0032\u0031\u002E\u0031\u0031\u0032\u002E\u0031',
  '\u0031\u0030\u0034\u002E\u0032\u0031\u002E\u0032\u0030\u0033\u002E\u0032\u0034\u0036',
  '\u0031\u0030\u0034\u002E\u0032\u0031\u002E\u0032\u0031\u0037\u002E\u0034\u0038',
  '\u0031\u0030\u0034\u002E\u0032\u0031\u002E\u0032\u0033\u0033\u002E\u0031\u0037\u0037',
  '\u0031\u0030\u0034\u002E\u0032\u0031\u002E\u0033\u0032\u002E\u0031',
  '\u0031\u0030\u0034\u002E\u0032\u0031\u002E\u0034\u002E\u0032\u0032\u0035',
  '\u0031\u0030\u0034\u002E\u0032\u0031\u002E\u0034\u0033\u002E\u0031\u0034\u0035',
  '\u0031\u0030\u0034\u002E\u0032\u0031\u002E\u0034\u0038\u002E\u0031',
  '\u0031\u0030\u0034\u002E\u0032\u0031\u002E\u0035\u0032\u002E\u0039\u0035',
  '\u0031\u0030\u0034\u002E\u0032\u0031\u002E\u0036\u0034\u002E\u0031',
  '\u0031\u0030\u0034\u002E\u0032\u0031\u002E\u0038\u0030\u002E\u0031',
  '\u0031\u0030\u0034\u002E\u0032\u0031\u002E\u0039\u0036\u002E\u0031',
  '\u0031\u0030\u0034\u002E\u0032\u0031\u002E\u0039\u0036\u002E\u0032\u0031\u0032',
  '\u0031\u0030\u0034\u002E\u0032\u0031\u002E\u0039\u0038\u002E\u0031\u0038\u0034',
  '\u0031\u0030\u0034\u002E\u0032\u0031\u002E\u0039\u002E\u0033\u0036',
  '\u0031\u0030\u0034\u002E\u0032\u0034\u002E\u0030\u002E\u0032\u0033\u0034',
  '\u0031\u0030\u0034\u002E\u0032\u0034\u002E\u0031\u0034\u0036\u002E\u0032\u0034',
  '\u0031\u0030\u0034\u002E\u0032\u0034\u002E\u0031\u0035\u0036\u002E\u0038\u0036',
  '\u0031\u0030\u0034\u002E\u0032\u0034\u002E\u0031\u0036\u002E\u0031\u0038\u0034',
  '\u0031\u0030\u0034\u002E\u0032\u0034\u002E\u0031\u0037\u0037\u002E\u0036\u0039',
  '\u0031\u0030\u0034\u002E\u0032\u0034\u002E\u0035\u0033\u002E\u0032\u0033\u0035',
  '\u0031\u0030\u0034\u002E\u0032\u0034\u002E\u0038\u0039\u002E\u0031\u0038\u0031',
  '\u0031\u0030\u0034\u002E\u0032\u0035\u002E\u0031\u0030\u002E\u0031\u0036\u0033',
  '\u0031\u0030\u0034\u002E\u0032\u0035\u002E\u0031\u0030\u0031\u002E\u0031\u0032\u0038',
  '\u0031\u0030\u0034\u002E\u0032\u0035\u002E\u0031\u0030\u0033\u002E\u0031\u0033\u0039',
  '\u0031\u0030\u0034\u002E\u0032\u0035\u002E\u0031\u0031\u0038\u002E\u0032\u0033\u0035',
  '\u0031\u0030\u0034\u002E\u0032\u0035\u002E\u0033\u0036\u002E\u0031\u0030\u0036',
  '\u0031\u0030\u0034\u002E\u0032\u0035\u002E\u0036\u0035\u002E\u0031\u0038\u0036',
  '\u0031\u0030\u0034\u002E\u0032\u0035\u002E\u0037\u0037\u002E\u0033\u0033',
  '\u0031\u0030\u0034\u002E\u0032\u0036\u002E\u0031\u0035\u002E\u0031\u0036',
  '\u0031\u0030\u0034\u002E\u0032\u0037\u002E\u0032\u0034\u002E\u0031\u0038\u0038',
  '\u0031\u0030\u0034\u002E\u0033\u0031\u002E\u0031\u0036\u002E\u0031\u0033\u0036',
  '\u0031\u0030\u0038\u002E\u0031\u0036\u0032\u002E\u0031\u0039\u0032\u002E\u0031\u0039\u0038',
  '\u0031\u0034\u0031\u002E\u0031\u0030\u0031\u002E\u0031\u0031\u0034\u002E\u0031\u0039\u0037',
  '\u0031\u0034\u0031\u002E\u0031\u0030\u0031\u002E\u0031\u0031\u0034\u002E\u0032\u0034\u0035',
  '\u0031\u0034\u0031\u002E\u0031\u0030\u0031\u002E\u0031\u0031\u0034\u002E\u0039\u0035',
  '\u0031\u0034\u0031\u002E\u0031\u0030\u0031\u002E\u0031\u0031\u0035\u002E\u0034\u0036',
  '\u0031\u0034\u0031\u002E\u0031\u0030\u0031\u002E\u0031\u0032\u0030\u002E\u0031\u0034\u0037',
  '\u0031\u0034\u0031\u002E\u0031\u0030\u0031\u002E\u0031\u0032\u0030\u002E\u0032\u0034\u0036',
  '\u0031\u0034\u0031\u002E\u0031\u0030\u0031\u002E\u0031\u0032\u0031\u002E\u0031\u0030\u0034',
  '\u0031\u0034\u0031\u002E\u0031\u0030\u0031\u002E\u0031\u0032\u0031\u002E\u0032\u0034\u0039',
  '\u0031\u0034\u0031\u002E\u0031\u0030\u0031\u002E\u0031\u0032\u0032\u002E\u0031\u0034\u0038',
  '\u0031\u0036\u0032\u002E\u0031\u0035\u0039\u002E\u0031\u0032\u0039\u002E\u0031\u0039\u0036',
  '\u0031\u0036\u0032\u002E\u0031\u0035\u0039\u002E\u0031\u0033\u0034\u002E\u0031\u0030\u0031',
  '\u0031\u0036\u0032\u002E\u0031\u0035\u0039\u002E\u0031\u0033\u0034\u002E\u0031\u0036\u0032',
  '\u0031\u0036\u0032\u002E\u0031\u0035\u0039\u002E\u0031\u0033\u0034\u002E\u0037\u0036',
  '\u0031\u0036\u0032\u002E\u0031\u0035\u0039\u002E\u0031\u0033\u0038\u002E\u0032\u0036',
  '\u0031\u0036\u0032\u002E\u0031\u0035\u0039\u002E\u0031\u0033\u0038\u002E\u0039\u0030',
  '\u0031\u0036\u0032\u002E\u0031\u0035\u0039\u002E\u0031\u0034\u0033\u002E\u0032\u0030\u0038',
  '\u0031\u0036\u0032\u002E\u0031\u0035\u0039\u002E\u0031\u0035\u0033\u002E\u0033\u0030',
  '\u0031\u0036\u0032\u002E\u0031\u0035\u0039\u002E\u0032\u0033\u0035\u002E\u0032\u0034\u0037',
  '\u0031\u0036\u0032\u002E\u0031\u0035\u0039\u002E\u0032\u0033\u0036\u002E\u0032\u0034\u0030',
  '\u0031\u0036\u0032\u002E\u0031\u0035\u0039\u002E\u0032\u0033\u0037\u002E\u0032\u0033\u0038',
  '\u0031\u0036\u0032\u002E\u0031\u0035\u0039\u002E\u0032\u0033\u0039\u002E\u0032\u0032\u0031',
  '\u0031\u0036\u0032\u002E\u0031\u0035\u0039\u002E\u0032\u0034\u0038\u002E\u0031\u0035\u0031',
  '\u0031\u0036\u0032\u002E\u0031\u0035\u0039\u002E\u0032\u0034\u0039\u002E\u0039\u0032',
  '\u0031\u0036\u0032\u002E\u0031\u0035\u0039\u002E\u0032\u0035\u0033\u002E\u0031\u0037\u0032',
  '\u0031\u0036\u0032\u002E\u0031\u0035\u0039\u002E\u0032\u0035\u0035\u002E\u0031\u0030\u0031',
  '\u0031\u0036\u0032\u002E\u0031\u0035\u0039\u002E\u0034\u0031\u002E\u0035\u0032',
  '\u0031\u0036\u0032\u002E\u0031\u0035\u0039\u002E\u0036\u0032\u002E\u0036\u0039',
  '\u0031\u0036\u0032\u002E\u0032\u0035\u0031\u002E\u0038\u0032\u002E\u0031\u0038\u0037',
  '\u0031\u0037\u0032\u002E\u0036\u0034\u002E\u0031\u0035\u0033\u002E\u0032\u0033\u0035',
  '\u0031\u0037\u0032\u002E\u0036\u0034\u002E\u0033\u0035\u002E\u0032\u0032\u0036',
  '\u0031\u0037\u0032\u002E\u0036\u0034\u002E\u0036\u0036\u002E\u0031\u0033\u0031',
  '\u0031\u0037\u0032\u002E\u0036\u0034\u002E\u0036\u0036\u002E\u0031\u0036\u0035',
  '\u0031\u0037\u0032\u002E\u0036\u0034\u002E\u0036\u0038\u002E\u0031\u0036\u0032',
  '\u0031\u0037\u0032\u002E\u0036\u0034\u002E\u0038\u0030\u002E\u0031\u0035\u0032',
  '\u0031\u0037\u0032\u002E\u0036\u0034\u002E\u0038\u0031\u002E\u0031\u0035\u0033',
  '\u0031\u0037\u0032\u002E\u0036\u0034\u002E\u0038\u0036\u002E\u0031\u0034\u0032',
  '\u0031\u0037\u0032\u002E\u0036\u0034\u002E\u0038\u0039\u002E\u0031\u0031\u0038',
  '\u0031\u0037\u0032\u002E\u0036\u0034\u002E\u0038\u0039\u002E\u0038\u0034',
  '\u0031\u0037\u0032\u002E\u0036\u0034\u002E\u0039\u0030\u002E\u0031\u0034\u0034',
  '\u0031\u0037\u0032\u002E\u0036\u0034\u002E\u0039\u0031\u002E\u0038\u0037',
  '\u0031\u0037\u0032\u002E\u0036\u0034\u002E\u0039\u0033\u002E\u0032\u0032\u0030',
  '\u0031\u0037\u0032\u002E\u0036\u0034\u002E\u0039\u0034\u002E\u0031\u0031\u0031',
  '\u0031\u0037\u0032\u002E\u0036\u0034\u002E\u0039\u0034\u002E\u0031\u0033\u0037',
  '\u0031\u0037\u0032\u002E\u0036\u0034\u002E\u0039\u0034\u002E\u0039',
  '\u0031\u0037\u0032\u002E\u0036\u0036\u002E\u0032\u0030\u0035\u002E\u0039\u0035',
  '\u0031\u0037\u0032\u002E\u0036\u0036\u002E\u0032\u0031\u0033\u002E\u0033\u0038',
  '\u0031\u0037\u0032\u002E\u0036\u0036\u002E\u0034\u0034\u002E\u0031\u0039\u0034',
  '\u0031\u0037\u0032\u002E\u0036\u0036\u002E\u0034\u0034\u002E\u0038\u0031',
  '\u0031\u0037\u0032\u002E\u0036\u0036\u002E\u0034\u0035\u002E\u0039',
  '\u0031\u0037\u0032\u002E\u0036\u0036\u002E\u0034\u0036\u002E\u0032\u0034\u0037',
  '\u0031\u0037\u0032\u002E\u0036\u0036\u002E\u0034\u0037\u002E\u0031\u0037\u0035',
  '\u0031\u0037\u0032\u002E\u0036\u0036\u002E\u0034\u0037\u002E\u0036\u0032',
  '\u0031\u0037\u0032\u002E\u0036\u0036\u002E\u0034\u0037\u002E\u0039\u0030',
  '\u0031\u0037\u0032\u002E\u0036\u0037\u002E\u0031\u0030\u0034\u002E\u0032\u0035\u0035',
  '\u0031\u0037\u0032\u002E\u0036\u0037\u002E\u0031\u0031\u0036\u002E\u0036\u0033',
  '\u0031\u0037\u0032\u002E\u0036\u0037\u002E\u0031\u0032\u0030\u002E\u0035\u0037',
  '\u0031\u0037\u0032\u002E\u0036\u0037\u002E\u0031\u0032\u0032\u002E\u0036\u0032',
  '\u0031\u0037\u0032\u002E\u0036\u0037\u002E\u0031\u0032\u0036\u002E\u0031\u0033\u0037',
  '\u0031\u0037\u0032\u002E\u0036\u0037\u002E\u0031\u0033\u0032\u002E\u0031\u0037\u0039',
  '\u0031\u0037\u0032\u002E\u0036\u0037\u002E\u0031\u0033\u0033\u002E\u0031\u0037\u0036',
  '\u0031\u0037\u0032\u002E\u0036\u0037\u002E\u0031\u0033\u0034\u002E\u0032\u0032\u0036',
  '\u0031\u0037\u0032\u002E\u0036\u0037\u002E\u0031\u0034\u0031\u002E\u0031\u0039\u0031',
  '\u0031\u0037\u0032\u002E\u0036\u0037\u002E\u0031\u0034\u0036\u002E\u0032\u0038',
  '\u0031\u0037\u0032\u002E\u0036\u0037\u002E\u0031\u0035\u0032\u002E\u0031\u0035\u0034',
  '\u0031\u0037\u0032\u002E\u0036\u0037\u002E\u0031\u0035\u0037\u002E\u0031\u0037\u0033',
  '\u0031\u0037\u0032\u002E\u0036\u0037\u002E\u0031\u0035\u0037\u002E\u0032',
  '\u0031\u0037\u0032\u002E\u0036\u0037\u002E\u0031\u0035\u0038\u002E\u0037\u0039',
  '\u0031\u0037\u0032\u002E\u0036\u0037\u002E\u0031\u0036\u0034\u002E\u0034\u0036',
  '\u0031\u0037\u0032\u002E\u0036\u0037\u002E\u0031\u0037\u0031\u002E\u0031\u0030\u0036',
  '\u0031\u0037\u0032\u002E\u0036\u0037\u002E\u0031\u0037\u0037\u002E\u0032\u0038',
  '\u0031\u0037\u0032\u002E\u0036\u0037\u002E\u0031\u0038\u0032\u002E\u0037\u0033',
  '\u0031\u0037\u0032\u002E\u0036\u0037\u002E\u0031\u0039\u0033\u002E\u0031\u0037\u0030',
  '\u0031\u0037\u0032\u002E\u0036\u0037\u002E\u0032\u0030\u0035\u002E\u0031\u0034\u0036',
  '\u0031\u0037\u0032\u002E\u0036\u0037\u002E\u0032\u0030\u0037\u002E\u0033\u0035',
  '\u0031\u0037\u0032\u002E\u0036\u0037\u002E\u0032\u0031\u0039\u002E\u0031\u0030\u0033',
  '\u0031\u0037\u0032\u002E\u0036\u0037\u002E\u0032\u0032\u0036\u002E\u0031\u0032\u0037',
  '\u0031\u0037\u0032\u002E\u0036\u0037\u002E\u0032\u0035\u0030\u002E\u0032\u0030\u0039',
  '\u0031\u0037\u0032\u002E\u0036\u0037\u002E\u0037\u0030\u002E\u0031\u0030',
  '\u0031\u0037\u0032\u002E\u0036\u0037\u002E\u0037\u0032\u002E\u0032\u0034\u0031',
  '\u0031\u0037\u0032\u002E\u0036\u0037\u002E\u0037\u0034\u002E\u0032\u0030\u0034',
  '\u0031\u0037\u0032\u002E\u0036\u0037\u002E\u0037\u0039\u002E\u0031\u0038\u0032',
  '\u0031\u0037\u0032\u002E\u0036\u0037\u002E\u0038\u0031\u002E\u0032\u0033\u0037',
  '\u0031\u0037\u0032\u002E\u0036\u0037\u002E\u0039\u0036\u002E\u0032\u0035',
  '\u0031\u0037\u0032\u002E\u0036\u0037\u002E\u0039\u0037\u002E\u0032\u0034\u0039',
  '\u0031\u0038\u0038\u002E\u0031\u0031\u0034\u002E\u0039\u0036\u002E\u0033',
  '\u0031\u0038\u0038\u002E\u0031\u0031\u0034\u002E\u0039\u0037\u002E\u0033',
  '\u0031\u0038\u0038\u002E\u0031\u0031\u0034\u002E\u0039\u0038\u002E\u0031',
  '\u0031\u0038\u0038\u002E\u0031\u0031\u0034\u002E\u0039\u0038\u002E\u0032\u0032\u0034',
  '\u0031\u0038\u0038\u002E\u0031\u0031\u0034\u002E\u0039\u0039\u002E\u0031\u0033\u0037',
  '\u0031\u0039\u0030\u002E\u0039\u0033\u002E\u0032\u0034\u0034\u002E\u0032\u0030\u0031',
  '\u0031\u0039\u0030\u002E\u0039\u0033\u002E\u0032\u0034\u0034\u002E\u0038\u0030',
  '\u0031\u0039\u0030\u002E\u0039\u0033\u002E\u0032\u0034\u0035\u002E\u0031\u0030\u0038',
  '\u0031\u0039\u0030\u002E\u0039\u0033\u002E\u0032\u0034\u0035\u002E\u0031\u0033\u0033',
  '\u0031\u0039\u0030\u002E\u0039\u0033\u002E\u0032\u0034\u0035\u002E\u0031\u0034\u0036',
  '\u0031\u0039\u0030\u002E\u0039\u0033\u002E\u0032\u0034\u0035\u002E\u0038\u0037',
  '\u0031\u0039\u0030\u002E\u0039\u0033\u002E\u0032\u0034\u0036\u002E\u0031\u0031\u0033',
  '\u0031\u0039\u0030\u002E\u0039\u0033\u002E\u0032\u0034\u0037\u002E\u0030',
  '\u0031\u0039\u0033\u002E\u0039\u002E\u0034\u0039\u002E\u0034\u0038',
  '\u0031\u0039\u0033\u002E\u0039\u002E\u0034\u0039\u002E\u0036\u0037',
  '\u0031\u0039\u0038\u002E\u0034\u0031\u002E\u0032\u0030\u0038\u002E\u0031\u0037\u0036',
  '\u0031\u0039\u0038\u002E\u0034\u0031\u002E\u0032\u0030\u0038\u002E\u0031\u0038\u0036',
  '\u0031\u0039\u0038\u002E\u0034\u0031\u002E\u0032\u0030\u0039\u002E\u0030',
  '\u0031\u0039\u0038\u002E\u0034\u0031\u002E\u0032\u0030\u0039\u002E\u0031\u0031\u0030',
  '\u0031\u0039\u0038\u002E\u0034\u0031\u002E\u0032\u0030\u0039\u002E\u0031\u0038\u0032',
  '\u0031\u0039\u0038\u002E\u0034\u0031\u002E\u0032\u0030\u0039\u002E\u0031\u0039\u0032',
  '\u0031\u0039\u0038\u002E\u0034\u0031\u002E\u0032\u0030\u0039\u002E\u0032\u0034\u0033',
  '\u0031\u0039\u0038\u002E\u0034\u0031\u002E\u0032\u0031\u0031\u002E\u0032\u0030\u0033',
  '\u0031\u0039\u0038\u002E\u0034\u0031\u002E\u0032\u0032\u0032\u002E\u0031\u0036\u0036',
  '\u0034\u0035\u002E\u0031\u0034\u0032\u002E\u0031\u0032\u0030\u002E\u0034\u0030'
];

   let allUniqueIPs = [...githubIPs];
  
  if (allUniqueIPs.length < 50) {
    const needed = 50 - allUniqueIPs.length;
    
    const shuffledBackupIPs = [...backupIPs];
    for (let i = shuffledBackupIPs.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [shuffledBackupIPs[i], shuffledBackupIPs[j]] = [shuffledBackupIPs[j], shuffledBackupIPs[i]];
    }
    
    let addedCount = 0;
    for (let i = 0; i < shuffledBackupIPs.length && addedCount < needed; i++) {
      const ip = shuffledBackupIPs[i];
      if (!allUniqueIPs.includes(ip)) {
        allUniqueIPs.push(ip);
        addedCount++;
      }
    }
  }

  allUniqueIPs = allUniqueIPs.slice(0, 51);

  const isPagesDeployment = hostName.endsWith('.pages.dev');

  let configCounter = 0;
  
  allUniqueIPs.forEach((ip, index) => {
    const portIndex = index % allPorts.length;
    const selectedPort = allPorts[portIndex];
    
    const isHttpsPort = httpsPorts.includes(selectedPort);
    const protocol = isHttpsPort ? 'tls' : 'tcp';
    
    if (isPagesDeployment && !isHttpsPort) {
      return;
    }
    
    configCounter++;
    const tag = `${configCounter}🌟Star_${protocol.toUpperCase()}`;
    
    links.push(
      buildLink({ 
        core, 
        proto: protocol, 
        userID, 
        hostName, 
        address: ip, 
        port: selectedPort, 
        tag: tag,
        index: links.length
      })
    );
  });
  
  return new Response(btoa(links.join('\n')), {
    headers: { 'Content-Type': 'text/plain;charset=utf-8' },
  });
}

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    const hasPassword = await env.Chapoon.get('admin_password');

    if (!hasPassword) {
        if (url.pathname === '/setup' && request.method === 'POST') {
            const formData = await request.formData();
            const password = formData.get('password');
            const confirmPassword = formData.get('confirmPassword');
            
            if (!password || !confirmPassword) {
                return new Response('Both password fields are required', { status: 400 });
            }
            
            if (password !== confirmPassword) {
                return new Response('Passwords do not match', { status: 400 });
            }
            
            await env.Chapoon.put('admin_password', password);
            
            const headers = new Headers();
            headers.append('Location', '/login');
            return new Response(null, { status: 302, headers });
        }
        
        if (url.pathname === '/setup' || url.pathname === '/') {
            return showSetupPage();
        }
        
        const headers = new Headers();
        headers.append('Location', '/setup');
        return new Response(null, { status: 302, headers });
    }

    const userConfig = await loadFromKV(env);
    const cfg = Config.fromEnv(env);
    cfg.userID = userConfig.userID || '';

    const upgradeHeader = request.headers.get('Upgrade');
    if (upgradeHeader && upgradeHeader.toLowerCase() === 'websocket') {
        const requestConfig = {
            userID: cfg.userID,
            proxyIP: cfg.proxyIP,
            proxyPort: cfg.proxyPort,
            socks5Address: cfg.socks5.address,
            socks5Relay: cfg.socks5.relayMode,
            enableSocks: cfg.socks5.enabled,
            parsedSocks5Address: cfg.socks5.enabled
                ? socks5AddressParser(cfg.socks5.address)
                : {},
        };
        
        if (!cfg.userID) {
            return new Response('UUID not configured', { status: 400 });
        }
        
        return ProtocolOverWSHandler(request, requestConfig);
    }

    
    if (url.pathname === '/login') {
        if (request.method === 'POST') {
            const clientIP = request.headers.get('CF-Connecting-IP') || 'unknown';
            
            try {
                await checkRateLimit(env, clientIP);
            } catch (rateError) {
                return showLoginPage(rateError.message);
            }
            
            const formData = await request.formData();
            const password = formData.get('password');
            const storedPassword = await env.Chapoon.get('admin_password');
            
            if (password === storedPassword) {
                await env.Chapoon.delete(`rate_limit_${clientIP}`);
                
                const sessionToken = 'logged_in_' + Date.now();
                await setSessionToken(env, sessionToken);
                
                const headers = new Headers();
                headers.append('Location', '/');
                headers.append('Set-Cookie', `session_token=${sessionToken}; Path=/; HttpOnly; SameSite=Strict; Secure`);
                return new Response(null, { status: 302, headers });
            } else {
                const newAttempts = await incrementRateLimit(env, clientIP);
                let errorMessage = `Invalid password (${newAttempts}/${MAX_LOGIN_ATTEMPTS})`;
                
                if (newAttempts >= MAX_LOGIN_ATTEMPTS) {
                    errorMessage = 'Too many failed attempts. Account locked for 15 minutes';
                }
                
                return showLoginPage(errorMessage);
            }
        } else {
            const error = url.searchParams.get('error') || '';
            return showLoginPage(error);
        }
    }

    if (url.pathname === '/logout') {
        await clearSessionToken(env);
        const headers = new Headers();
        headers.append('Location', '/login');
        headers.append('Set-Cookie', 'session_token=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT');
        return new Response(null, { status: 302, headers });
    }

    if (url.pathname === '/save-config' && request.method === 'POST') {
        if (!(await checkAuth(env, request))) {
            return new Response('Unauthorized', { status: 401 });
        }
        
        try {
            const configData = await request.json();
            const result = await saveToKV(env, configData);
            
            if (result.success) {
                return new Response(JSON.stringify({ success: true }), {
                    headers: { 'Content-Type': 'application/json' }
                });
            } else {
                return new Response(JSON.stringify({ success: false, error: result.error }), {
                    status: 500,
                    headers: { 'Content-Type': 'application/json' }
                });
            }
        } catch (error) {
            return new Response(JSON.stringify({ success: false, error: error.message }), {
                status: 400,
                headers: { 'Content-Type': 'application/json' }
            });
        }
    }

        if (url.pathname === '/fragment-config') {
        if (!(await checkAuth(env, request))) {
            return new Response('Unauthorized', { status: 401 });
        }
        return handleFragmentApi(request, env);
    }

    if (url.pathname === '/change-password' && request.method === 'POST') {
        if (!(await checkAuth(env, request))) {
            return new Response('Unauthorized', { status: 401 });
        }
        
        try {
            const { currentPassword, newPassword } = await request.json();
            const storedPassword = await env.Chapoon.get('admin_password');
            
            if (currentPassword !== storedPassword) {
                return new Response(JSON.stringify({ error: 'Current password is incorrect' }), {
                    status: 400,
                    headers: { 'Content-Type': 'application/json' }
                });
            }
            
            await env.Chapoon.put('admin_password', newPassword);
            
            return new Response(JSON.stringify({ success: true }), {
                status: 200,
                headers: { 'Content-Type': 'application/json' }
            });
            
        } catch (error) {
            return new Response(JSON.stringify({ error: 'Server error: ' + error.message }), {
                status: 500,
                headers: { 'Content-Type': 'application/json' }
            });
        }
    }

if (url.pathname === '/default-sub') {
    return handleIpSubscription('xray', cfg.userID, url.hostname, env);
}

   if (url.pathname === '/') {
       if (!(await checkAuth(env, request))) {
           const headers = new Headers();
           headers.append('Location', '/login');
           return new Response(null, { status: 302, headers });
       }
       return handleConfigPage(userConfig, url.hostname, cfg.proxyAddress);
   }

    return new Response('Page not found', { status: 404 });
  },
};

function handleConfigPage(userConfig, hostName, proxyAddress) {
  const html = generateBeautifulConfigPage(userConfig, hostName, proxyAddress);
  return new Response(html, { headers: { 'Content-Type': 'text/html; charset=utf-8' } });
}

function generateBeautifulConfigPage(userConfig, hostName, proxyAddress) {

const subDefaultUrl = `https://${hostName}/default-sub#STAR_D`;

  let finalHTML = `
  <!doctype html>
  <html lang="en">
  <head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>🌟 Star</title>
    <link rel="preconnect" href="https://fonts.googleapis.com">
    <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
    <link href="https://fonts.googleapis.com/css2?family=Fira+Code:wght@300..700&display=swap" rel="stylesheet">
    <style>${getPageCSS()}</style> 
  </head>
  <body data-proxy-ip="${proxyAddress}">
    ${getPageHTML(subDefaultUrl, userConfig)}
    <div style="text-align: center; margin: 20px;">
      <a href="/logout" style="display: inline-block;padding: 12px 24px;background: #e53e3e;color: white;text-decoration: none;border-radius: 8px;font-weight: bold;transition: all 0.3s ease;font-weight: 500;font-size: 20px;">
        🚪 Logout
      </a>
    </div>
    <script>
      const userConfig = ${JSON.stringify(userConfig)};
    </script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js"></script>
    <script>${getPageScript()}</script>
        <div id="qrModal" class="qr-modal" style="display: none;">
            <div class="qr-container">
                <h3 class="qr-title">Scan QR Code</h3>
                <div id="qrcode"></div>
            </div>
        </div>
     </body>
  </html>`;

  return finalHTML;
}

async function ProtocolOverWSHandler(request, config) {
  const webSocketPair = new WebSocketPair();
  const [client, webSocket] = Object.values(webSocketPair);
  webSocket.accept();
  let address = '';
  let portWithRandomLog = '';
  let udpStreamWriter = null;
  const log = (/** @type {string} */ info, /** @type {undefined} */ event) => {
    console.log(`[${address}:${portWithRandomLog}] ${info}`, event || '');
  };
  const earlyDataHeader = request.headers.get('Sec-WebSocket-Protocol') || '';
  const readableWebSocketStream = MakeReadableWebSocketStream(webSocket, earlyDataHeader, log);
  let remoteSocketWapper = { value: null };
  let isDns = false;

  readableWebSocketStream
    .pipeTo(
      new WritableStream({
        async write(chunk, controller) {
          if (udpStreamWriter) {
            return udpStreamWriter.write(chunk);
          }

          if (remoteSocketWapper.value) {
            const writer = remoteSocketWapper.value.writable.getWriter();
            await writer.write(chunk);
            writer.releaseLock();
            return;
          }

          const {
            hasError,
            message,
            addressType,
            portRemote = 443,
            addressRemote = '',
            rawDataIndex,
            ProtocolVersion = new Uint8Array([0, 0]),
            isUDP,
          } = ProcessProtocolHeader(chunk, config.userID);

          address = addressRemote;
          portWithRandomLog = `${portRemote}--${Math.random()} ${isUDP ? 'udp' : 'tcp'} `;

          if (hasError) {
            throw new Error(message);
          }

          const vlessResponseHeader = new Uint8Array([ProtocolVersion[0], 0]);
          const rawClientData = chunk.slice(rawDataIndex);

          if (isUDP) {
            if (portRemote === 53) {
              const dnsPipeline = await createDnsPipeline(webSocket, vlessResponseHeader, log);
              udpStreamWriter = dnsPipeline.write;
              udpStreamWriter(rawClientData);
            } else {
              throw new Error('UDP proxy is only enabled for DNS (port 53)');
            }
            return;
          }

          HandleTCPOutBound(
            remoteSocketWapper,
            addressType,
            addressRemote,
            portRemote,
            rawClientData,
            webSocket,
            vlessResponseHeader,
            log,
            config,
          );
        },
        close() {
          log(`readableWebSocketStream closed`);
        },
        abort(err) {
          log(`readableWebSocketStream aborted`, err);
        },
      }),
    )
    .catch(err => {
      console.error('Pipeline failed:', err.stack || err);
    });

  return new Response(null, { status: 101, webSocket: client });
}

function isValidUUID(uuid) {
  const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  return uuidRegex.test(uuid);
}

async function HandleTCPOutBound(
  remoteSocket,
  addressType,
  addressRemote,
  portRemote,
  rawClientData,
  webSocket,
  protocolResponseHeader,
  log,
  config,
) {
  if (!config || !config.userID) {
    throw new Error('UUID not configured - Please save UUID first');
  }

  async function connectAndWrite(address, port, socks = false) {
    let tcpSocket;
    if (config.socks5Relay) {
      tcpSocket = await socks5Connect(addressType, address, port, log, config.parsedSocks5Address);
    } else {
      tcpSocket = socks
        ? await socks5Connect(addressType, address, port, log, config.parsedSocks5Address)
        : connect({ hostname: address, port: port });
    }
    remoteSocket.value = tcpSocket;
    log(`connected to ${address}:${port}`);
    const writer = tcpSocket.writable.getWriter();
    await writer.write(rawClientData);
    writer.releaseLock();
    return tcpSocket;
  }

  // اگر SOCKS5 فعال باشد، رفتار قبلی حفظ می‌شود
  if (config.enableSocks || config.socks5Relay) {
    async function retry() {
      const tcpSocket = config.enableSocks
        ? await connectAndWrite(addressRemote, portRemote, true)
        : await connectAndWrite(
          config.proxyIP || addressRemote,
          config.proxyPort || portRemote,
          false,
        );

      tcpSocket.closed
        .catch(error => {
          console.log('retry tcpSocket closed error', error);
        })
        .finally(() => {
          safeCloseWebSocket(webSocket);
        });
      RemoteSocketToWS(tcpSocket, webSocket, protocolResponseHeader, null, log);
    }

    const tcpSocket = await connectAndWrite(addressRemote, portRemote);
    RemoteSocketToWS(tcpSocket, webSocket, protocolResponseHeader, retry, log);
    return;
  }

  // ✅ pool + NAT64
  const pool = config.proxyPool && config.proxyPool.length > 0
    ? config.proxyPool
    : (config.proxyIP ? [`${config.proxyIP}:${config.proxyPort || 443}`] : []);

  async function tryPool(index) {
    if (index >= pool.length) {
      return tryNAT64();
    }
    try {
      const [proxyHost, proxyPortRaw = '443'] = String(pool[index]).split(':');
      const proxyPort = Number(proxyPortRaw) || 443;

      const tcpSocket = await connectAndWrite(proxyHost, proxyPort);
      tcpSocket.closed
        .catch(error => {
          console.log('proxy tcpSocket closed error', error);
        })
        .finally(() => {
          safeCloseWebSocket(webSocket);
        });
      RemoteSocketToWS(tcpSocket, webSocket, protocolResponseHeader, () => tryPool(index + 1), log);
    } catch (err) {
      console.log(`Proxy ${index} (${pool[index]}) failed:`, err.message);
      return tryPool(index + 1);
    }
  }

  async function tryNAT64() {
    try {
      const ipv4 = await resolveIPv4(addressRemote);
      const nat64Address = toNAT64Address(ipv4);
      if (!nat64Address) {
        console.log(`NAT64 fallback failed: could not resolve ${addressRemote}`);
        safeCloseWebSocket(webSocket);
        return;
      }
      console.log(`Falling back to NAT64: ${nat64Address}`);
      const tcpSocket = await connectAndWrite(nat64Address, portRemote);
      tcpSocket.closed
        .catch(error => {
          console.log('NAT64 tcpSocket closed error', error);
        })
        .finally(() => {
          safeCloseWebSocket(webSocket);
        });
      RemoteSocketToWS(tcpSocket, webSocket, protocolResponseHeader, null, log);
    } catch (err) {
      console.log(`NAT64 fallback error:`, err.message);
      safeCloseWebSocket(webSocket);
    }
  }

  try {
    const tcpSocket = await connectAndWrite(addressRemote, portRemote);
    RemoteSocketToWS(tcpSocket, webSocket, protocolResponseHeader, () => tryPool(0), log);
  } catch (err) {
    console.log(`Direct connection to ${addressRemote}:${portRemote} failed, trying pool...`);
    await tryPool(0);
  }
}

function MakeReadableWebSocketStream(webSocketServer, earlyDataHeader, log) {
  return new ReadableStream({
    start(controller) {
      webSocketServer.addEventListener('message', (/** @type {{ data: any; }} */ event) => controller.enqueue(event.data));
      webSocketServer.addEventListener('close', () => {
        safeCloseWebSocket(webSocketServer);
        controller.close();
      });
      webSocketServer.addEventListener('error', (/** @type {any} */ err) => {
        log('webSocketServer has error');
        controller.error(err);
      });
      const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
      if (error) controller.error(error);
      else if (earlyData) controller.enqueue(earlyData);
    },
    pull(_controller) { },
    cancel(reason) {
      log(`ReadableStream was canceled, due to ${reason}`);
      safeCloseWebSocket(webSocketServer);
    },
  });
}

function ProcessProtocolHeader(protocolBuffer, userID) {
  if (protocolBuffer.byteLength < 24) return { hasError: true, message: 'invalid data' };

  const dataView = new DataView(protocolBuffer);
  const version = dataView.getUint8(0);
  const slicedBufferString = stringify(new Uint8Array(protocolBuffer.slice(1, 17)));
  const uuids = userID.split(',').map((/** @type {string} */ id) => id.trim());
  const isValidUser = uuids.some((/** @type {string} */ uuid) => slicedBufferString === uuid);

  if (!isValidUser) return { hasError: true, message: 'invalid user' };

  const optLength = dataView.getUint8(17);
  const command = dataView.getUint8(18 + optLength);
  if (command !== 1 && command !== 2)
    return { hasError: true, message: `command ${command} is not supported` };

  const portIndex = 18 + optLength + 1;
  const portRemote = dataView.getUint16(portIndex);
  const addressType = dataView.getUint8(portIndex + 2);
  let addressValue, addressLength, addressValueIndex;

  switch (addressType) {
    case 1:
      addressLength = 4;
      addressValueIndex = portIndex + 3;
      addressValue = new Uint8Array(
        protocolBuffer.slice(addressValueIndex, addressValueIndex + addressLength),
      ).join('.');
      break;
    case 2:
      addressLength = dataView.getUint8(portIndex + 3);
      addressValueIndex = portIndex + 4;
      addressValue = new TextDecoder().decode(
        protocolBuffer.slice(addressValueIndex, addressValueIndex + addressLength),
      );
      break;
    case 3:
      addressLength = 16;
      addressValueIndex = portIndex + 3;
      addressValue = Array.from({ length: 8 }, (_, i) =>
        dataView.getUint16(addressValueIndex + i * 2).toString(16),
      ).join(':');
      break;
    default:
      return { hasError: true, message: `invalid addressType: ${addressType}` };
  }

  if (!addressValue)
    return { hasError: true, message: `addressValue is empty, addressType is ${addressType}` };

  return {
    hasError: false,
    addressRemote: addressValue,
    addressType,
    portRemote,
    rawDataIndex: addressValueIndex + addressLength,
    ProtocolVersion: new Uint8Array([version]),
    isUDP: command === 2,
  };
}

async function RemoteSocketToWS(remoteSocket, webSocket, protocolResponseHeader, retry, log) {
  let hasIncomingData = false;
  try {
    await remoteSocket.readable.pipeTo(
      new WritableStream({
        async write(chunk) {
          if (webSocket.readyState !== CONST.WS_READY_STATE_OPEN)
            throw new Error('WebSocket is not open');
          hasIncomingData = true;
          const dataToSend = protocolResponseHeader
            ? await new Blob([protocolResponseHeader, chunk]).arrayBuffer()
            : chunk;
          webSocket.send(dataToSend);
          protocolResponseHeader = null;
        },
        close() {
          log(`Remote connection readable closed. Had incoming data: ${hasIncomingData}`);
        },
        abort(reason) {
          console.error(`Remote connection readable aborted:`, reason);
        },
      }),
    );
  } catch (error) {
    console.error(`RemoteSocketToWS error:`, error.stack || error);
    safeCloseWebSocket(webSocket);
  }
  if (!hasIncomingData && retry) {
    log(`No incoming data, retrying`);
    await retry();
  }
}

function base64ToArrayBuffer(base64Str) {
  if (!base64Str) return { earlyData: null, error: null };
  try {
    const binaryStr = atob(base64Str.replace(/-/g, '+').replace(/_/g, '/'));
    const buffer = new ArrayBuffer(binaryStr.length);
    const view = new Uint8Array(buffer);
    for (let i = 0; i < binaryStr.length; i++) {
      view[i] = binaryStr.charCodeAt(i);
    }
    return { earlyData: buffer, error: null };
  } catch (error) {
    return { earlyData: null, error };
  }
}

function safeCloseWebSocket(socket) {
  try {
    if (
      socket.readyState === CONST.WS_READY_STATE_OPEN ||
      socket.readyState === CONST.WS_READY_STATE_CLOSING
    ) {
      socket.close();
    }
  } catch (error) {
    console.error('safeCloseWebSocket error:', error);
  }
}

const byteToHex = Array.from({ length: 256 }, (_, i) => (i + 0x100).toString(16).slice(1));

function unsafeStringify(arr, offset = 0) {
  return (
    byteToHex[arr[offset]] +
    byteToHex[arr[offset + 1]] +
    byteToHex[arr[offset + 2]] +
    byteToHex[arr[offset + 3]] +
    '-' +
    byteToHex[arr[offset + 4]] +
    byteToHex[arr[offset + 5]] +
    '-' +
    byteToHex[arr[offset + 6]] +
    byteToHex[arr[offset + 7]] +
    '-' +
    byteToHex[arr[offset + 8]] +
    byteToHex[arr[offset + 9]] +
    '-' +
    byteToHex[arr[offset + 10]] +
    byteToHex[arr[offset + 11]] +
    byteToHex[arr[offset + 12]] +
    byteToHex[arr[offset + 13]] +
    byteToHex[arr[offset + 14]] +
    byteToHex[arr[offset + 15]]
  ).toLowerCase();
}

function stringify(arr, offset = 0) {
  const uuid = unsafeStringify(arr, offset);
  if (!isValidUUID(uuid)) throw new TypeError('Stringified UUID is invalid');
  return uuid;
}

async function createDnsPipeline(webSocket, vlessResponseHeader, log) {
  let isHeaderSent = false;
  const transformStream = new TransformStream({
    transform(chunk, controller) {
      for (let index = 0; index < chunk.byteLength;) {
        const lengthBuffer = chunk.slice(index, index + 2);
        const udpPacketLength = new DataView(lengthBuffer).getUint16(0);
        const udpData = new Uint8Array(chunk.slice(index + 2, index + 2 + udpPacketLength));
        index = index + 2 + udpPacketLength;
        controller.enqueue(udpData);
      }
    },
  });

  transformStream.readable
    .pipeTo(
      new WritableStream({
        async write(chunk) {
          try {
            const resp = await fetch(`https://1.1.1.1/dns-query`, {
              method: 'POST',
              headers: { 'content-type': 'application/dns-message' },
              body: chunk,
            });
            const dnsQueryResult = await resp.arrayBuffer();
            const udpSize = dnsQueryResult.byteLength;
            const udpSizeBuffer = new Uint8Array([(udpSize >> 8) & 0xff, udpSize & 0xff]);

            if (webSocket.readyState === CONST.WS_READY_STATE_OPEN) {
              log(`DNS query successful, length: ${udpSize}`);
              if (isHeaderSent) {
                webSocket.send(await new Blob([udpSizeBuffer, dnsQueryResult]).arrayBuffer());
              } else {
                webSocket.send(
                  await new Blob([
                    vlessResponseHeader,
                    udpSizeBuffer,
                    dnsQueryResult,
                  ]).arrayBuffer(),
                );
                isHeaderSent = true;
              }
            }
          } catch (error) {
            log('DNS query error: ' + error);
          }
        },
      }),
    )
    .catch(e => {
      log('DNS stream error: ' + e);
    });

  const writer = transformStream.writable.getWriter();
  return {
    write: (/** @type {any} */ chunk) => writer.write(chunk),
  };
}

async function socks5Connect(addressType, addressRemote, portRemote, log, parsedSocks5Addr) {
  const { username, password, hostname, port } = parsedSocks5Addr;
  const socket = connect({ hostname, port });
  const writer = socket.writable.getWriter();
  const reader = socket.readable.getReader();
  const encoder = new TextEncoder();

  await writer.write(new Uint8Array([5, 2, 0, 2]));
  let res = (await reader.read()).value;
  if (res[0] !== 0x05 || res[1] === 0xff) throw new Error('SOCKS5 server connection failed.');

  if (res[1] === 0x02) {
    if (!username || !password) throw new Error('SOCKS5 auth credentials not provided.');
    const authRequest = new Uint8Array([
      1,
      username.length,
      ...encoder.encode(username),
      password.length,
      ...encoder.encode(password),
    ]);
    await writer.write(authRequest);
    res = (await reader.read()).value;
    if (res[0] !== 0x01 || res[1] !== 0x00) throw new Error('SOCKS5 authentication failed.');
  }

  let DSTADDR;
  switch (addressType) {
    case 1:
      DSTADDR = new Uint8Array([1, ...addressRemote.split('.').map(Number)]);
      break;
    case 2:
      DSTADDR = new Uint8Array([3, addressRemote.length, ...encoder.encode(addressRemote)]);
      break;
    case 3:
      DSTADDR = new Uint8Array([
        4,
        ...addressRemote
          .split(':')
          .flatMap((/** @type {string} */ x) => [parseInt(x.slice(0, 2), 16), parseInt(x.slice(2), 16)]),
      ]);
      break;
    default:
      throw new Error(`Invalid addressType for SOCKS5: ${addressType}`);
  }

  const socksRequest = new Uint8Array([5, 1, 0, ...DSTADDR, portRemote >> 8, portRemote & 0xff]);
  await writer.write(socksRequest);
  res = (await reader.read()).value;
  if (res[1] !== 0x00) throw new Error('Failed to open SOCKS5 connection.');

  writer.releaseLock();
  reader.releaseLock();
  return socket;
}

function socks5AddressParser(address) {
  try {
    const [authPart, hostPart] = address.includes('@') ? address.split('@') : [null, address];
    const [hostname, portStr] = hostPart.split(':');
    const port = parseInt(portStr, 10);
    if (!hostname || isNaN(port)) throw new Error();

    let username, password;
    if (authPart) {
      [username, password] = authPart.split(':');
      if (!username) throw new Error();
    }
    return { username, password, hostname, port };
  } catch {
    throw new Error('Invalid SOCKS5 address format. Expected [user:pass@]host:port');
  }
}

function getPageCSS() {
  return `
      * {
        margin: 0;
        padding: 0;
        box-sizing: border-box;
      }
      @font-face {
	      font-family: "Aldine 401 BT Web";
	      src: url("https://pub-7a3b428c76aa411181a0f4dd7fa9064b.r2.dev/Aldine401_Mersedeh.woff2") format("woff2");
	      font-weight: 400; font-style: normal; font-display: swap;
	    }
	    @font-face {
	      font-family: "Styrene B LC";
	      src: url("https://pub-7a3b428c76aa411181a0f4dd7fa9064b.r2.dev/StyreneBLC-Regular.woff2") format("woff2");
	      font-weight: 400; font-style: normal; font-display: swap;
	    }
	    @font-face {
	      font-family: "Styrene B LC";
	      src: url("https://pub-7a3b428c76aa411181a0f4dd7fa9064b.r2.dev/StyreneBLC-Medium.woff2") format("woff2");
	      font-weight: 500; font-style: normal; font-display: swap;
	    }
      :root {
        --background-primary: #2a2421; --background-secondary: #35302c; --background-tertiary: #413b35;
        --border-color: #5a4f45; --border-color-hover: #766a5f; --text-primary: #e5dfd6; --text-secondary: #b3a89d;
        --text-accent: #ffffff; --accent-primary: #be9b7b; --accent-secondary: #f5f5f5; --accent-tertiary: #8d6e5c;
        --accent-primary-darker: #8a6f56; --button-text-primary: #2a2421; --button-text-secondary: var(--text-primary);
        --shadow-color: rgba(0, 0, 0, 0.35); --shadow-color-accent: rgba(190, 155, 123, 0.4);
        --border-radius: 8px; --transition-speed: 0.2s; --transition-speed-fast: 0.1s; --transition-speed-medium: 0.3s; --transition-speed-long: 0.6s;
        --status-success: #70b570; --status-error: #e05d44; --status-warning: #e0bc44; --status-info: #4f90c4;
        --serif: "Aldine 401 BT Web", "Times New Roman", Times, Georgia, ui-serif, serif;
	      --sans-serif: "Styrene B LC", -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, Arial, "Noto Color Emoji", sans-serif;
	      --mono-serif: "Fira Code", Cantarell, "Courier Prime", monospace;
	    }
      body {
        font-family: var(--sans-serif); font-size: 16px; font-weight: 400; font-style: normal;
        background-color: var(--background-primary); color: var(--text-primary);
        padding: 3rem; line-height: 1.5; -webkit-font-smoothing: antialiased; -moz-osx-font-smoothing: grayscale;
      }
      .container {
        max-width: 800px; margin: 20px auto; padding: 0 12px; border-radius: var(--border-radius);
        box-shadow: 0 6px 15px rgba(0, 0, 0, 0.2), 0 0 25px 8px var(--shadow-color-accent);
        transition: box-shadow var(--transition-speed-medium) ease;
      }
      .container:hover { box-shadow: 0 8px 20px rgba(0, 0, 0, 0.25), 0 0 35px 10px var(--shadow-color-accent); }
      .header { text-align: center; margin-bottom: 40px; padding-top: 30px; }
      .header h1 { font-family: var(--serif); font-weight: 400; font-size: 1.8rem; color: var(--text-accent); margin-top: 0px; margin-bottom: 2px; }
      .header p { color: var(--text-secondary); font-size: 0.6rem; font-weight: 400; }
      .config-card {
        background: var(--background-secondary); border-radius: var(--border-radius); padding: 20px; margin-bottom: 24px;
        border: 1px solid var(--border-color);
        transition: border-color var(--transition-speed) ease, box-shadow var(--transition-speed) ease;
      }
      .config-card:hover { border-color: var(--border-color-hover); box-shadow: 0 4px 8px var(--shadow-color); }
      .config-title {
        font-family: var(--serif); font-size: 1.6rem; font-weight: 400; color: var(--accent-secondary);
        margin-bottom: 16px; padding-bottom: 13px; border-bottom: 1px solid var(--border-color);
        display: flex; align-items: center; justify-content: space-between;
      }
      .config-title .refresh-btn {
        position: relative; overflow: hidden; display: flex; align-items: center; gap: 4px;
        font-family: var(--serif); font-size: 12px; padding: 6px 12px; border-radius: 6px;
        color: var(--accent-secondary); background-color: var(--background-tertiary); border: 1px solid var(--border-color);
        cursor: pointer;
        transition: background-color var(--transition-speed) ease, border-color var(--transition-speed) ease, color var(--transition-speed) ease, transform var(--transition-speed) ease, box-shadow var(--transition-speed) ease;
      }
      .config-title .refresh-btn::before {
        content: ''; position: absolute; top: 0; left: 0; width: 100%; height: 100%;
        background: linear-gradient(120deg, transparent, rgba(255, 255, 255, 0.2), transparent);
        transform: translateX(-100%); transition: transform var(--transition-speed-long) ease; z-index: 1;
      }
      .config-title .refresh-btn:hover {
        letter-spacing: 0.5px; font-weight: 600; background-color: #4d453e; color: var(--accent-primary);
        border-color: var(--border-color-hover); transform: translateY(-2px); box-shadow: 0 4px 8px var(--shadow-color);
      }
      .config-title .refresh-btn:hover::before { transform: translateX(100%); }
      .config-title .refresh-btn:active { transform: translateY(0px) scale(0.98); box-shadow: none; }
      .refresh-icon { width: 12px; height: 12px; stroke: currentColor; }
      .config-content {
        position: relative; background: var(--background-tertiary); border-radius: var(--border-radius);
        padding: 16px; margin-bottom: 20px; border: 1px solid var(--border-color);
      }
      .config-content pre {
        overflow-x: auto; font-family: var(--mono-serif); font-size: 7px; color: var(--text-primary);
        margin: 0; white-space: pre-wrap; word-break: break-all;
      }
      .button {
        display: inline-flex; align-items: center; justify-content: center; gap: 8px;
        padding: 8px 16px; border-radius: var(--border-radius); font-size: 15px; font-weight: 500;
        cursor: pointer; border: 1px solid var(--border-color); background-color: var(--background-tertiary);
        color: var(--button-text-secondary);
        transition: background-color var(--transition-speed) ease, border-color var(--transition-speed) ease, color var(--transition-speed) ease, transform var(--transition-speed) ease, box-shadow var(--transition-speed) ease;
        -webkit-tap-highlight-color: transparent; touch-action: manipulation; text-decoration: none; overflow: hidden; z-index: 1;
      }
      .button:focus-visible { outline: 2px solid var(--accent-primary); outline-offset: 2px; }
      .button:disabled { opacity: 0.6; cursor: not-allowed; transform: none; box-shadow: none; transition: opacity var(--transition-speed) ease; }
      .copy-buttons {
        position: relative; display: flex; gap: 4px; overflow: hidden; align-self: center;
        font-family: var(--serif); font-size: 13px; padding: 6px 12px; border-radius: 6px;
        color: var(--accent-secondary); border: 1px solid var(--border-color);
        transition: background-color var(--transition-speed) ease, border-color var(--transition-speed) ease, color var(--transition-speed) ease, transform var(--transition-speed) ease, box-shadow var(--transition-speed) ease;
      }
      .copy-buttons::before, .client-btn::before {
        content: ''; position: absolute; top: 0; left: 0; width: 100%; height: 100%;
        background: linear-gradient(120deg, transparent, rgba(255, 255, 255, 0.2), transparent);
        transform: translateX(-100%); transition: transform var(--transition-speed-long) ease; z-index: -1;
      }
      .copy-buttons:hover::before, .client-btn:hover::before { transform: translateX(100%); }
      .copy-buttons:hover {
        background-color: #4d453e; letter-spacing: 0.5px; font-weight: 600;
        border-color: var(--border-color-hover); transform: translateY(-2px); box-shadow: 0 4px 8px var(--shadow-color);
      }
      .copy-buttons:active { transform: translateY(0px) scale(0.98); box-shadow: none; }
      .copy-icon { width: 12px; height: 12px; stroke: currentColor; }
      .client-buttons { display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 12px; margin-top: 16px; }
      .client-btn {
        width: 100%; background-color: var(--accent-primary); color: var(--background-tertiary);
        border-radius: 6px; border-color: var(--accent-primary-darker); position: relative; overflow: hidden;
        transition: all 0.3s cubic-bezier(0.2, 0.8, 0.2, 1); box-shadow: 0 2px 5px rgba(0, 0, 0, 0.15);
      }
      .client-btn::after {
        content: ''; position: absolute; bottom: -5px; left: 0; width: 100%; height: 5px;
        background: linear-gradient(90deg, var(--accent-tertiary), var(--accent-secondary));
        opacity: 0; transition: all 0.3s ease; z-index: 0;
      }
      .client-btn:hover {
        text-transform: uppercase; letter-spacing: 0.3px; transform: translateY(-3px);
        background-color: var(--accent-secondary); color: var(--button-text-primary);
        box-shadow: 0 5px 15px rgba(190, 155, 123, 0.5); border-color: var(--accent-secondary);
      }
      .client-btn:hover::after { opacity: 1; bottom: 0; }
      .client-btn:active { transform: translateY(0) scale(0.98); box-shadow: 0 2px 3px rgba(0, 0, 0, 0.2); background-color: var(--accent-primary-darker); }
      .client-btn .client-icon { position: relative; z-index: 2; transition: transform 0.3s ease; }
      .client-btn:hover .client-icon { transform: rotate(15deg) scale(1.1); }
      .client-btn .button-text { position: relative; z-index: 2; transition: letter-spacing 0.3s ease; }
      .client-btn:hover .button-text { letter-spacing: 0.5px; }
	    .client-icon { width: 18px; height: 18px; border-radius: 6px; background-color: var(--background-secondary); display: flex; align-items: center; justify-content: center; flex-shrink: 0; }
	    .client-icon svg { width: 14px; height: 14px; fill: var(--accent-secondary); }
	    .button.copied { background-color: var(--accent-secondary) !important; color: var(--background-tertiary) !important; }
	    .button.error { background-color: #c74a3b !important; color: var(--text-accent) !important; }
	    .footer { text-align: center; margin-top: 20px; padding-bottom: 1px; color: var(--text-secondary); font-size: 8px; }
	    .footer p { margin-bottom: 0px; }
	    ::-webkit-scrollbar { width: 8px; height: 8px; }
	    ::-webkit-scrollbar-track { background: var(--background-primary); border-radius: 4px; }
	    ::-webkit-scrollbar-thumb { background: var(--border-color); border-radius: 4px; border: 2px solid var(--background-primary); }
	    ::-webkit-scrollbar-thumb:hover { background: var(--border-color-hover); }
	    * { scrollbar-width: thin; scrollbar-color: var(--border-color) var(--background-primary); }
	    .ip-info-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(230px, 1fr)); gap: 24px; }
	    .ip-info-section { background-color: var(--background-tertiary); border-radius: var(--border-radius); padding: 16px; border: 1px solid var(--border-color); display: flex; flex-direction: column; gap: 20px; }
	    .ip-info-header { display: flex; align-items: center; gap: 10px; border-bottom: 1px solid var(--border-color); padding-bottom: 10px; }
	    .ip-info-header svg { width: 20px; height: 20px; stroke: var(--accent-secondary); }
	    .ip-info-header h3 { font-family: var(--serif); font-size: 18px; font-weight: 400; color: var(--accent-secondary); margin: 0; }
	    .ip-info-content { display: flex; flex-direction: column; gap: 10px; }
	    .ip-info-item { display: flex; flex-direction: column; gap: 2px; }
	    .ip-info-item .label { font-size: 11px; color: var(--text-secondary); text-transform: uppercase; letter-spacing: 0.5px; }
	    .ip-info-item .value { font-size: 14px; color: var(--text-primary); word-break: break-all; line-height: 1.4; }
	    .badge { display: inline-flex; align-items: center; justify-content: center; padding: 3px 8px; border-radius: 12px; font-size: 11px; font-weight: 500; text-transform: uppercase; letter-spacing: 0.5px; }
	    .badge-yes { background-color: rgba(112, 181, 112, 0.15); color: var(--status-success); border: 1px solid rgba(112, 181, 112, 0.3); }
	    .badge-no { background-color: rgba(224, 93, 68, 0.15); color: var(--status-error); border: 1px solid rgba(224, 93, 68, 0.3); }
	    .badge-neutral { background-color: rgba(79, 144, 196, 0.15); color: var(--status-info); border: 1px solid rgba(79, 144, 196, 0.3); }
	    .badge-warning { background-color: rgba(224, 188, 68, 0.15); color: var(--status-warning); border: 1px solid rgba(224, 188, 68, 0.3); }
	    .skeleton { display: block; background: linear-gradient(90deg, var(--background-tertiary) 25%, var(--background-secondary) 50%, var(--background-tertiary) 75%); background-size: 200% 100%; animation: loading 1.5s infinite; border-radius: 4px; height: 16px; }
	    @keyframes loading { 0% { background-position: 200% 0; } 100% { background-position: -200% 0; } }
	    .country-flag { display: inline-block; width: 18px; height: auto; max-height: 14px; margin-right: 6px; vertical-align: middle; border-radius: 2px; }
	    @media (max-width: 768px) {
	      body { padding: 20px; } .container { padding: 0 14px; width: min(100%, 768px); }
	      .ip-info-grid { grid-template-columns: repeat(auto-fit, minmax(170px, 1fr)); gap: 18px; }
	      .header h1 { font-size: 1.8rem; } .header p { font-size: 0.7rem }
	      .ip-info-section { padding: 14px; gap: 18px; } .ip-info-header h3 { font-size: 16px; }
	      .ip-info-header { gap: 8px; } .ip-info-content { gap: 8px; }
	      .ip-info-item .label { font-size: 11px; } .ip-info-item .value { font-size: 13px; }
	      .config-card { padding: 16px; } .config-title { font-size: 18px; }
	      .config-title .refresh-btn { font-size: 11px; } .config-content pre { font-size: 12px; }
	      .client-buttons { grid-template-columns: repeat(auto-fill, minmax(260px, 1fr)); }
	      .button { font-size: 12px; } .copy-buttons { font-size: 11px; width: 100%; }
	    }
	    @media (max-width: 480px) {
	      body { padding: 0px; } .container { padding: 0 7px; width: min(100%, 390px); }
	      .header h1 { font-size: 20px; } .header p { font-size: 8px; }
	      .ip-info-section { padding: 14px; gap: 16px; }
	      .ip-info-grid { grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; }
	      .ip-info-header h3 { font-size: 14px; } .ip-info-header { gap: 6px; }
	      .ip-info-content { gap: 6px; } .ip-info-header svg { width: 18px; height: 18px; }
	      .ip-info-item .label { font-size: 9px; } .ip-info-item .value { font-size: 11px; }
	      .badge { padding: 2px 6px; font-size: 10px; border-radius: 10px; }
	      .config-card { padding: 10px; } .config-title { font-size: 16px; }
	      .config-title .refresh-btn { font-size: 10px; } .config-content { padding: 5px; }
	      .config-content pre { font-size: 10px; }
	      .client-buttons { grid-template-columns: repeat(auto-fill, minmax(200px, 1fr)); }
	      .button { padding: 4px 8px; font-size: 13px; } .copy-buttons { font-size: 15px; }
	      .footer { font-size: 10px; }
	    }
	    @media (max-width: 359px) {
          body { padding: 12px; font-size: 14px; } .container { max-width: 100%; padding: 8px; }
          .header h1 { font-size: 16px; } .header p { font-size: 6px; }
          .ip-info-section { padding: 12px; gap: 12px; }
          .ip-info-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 10px; }
          .ip-info-header h3 { font-size: 13px; } .ip-info-header { gap: 4px; } .ip-info-content { gap: 4px; }
          .ip-info-header svg { width: 16px; height: 16px; } .ip-info-item .label { font-size: 8px; }
		  .ip-info-item .value { font-size: 10px; } .badge { padding: 1px 4px; font-size: 9px; border-radius: 8px; }
          .config-card { padding: 8px; } .config-title { font-size: 13px; } .config-title .refresh-btn { font-size: 9px; }
          .config-content { padding: 8px; } .config-content pre { font-size: 8px; }
		  .client-buttons { grid-template-columns: repeat(auto-fill, minmax(150px, 1fr)); }
          .button { padding: 3px 6px; font-size: 10px; } .copy-buttons { font-size: 9px; } .footer { font-size: 7px; }
        }

.qr-modal {
    position: fixed;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    background: rgba(42, 36, 33, 0.95);
    display: none;
    justify-content: center;
    align-items: center;
    z-index: 10000;
    backdrop-filter: blur(5px);
}

.qr-container {
    background: var(--background-secondary);
    padding: 25px;
    border-radius: 12px;
    text-align: center;
    border: 2px solid var(--accent-primary);
    box-shadow: 0 10px 30px rgba(0,0,0,0.3);
}

.qr-title {
    color: var(--accent-secondary);
    margin-bottom: 20px;
    font-family: var(--serif);
    font-size: 1.4rem;
}
 
        @media (min-width: 360px) { .container { max-width: 100%; } }
        @media (min-width: 480px) { .container { max-width: 90%; } }
        @media (min-width: 640px) { .container { max-width: 600px; } }
        @media (min-width: 768px) { .container { max-width: 720px; } }
        @media (min-width: 1024px) { .container { max-width: 800px; } }
  
        .subscription-section { display: flex; flex-direction: column; gap: 16px; }
        .subscription-item { display: flex; flex-direction: column; gap: 8px; }
        .subscription-item label { font-size: 14px; color: var(--text-secondary); font-weight: 500; }
        .input-group { display: flex; gap: 8px; align-items: center; }
        .input-group input { 
        flex: 1; padding: 8px 12px; border-radius: var(--border-radius); 
        border: 1px solid var(--border-color); background: var(--background-tertiary); 
        color: var(--text-primary); font-family: var(--mono-serif); font-size: 12px;
        }
        .input-group input:focus { outline: none; border-color: var(--accent-primary); }
        #qrcode { display: inline-block; padding: 10px; background: white; border-radius: 8px; }
        #qrcode-container { animation: fadeIn 0.3s ease; }
        @keyframes fadeIn { from { opacity: 0; } to { opacity: 1; } }

        @media (max-width: 768px) {
        .input-group { flex-direction: column; align-items: stretch; }
        .input-group input { margin-bottom: 8px; }
          }
        `;
       }

function getPageHTML(subDefaultUrl, userConfig) {
  return `
    <div class="container">
      <div class="header">
      <h1>🌟 STAR 🌟</h1>
        <h1>VLESS Proxy Configuration</h1>
      </div>

      <div class="config-card">
        <div class="config-title">
          <span>UUID Management</span>
        </div>
        <div class="config-content">
          <div class="form-group">
            <label for="uuid-input" style="display: block; margin-bottom: 8px; color: var(--text-secondary); font-weight: 500;">🔑 UUID</label>
            <div style="display: flex;gap: 10px;align-items: center;margin-bottom: 15px;">
              <input type="text" id="uuid-input" class="form-input" value="${userConfig.userID || ''}" placeholder="Enter UUID" style="flex: 1; padding: 12px; border: 1px solid var(--border-color); border-radius: 5px; background: var(--background-tertiary); color: var(--text-primary);">
              <button type="button" onclick="generateRandomUUID()" class="button copy-buttons" style="white-space: nowrap; padding: 8px 5px; font-size: 16px !important; width: 94px;">
                🎲 Generate
              </button>
            </div>
          </div>
        </div>
      </div>
      <div style="margin-top: 20px; display: flex; gap: 10px;">
        <button class="button copy-buttons" onclick="saveConfig()" style="flex: 1;padding: 15px;font-size: 16px;font-weight: 500;font-size: 17px !important;margin-bottom: 20px;">
            💾 Save Configuration
        </button>
      </div>

      ${userConfig.userID ? `
      <div class="config-card">
        <div class="config-title">
          <span>Subscription Links</span>
        </div>
        <div class="subscription-section">
          <div class="subscription-item">
            <label>Default Config:</label>
            <div class="input-group">
              <input type="text" id="default-sub-link" readonly value="${subDefaultUrl}">
              <button class="button copy-buttons" style="font-size: 15px;" onclick="copySubscriptionLink('default-sub')">
                <svg class="copy-icon" xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                  <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
                  <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
                </svg>
                Copy
              </button>
                <button class="button copy-buttons" onclick="generateQRCode('default-sub')">
                    📱 QR Code
                </button>
            </div>
          </div>
        </div>
      </div>
      ` : '<div class="config-card"><div class="config-content" style="text-align: center; padding: 40px;"><p>⚠️ Please set and save UUID first to see configurations</p></div></div>'}

      <div class="config-card">
        <div class="config-title">
          <span>Change Password</span>
        </div>
        <div class="config-content">
          <form id="changePasswordForm">
            <div class="form-group">
              <label for="current-password" style="display: block; margin-bottom: 8px; color: var(--text-secondary); font-weight: 500; margin-top: 20px;">Current Password</label>
              <div style="position: relative;">
                <input type="password" id="current-password" class="form-input" required style="width: 100%;padding: 12px;padding-right: 50px;border-radius: 8px;background: #93805470;border: 1px;color: #ffd5a9;font-size: 16px;">
                <button type="button" onclick="togglePassword('current-password')" style="position: absolute; right: 10px; top: 50%; transform: translateY(-50%); background: none; border: none; cursor: pointer; font-size: 17px;">🙈</button>
              </div>
            </div>
            
            <div class="form-group">
              <label for="new-password" style="display: block; margin-bottom: 8px; color: var(--text-secondary); font-weight: 500; margin-top: 20px;">New Password</label>
              <div style="position: relative;">
                <input type="password" id="new-password" class="form-input" required style="width: 100%;padding: 12px;padding-right: 50px;border-radius: 8px;background: #93805470;border: 1px;color: #ffd5a9;font-size: 16px;">
                <button type="button" onclick="togglePassword('new-password')" style="position: absolute; right: 10px; top: 50%; transform: translateY(-50%); background: none; border: none; cursor: pointer; font-size: 17px;">🙈</button>
              </div>
            </div>
            
            <div class="form-group">
              <label for="confirm-password" style="display: block; margin-bottom: 8px; color: var(--text-secondary); font-weight: 500; margin-top: 20px;">Confirm New Password</label>
              <div style="position: relative;">
                <input type="password" id="confirm-password" class="form-input" required style="width: 100%;padding: 12px;padding-right: 50px;border-radius: 8px;background: #93805470;border: 1px;color: #ffd5a9;font-size: 16px;">
                <button type="button" onclick="togglePassword('confirm-password')" style="position: absolute; right: 10px; top: 50%; transform: translateY(-50%); background: none; border: none; cursor: pointer; font-size: 17px;">🙈</button>
              </div>
            </div>
            
            <button type="button" class="button copy-buttons" onclick="changePassword()" style="width: 100%;padding: 12px;margin-top: 10px;font-size: 20px !important;">
              🔐 Change Password
            </button>
            <div id="password-change-message" style="margin-top: 15px;"></div>
          </form>
        </div>
      </div>

      <div class="config-card">
        <div class="config-title">
          <span>🧩 Fragment Settings</span>
        </div>
        <div class="config-content">
          <label for="fragment-input" style="display: block; margin-bottom: 8px; color: var(--text-secondary); font-weight: 500; margin-top: 20px;">Fragment (JSON)</label>
          <textarea id="fragment-input" spellcheck="false" style="width: 100%; min-height: 240px; font-family: monospace; direction: ltr; text-align: left; resize: vertical; padding: 12px; border-radius: 8px; background: #93805470; border: 1px solid var(--border-color); color: #ffd5a9; font-size: 12px;"></textarea>
          <small style="color: var(--text-secondary); display: block; margin-top: 8px; font-size: 12px;">
            All subscription configs use this fragment. Changes apply on the next subscription update.
          </small>
          <div style="display: flex; gap: 10px; margin-top: 15px;">
            <button type="button" class="button copy-buttons" onclick="saveFragment()" style="flex: 1; padding: 12px; font-size: 16px;">💾 Save Fragment</button>
            <button type="button" class="button copy-buttons" onclick="resetFragment()" style="flex: 1; padding: 12px; font-size: 16px;">↩️ Reset Default</button>
          </div>
        </div>
      </div>

      <div class="footer">
      </div>
    </div>
  `;
}

function getPageScript() {
  return `
      function copyToClipboard(button, text) {
        const originalHTML = button.innerHTML;
        navigator.clipboard.writeText(text).then(() => {
          button.innerHTML = '<svg class="copy-icon" xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg> Copied!';
          button.classList.add("copied");
          button.disabled = true;
          setTimeout(() => {
            button.innerHTML = originalHTML;
            button.classList.remove("copied");
            button.disabled = false;
          }, 1200);
        }).catch(err => {
          console.error("Failed to copy text: ", err);
        });
      }

      function generateRandomUUID() {
        const uuid = 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
          const r = Math.random() * 16 | 0;
          const v = c == 'x' ? r : (r & 0x3 | 0x8);
          return v.toString(16);
        });
        
        document.getElementById('uuid-input').value = uuid;
        showMessage('UUID generated successfully!');
      }

async function saveConfig() {
    const uuid = document.getElementById('uuid-input').value.trim();
    
    if (!uuid) {
        showMessage('Please enter a UUID', 'error');
        return;
    }

    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    if (!uuidRegex.test(uuid)) {
        showMessage('Invalid UUID format', 'error');
        return;
    }

    try {
        const response = await fetch('/save-config', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify({ 
                userID: uuid 
            })
        });
        
        const result = await response.json();
        if (result.success) {
            showMessage('✅ saved successfully! Page will reload...');
            setTimeout(() => {
                window.location.reload();
            }, 1500);
        } else {
            showMessage('Failed to save: ' + result.error, 'error');
        }
    } catch (error) {
        showMessage('Error saving: ' + error.message, 'error');
    }
}

      function showMessage(message, type = 'success') {
        const messageDiv = document.createElement('div');
        messageDiv.style.cssText = 'position: fixed; top: 20px; right: 20px; background: ' + (type === 'success' ? '#d4b595' : '#e53e3e') + '; color: var(--background-tertiary); padding: 12px 20px; border-radius: 8px; font-weight: 600; z-index: 1000; box-shadow: 0 4px 12px rgba(0,0,0,0.15); animation: slideIn 0.3s ease;';
        
        messageDiv.textContent = message;
        document.body.appendChild(messageDiv);
        
        setTimeout(() => {
          if (messageDiv.parentNode) {
            messageDiv.parentNode.removeChild(messageDiv);
          }
        }, 3000);
      }

      const style = document.createElement('style');
      style.textContent = '@keyframes slideIn { from { transform: translateX(100%); opacity: 0; } to { transform: translateX(0); opacity: 1; } } @keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }';
      document.head.appendChild(style);

      function copySubscriptionLink(type) {
        let input;
      if (type === 'default-sub') {
    input = document.getElementById('default-sub-link');
        } else if (type === 'custom-sub') {
          input = document.getElementById('custom-sub-link');
        }
        
        const button = event.currentTarget;
        
        navigator.clipboard.writeText(input.value).then(() => {
          const originalHTML = button.innerHTML;
          button.innerHTML = 'Copied';
          button.classList.add('copied');
          setTimeout(() => {
            button.innerHTML = originalHTML;
            button.classList.remove('copied');
          }, 2000);
        }).catch(err => {
          console.error('Failed to copy: ', err);
          button.innerHTML = 'Error';
          button.classList.add('error');
          setTimeout(() => {
            button.innerHTML = originalHTML;
            button.classList.remove('error');
          }, 2000);
        });
      }

function generateQRCode(type) {
    let elementId;
    let modalTitle;
    
    if (type === 'default-sub') {
        elementId = 'default-sub-link';
        modalTitle = 'Default Sub QR Code';
    } else if (type === 'custom-sub') {
        elementId = 'custom-sub-link';
        modalTitle = 'Custom Sub QR Code';
    } else {
        showMessage('❌ Invalid QR code type', 'error');
        return;
    }
    
    const url = document.getElementById(elementId).value;
    if (!url) {
        showMessage('❌ No URL to generate QR code', 'error');
        return;
    }
    
    const qrModal = document.getElementById('qrModal');
    const qrcodeDiv = document.getElementById('qrcode');
    const qrTitle = document.querySelector('.qr-title');
    
    qrcodeDiv.innerHTML = '';
    
    qrTitle.textContent = modalTitle;
    
    new QRCode(qrcodeDiv, {
        text: url,
        width: 200,
        height: 200,
        colorDark: "#000000",
        colorLight: "#ffffff",
        correctLevel: QRCode.CorrectLevel.H
    });
    
    qrModal.style.display = 'flex';
    
    qrModal.onclick = function(e) {
        if (e.target === qrModal) {
            qrModal.style.display = 'none';
            qrcodeDiv.innerHTML = '';
        }
    };
}

function closeQR() {
    const qrModal = document.getElementById('qrModal');
    const qrcodeDiv = document.getElementById('qrcode');
    qrModal.style.display = 'none';
    qrcodeDiv.innerHTML = '';
}

      window.togglePassword = function(inputId) {
          const input = document.getElementById(inputId);
          const button = input.parentNode.querySelector('button');
          
          if (input.type === 'password') {
              input.type = 'text';
              button.textContent = '🙉';
          } else {
              input.type = 'password';
              button.textContent = '🙈';
          }
      }

      window.changePassword = async function() {
          const currentPassword = document.getElementById('current-password').value;
          const newPassword = document.getElementById('new-password').value;
          const confirmPassword = document.getElementById('confirm-password').value;
          const messageDiv = document.getElementById('password-change-message');

          messageDiv.style.display = 'none';
          messageDiv.innerHTML = '';

          if (!currentPassword || !newPassword || !confirmPassword) {
              showPasswordMessage('Please fill all fields', 'error');
              return false;
          }

          if (newPassword !== confirmPassword) {
              showPasswordMessage('New passwords do not match', 'error');
              return false;
          }

          if (newPassword.length < 4) {
              showPasswordMessage('Password must be at least 4 characters', 'error');
              return false;
          }

          try {
              const response = await fetch('/change-password', {
                  method: 'POST',
                  headers: {
                      'Content-Type': 'application/json',
                  },
                  body: JSON.stringify({
                      currentPassword: currentPassword,
                      newPassword: newPassword
                  })
              });

              const result = await response.json();

              if (response.ok) {
                  showPasswordMessage('Password changed successfully!', 'success');
                  document.getElementById('changePasswordForm').reset();
              } else {
                  showPasswordMessage(result.error || 'Error changing password', 'error');
              }
          } catch (error) {
              showPasswordMessage('Network error: ' + error.message, 'error');
          }

          return false;
      }

      function showPasswordMessage(message, type) {
          const messageDiv = document.getElementById('password-change-message');
          messageDiv.innerHTML = message;
          messageDiv.style.display = 'block';
          messageDiv.style.padding = '12px';
          messageDiv.style.borderRadius = '5px';
          messageDiv.style.marginTop = '10px';
          messageDiv.style.textAlign = 'center';
          messageDiv.style.fontWeight = '600';
          
          if (type === 'success') {
              messageDiv.style.background = 'var(--accent-secondary)';
              messageDiv.style.color = 'var(--background-tertiary)';
          } else {
              messageDiv.style.background = '#e53e3e';
              messageDiv.style.color = 'white';
          }
          
          setTimeout(() => {
              messageDiv.style.display = 'none';
          }, 3000);
      }
      
            async function loadFragment() {
          try {
              const response = await fetch('/fragment-config', { cache: 'no-store' });
              if (!response.ok) throw new Error('HTTP ' + response.status);
              const data = await response.json();
              document.getElementById('fragment-input').value = JSON.stringify(data.config, null, 2);
          } catch (error) {
              console.error('Failed to load fragment:', error);
          }
      }

      async function saveFragment() {
          const textarea = document.getElementById('fragment-input');
          let parsed;
          try {
              parsed = JSON.parse(textarea.value);
          } catch (error) {
              showMessage('❌ Invalid JSON', 'error');
              return;
          }
          try {
              const response = await fetch('/fragment-config', {
                  method: 'POST',
                  headers: { 'Content-Type': 'application/json' },
                  body: JSON.stringify({ config: parsed })
              });
              const data = await response.json();
              if (!response.ok) throw new Error(data.error || 'Save failed');
              textarea.value = JSON.stringify(data.config, null, 2);
              showMessage('✅ Fragment saved', 'success');
          } catch (error) {
              showMessage('❌ ' + error.message, 'error');
          }
      }

      async function resetFragment() {
          try {
              const response = await fetch('/fragment-config', { method: 'DELETE' });
              const data = await response.json();
              if (!response.ok) throw new Error(data.error || 'Reset failed');
              document.getElementById('fragment-input').value = JSON.stringify(data.config, null, 2);
              showMessage('✅ Fragment reset to default', 'success');
          } catch (error) {
              showMessage('❌ ' + error.message, 'error');
          }
      }

      document.addEventListener('DOMContentLoaded', function() {
          loadFragment();
      });

      document.addEventListener('DOMContentLoaded', function() {
      });
  `;
}