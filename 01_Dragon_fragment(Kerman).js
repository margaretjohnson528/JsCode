import { connect } from 'cloudflare:sockets';

const MAX_LOGIN_ATTEMPTS = 5;
const LOGIN_WINDOW_MS = 15 * 60 * 1000;
const SESSION_TTL_SECONDS = 7 * 24 * 60 * 60;
const CONFIG_CACHE_TTL_MS = 30 * 1000;
const FRAGMENT_KV_KEY = 'fragment_config';
const MAX_FRAGMENT_BYTES = 4096;
const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;

const CIPHER_SUITES = 'TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256';

const DEFAULT_FRAGMENT = {
    tcp: [
        { type: 'fragment', settings: { packets: 'tlshello', lengths: ['0', '104', '1'], delays: ['0'], maxSplit: '0' } },
        { type: 'fragment', settings: { packets: '1-1', lengths: ['114', '1'], delays: ['1'], maxSplit: '11' } },
    ],
};

function escapeHtml(value) {
    return String(value ?? '')
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function parseBool(value) {
    if (value === undefined || value === null) return false;
    return ['1', 'true', 'yes', 'on'].includes(String(value).trim().toLowerCase());
}

function safeEqual(a, b) {
    a = String(a);
    b = String(b);
    const len = Math.max(a.length, b.length);
    let diff = a.length ^ b.length;
    for (let i = 0; i < len; i++) {
        diff |= (a.charCodeAt(i) || 0) ^ (b.charCodeAt(i) || 0);
    }
    return diff === 0;
}

function randomToken() {
    const bytes = crypto.getRandomValues(new Uint8Array(32));
    return [...bytes].map((b) => b.toString(16).padStart(2, '0')).join('');
}

async function sha256Hex(text) {
    const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
    return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, '0')).join('');
}

async function hashPassword(password) {
    const salt = randomToken().slice(0, 32);
    return 'sha256$' + salt + '$' + (await sha256Hex(salt + ':' + password));
}

async function verifyPassword(stored, input) {
    if (!stored || typeof input !== 'string') return { ok: false, needsUpgrade: false };
    if (stored.startsWith('sha256$')) {
        const parts = stored.split('$');
        if (parts.length !== 3 || !parts[1] || !parts[2]) return { ok: false, needsUpgrade: false };
        const candidate = await sha256Hex(parts[1] + ':' + input);
        return { ok: safeEqual(candidate, parts[2]), needsUpgrade: false };
    }
    return { ok: safeEqual(stored, input), needsUpgrade: true };
}

function sessionCookie(token) {
    return `session_token=${token}; Path=/; HttpOnly; SameSite=Strict; Secure; Max-Age=${SESSION_TTL_SECONDS}`;
}

function redirectTo(location, extraHeaders) {
    const headers = new Headers(extraHeaders || {});
    headers.set('Location', location);
    return new Response(null, { status: 302, headers });
}

function toBase64(text) {
    const bytes = new TextEncoder().encode(text);
    let binary = '';
    for (let i = 0; i < bytes.length; i += 0x8000) {
        binary += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
    }
    return btoa(binary);
}

let configCache = { loadedAt: 0, hasPassword: false, uuid: '', trojan: '' };

function invalidateRuntimeConfig() {
    configCache.loadedAt = 0;
}

async function loadRuntimeConfig(env) {
    const now = Date.now();
    if (configCache.loadedAt && now - configCache.loadedAt < CONFIG_CACHE_TTL_MS) return configCache;
    const [password, uuid, trojan] = await Promise.all([
        env.Kerman.get('admin_password'),
        loadUUIDFromKV(env),
        loadTrojanPasswordFromKV(env),
    ]);
    const fresh = {
        loadedAt: password ? now : 0,
        hasPassword: !!password,
        uuid: String(uuid || '').toLowerCase(),
        trojan: trojan || '',
    };
    configCache = fresh;
    return fresh;
}

function validateFragment(config) {
    if (!config || typeof config !== 'object' || Array.isArray(config)) {
        return 'Fragment must be a JSON object';
    }
    if (!Array.isArray(config.tcp) || config.tcp.length === 0) {
        return 'Fragment must contain a non-empty "tcp" array';
    }
    if (config.tcp.length > 8) {
        return 'Too many fragment rules (max 8)';
    }
    for (const rule of config.tcp) {
        if (!rule || typeof rule !== 'object' || typeof rule.type !== 'string' ||
            !rule.settings || typeof rule.settings !== 'object' || Array.isArray(rule.settings)) {
            return 'Each rule needs a "type" and a "settings" object';
        }
    }
    return null;
}

async function getFragmentConfig(env) {
    try {
        const raw = await env.Kerman.get(FRAGMENT_KV_KEY);
        if (raw) {
            const parsed = JSON.parse(raw);
            if (!validateFragment(parsed)) return parsed;
        }
    } catch (error) {
        console.error('Error loading fragment config from KV:', error);
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
                try {
                    config = JSON.parse(config);
                } catch (e) {
                    return json({ error: 'Invalid JSON' }, 400);
                }
            }
            const problem = validateFragment(config);
            if (problem) return json({ error: problem }, 400);
            const serialized = JSON.stringify(config);
            if (serialized.length > MAX_FRAGMENT_BYTES) return json({ error: 'Fragment is too large' }, 400);
            await env.Kerman.put(FRAGMENT_KV_KEY, serialized);
            return json({ success: true, config });
        }

        if (request.method === 'DELETE') {
            await env.Kerman.delete(FRAGMENT_KV_KEY);
            return json({ success: true, config: DEFAULT_FRAGMENT });
        }

        return json({ error: 'Method not allowed' }, 405);
    } catch (error) {
        return json({ error: 'Server error: ' + error.message }, 500);
    }
}

function parseCdnItem(item) {
    let host;
    let port = 443;
    let nodeName = '';
    if (item.includes('#')) {
        const idx = item.indexOf('#');
        nodeName = item.slice(idx + 1);
        item = item.slice(0, idx);
    }
    if (item.startsWith('[') && item.includes(']:')) {
        const ipv6End = item.indexOf(']:');
        host = item.substring(0, ipv6End + 1);
        port = parseInt(item.substring(ipv6End + 2)) || 443;
    } else if (item.includes(':')) {
        const parts = item.split(':');
        host = parts[0];
        port = parseInt(parts[1]) || 443;
    } else {
        host = item;
    }
    return { host, port, nodeName };
}

function buildSubscriptionLinks({ domain, uuid, trojanSecret, includeTrojan, fragment }) {
    const fingerprints = ['chrome', 'firefox'];
    const vlsHeader = 'v' + 'l' + 'e' + 's' + 's';
    const troHeader = 't' + 'r' + 'o' + 'j' + 'a' + 'n';
    const fm = encodeURIComponent(JSON.stringify(fragment));
    const cs = encodeURIComponent(CIPHER_SUITES);
    const links = [];
    let fpCounter = 0;

    const build = (scheme, secret, useUuidParams) => {
        for (const cdnItem of cfip) {
            const { host, port, nodeName } = parseCdnItem(cdnItem);
            const isNonTls = nonTlsPorts.includes(port);
            const fp = fingerprints[fpCounter % fingerprints.length];
            fpCounter++;

            const baseName = nodeName.replace(/_Ntls$|_Tls$/, '');
            const portSuffix = isNonTls ? '_Ntls' : '_Tls';
            const name = encodeURIComponent(nodeName ? `${baseName}_${scheme}${portSuffix}` : `Workers_${scheme}`);
            const path = generateRandomPath();
            const auth = `${scheme}://${encodeURIComponent(secret)}@${host}:${port}`;
            const enc = useUuidParams ? 'encryption=none&' : '';

            if (isNonTls) {
                links.push(`${auth}?${enc}security=none&fp=${fp}&allowInsecure=1&type=ws&host=${domain}&path=${path}&fm=${fm}#${name}`);
            } else {
                links.push(`${auth}?${enc}security=tls&sni=${domain}&fp=unsafe&alpn=http%2F1.1&allowInsecure=0&type=ws&host=${domain}&path=${path}&cs=${cs}&fm=${fm}#${name}`);
            }
        }
    };

    build(vlsHeader, uuid, true);
    if (includeTrojan) {
        fpCounter = 0;
        build(troHeader, trojanSecret || uuid, false);
    }
    return links;
}


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

        const storedToken = await env.Kerman.get('session_token');
        return !!storedToken && safeEqual(sessionToken, storedToken);
    } catch (error) {
        return false;
    }
}

async function setSessionToken(env, token) {
    await env.Kerman.put('session_token', token, { expirationTtl: SESSION_TTL_SECONDS });
}

async function clearSessionToken(env) {
    await env.Kerman.delete('session_token');
}

async function checkRateLimit(env, ip) {
    const key = `rate_limit_${ip}`;
    const attempts = await env.Kerman.get(key);
    if (attempts && parseInt(attempts) >= MAX_LOGIN_ATTEMPTS) {
        throw new Error('Too many failed attempts. Try again in 15 minutes.');
    }
    return attempts ? parseInt(attempts) : 0;
}

async function incrementRateLimit(env, ip) {
    const key = `rate_limit_${ip}`;
    const current = await env.Kerman.get(key);
    const newCount = current ? parseInt(current) + 1 : 1;
    await env.Kerman.put(key, newCount.toString(), { expirationTtl: LOGIN_WINDOW_MS / 1000 });
    return newCount;
}

let subPath = 'default';
let proxyIPs = [];  
let yourUUID = ''; 
let trojanPassword = '';
let disabletro = false;
  
let cfip = [];

let domains = [
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

let ports = [443, 8443, 2053, 2083, 2087, 2096];
let nonTlsPorts = [80];

let counter = 1;
const allPorts = [...ports, ...nonTlsPorts];

for (let i = 0; i < 25; i++) {

    const randomDomainIndex = Math.floor(Math.random() * domains.length);
    const randomDomain = domains[randomDomainIndex];
    
    const randomPortIndex = Math.floor(Math.random() * allPorts.length);
    const randomPort = allPorts[randomPortIndex];
    
    const isNonTls = nonTlsPorts.includes(randomPort);
    const portSuffix = isNonTls ? '_Ntls' : '_Tls';
    cfip.push(randomDomain + ':' + randomPort + '#' + counter + '_🐲Dragon' + portSuffix);
    counter++;
}


async function loadUUIDFromKV(env) {
    if (env.Kerman) {
        try {
            const storedUUID = await env.Kerman.get('user_uuid');
            if (storedUUID) {
                return storedUUID;
            }
        } catch (error) {
            console.error('Error loading UUID from KV:', error);
        }
    }
    
    return '';
}

async function saveUUIDToKV(uuid, env) {
    if (env.Kerman) {
        try {
            await env.Kerman.put('user_uuid', uuid);
            return true;
        } catch (error) {
            console.error('Error saving UUID to KV:', error);
            return false;
        }
    }
    return false;
}

async function loadTrojanPasswordFromKV(env) {
    if (env.Kerman) {
        try {
            const storedPassword = await env.Kerman.get('trojan_password');
            return storedPassword || '';
        } catch (error) {
            return '';
        }
    }
    return '';
}

async function saveTrojanPasswordToKV(password, env) {
    if (env.Kerman) {
        try {
            await env.Kerman.put('trojan_password', password);
            return true;
        } catch (error) {
            return false;
        }
    }
    return false;
}

function closeSocketQuietly(socket) { 
    try { 
        if (socket.readyState === WebSocket.OPEN || socket.readyState === WebSocket.CLOSING) {
            socket.close(); 
        }
    } catch (error) {} 
}

function formatIdentifier(arr, offset = 0) {
    const hex = [...arr.slice(offset, offset + 16)].map(b => b.toString(16).padStart(2, '0')).join('');
    return `${hex.substring(0,8)}-${hex.substring(8,12)}-${hex.substring(12,16)}-${hex.substring(16,20)}-${hex.substring(20)}`;
}

function base64ToArray(b64Str) {
    if (!b64Str) return { error: null };
    try { 
        const binaryString = atob(b64Str.replace(/-/g, '+').replace(/_/g, '/'));
        const bytes = new Uint8Array(binaryString.length);
        for (let i = 0; i < binaryString.length; i++) {
            bytes[i] = binaryString.charCodeAt(i);
        }
        return { earlyData: bytes.buffer, error: null }; 
    } catch (error) { 
        return { error }; 
    }
}

function parsePryAddress(serverStr) {
    if (!serverStr) return null;
    serverStr = serverStr.trim();
    if (serverStr.startsWith('socks://') || serverStr.startsWith('socks5://')) {
        const urlStr = serverStr.replace(/^socks:\/\//, 'socks5://');
        try {
            const url = new URL(urlStr);
            return {
                type: 'socks5',
                host: url.hostname,
                port: parseInt(url.port) || 1080,
                username: url.username ? decodeURIComponent(url.username) : '',
                password: url.password ? decodeURIComponent(url.password) : ''
            };
        } catch (e) {
            return null;
        }
    }
    
    if (serverStr.startsWith('http://') || serverStr.startsWith('https://')) {
        try {
            const url = new URL(serverStr);
            return {
                type: 'http',
                host: url.hostname,
                port: parseInt(url.port) || (serverStr.startsWith('https://') ? 443 : 80),
                username: url.username ? decodeURIComponent(url.username) : '',
                password: url.password ? decodeURIComponent(url.password) : ''
            };
        } catch (e) {
            return null;
        }
    }
    
    if (serverStr.startsWith('[')) {
        const closeBracket = serverStr.indexOf(']');
        if (closeBracket > 0) {
            const host = serverStr.substring(1, closeBracket);
            const rest = serverStr.substring(closeBracket + 1);
            if (rest.startsWith(':')) {
                const port = parseInt(rest.substring(1), 10);
                if (!isNaN(port) && port > 0 && port <= 65535) {
                    return { type: 'direct', host, port };
                }
            }
            return { type: 'direct', host, port: 443 };
        }
    }

    const lastColonIndex = serverStr.lastIndexOf(':');
    
    if (lastColonIndex > 0) {
        const host = serverStr.substring(0, lastColonIndex);
        const portStr = serverStr.substring(lastColonIndex + 1);
        const port = parseInt(portStr, 10);
        
        if (!isNaN(port) && port > 0 && port <= 65535) {
            return { type: 'direct', host, port };
        }
    }
    
    return { type: 'direct', host: serverStr, port: 443 };
}

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

function isSpeedTestSite(hostname) {
    const speedTestDomains = ['speedtest.net','fast.com',];
    if (speedTestDomains.includes(hostname)) {
        return true;
    }

    for (const domain of speedTestDomains) {
        if (hostname.endsWith('.' + domain) || hostname === domain) {
            return true;
        }
    }
    return false;
}

async function sha224(text) {
  const encoder = new TextEncoder();
  const data = encoder.encode(text);
  const K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
];
  let H = [0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4];
  const msgLen = data.length;
  const bitLen = msgLen * 8;
  const paddedLen = Math.ceil((msgLen + 9) / 64) * 64;
  const padded = new Uint8Array(paddedLen);
  padded.set(data);
  padded[msgLen] = 0x80;
  const view = new DataView(padded.buffer);
  view.setUint32(paddedLen - 4, bitLen, false);
  for (let chunk = 0; chunk < paddedLen; chunk += 64) {
    const W = new Uint32Array(64);
    
    for (let i = 0; i < 16; i++) {
      W[i] = view.getUint32(chunk + i * 4, false);
    }
    
    for (let i = 16; i < 64; i++) {
      const s0 = rightRotate(W[i - 15], 7) ^ rightRotate(W[i - 15], 18) ^ (W[i - 15] >>> 3);
      const s1 = rightRotate(W[i - 2], 17) ^ rightRotate(W[i - 2], 19) ^ (W[i - 2] >>> 10);
      W[i] = (W[i - 16] + s0 + W[i - 7] + s1) >>> 0;
    }
    
    let [a, b, c, d, e, f, g, h] = H;
    
    for (let i = 0; i < 64; i++) {
      const S1 = rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25);
      const ch = (e & f) ^ (~e & g);
      const temp1 = (h + S1 + ch + K[i] + W[i]) >>> 0;
      const S0 = rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const temp2 = (S0 + maj) >>> 0;
      
      h = g;
      g = f;
      f = e;
      e = (d + temp1) >>> 0;
      d = c;
      c = b;
      b = a;
      a = (temp1 + temp2) >>> 0;
    }
    
    H[0] = (H[0] + a) >>> 0;
    H[1] = (H[1] + b) >>> 0;
    H[2] = (H[2] + c) >>> 0;
    H[3] = (H[3] + d) >>> 0;
    H[4] = (H[4] + e) >>> 0;
    H[5] = (H[5] + f) >>> 0;
    H[6] = (H[6] + g) >>> 0;
    H[7] = (H[7] + h) >>> 0;
  }
  
  const result = [];
  for (let i = 0; i < 7; i++) {
    result.push(
      ((H[i] >>> 24) & 0xff).toString(16).padStart(2, '0'),
      ((H[i] >>> 16) & 0xff).toString(16).padStart(2, '0'),
      ((H[i] >>> 8) & 0xff).toString(16).padStart(2, '0'),
      (H[i] & 0xff).toString(16).padStart(2, '0')
    );
  }
  return result.join('');
}

function rightRotate(value, amount) {
  return (value >>> amount) | (value << (32 - amount));
}

function showSetupPage() {
    const html = `<!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Setup Password</title>
        <style>
            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }
            
            body {
                font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
                min-height: 100vh;
                display: flex;
                justify-content: center;
                align-items: center;
                padding: 20px;
            }
            
            .setup-card {
                background: rgba(255, 255, 255, 0.95);
                backdrop-filter: blur(10px);
                padding: 40px;
                border-radius: 12px;
                box-shadow: 0 0px 5px rgb(0 0 0);
                max-width: 450px;
                width: 100%;
                text-align: center;
            }
            
            .setup-icon {
                font-size: 3rem;
                margin-bottom: 20px;
            }
            
            .setup-title {
                color: #2d3748;
                margin-bottom: 30px;
                font-size: 1.8rem;
                font-weight: 700;
            }
            
            .form-group {
                margin-bottom: 20px;
                text-align: left;
            }
            
            label {
                display: block;
                margin-bottom: 8px;
                color: #4a5568;
                font-weight: 600;
            }
            
            input {
                width: 100%;
                padding: 15px;
                border: 2px solid #e2e8f0;
                border-radius: 5px;
                font-size: 16px;
            }
            
            input:focus {
                outline: none;
                border-color: #667eea;
                box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
            }
            
            .submit-btn {
                width: 100%;
                padding: 15px;
                background: linear-gradient(135deg, #667eea, #764ba2);
                color: white;
                border: none;
                border-radius: 5px;
                font-size: 16px;
                font-weight: 600;
                cursor: pointer;
                transition: transform 0.2s ease;
            }
            
            .submit-btn:hover {
                transform: translateY(-2px);
            }
            
            .error-message {
                color: #e53e3e;
                margin-top: 10px;
                display: none;
                font-size: 14px;
            }
        </style>
    </head>
    <body>
        <div class="setup-card">
            <h1 class="setup-title">Set Admin Password</h1>
                        <form method="POST" action="/setup" onsubmit="return validatePasswords()">
                <div class="form-group" style="position: relative;">
                    <label for="password">Password:</label>
                    <input type="password" id="password" name="password" required style="padding-right: 50px;">
                    <button type="button" onclick="togglePassword('password')" style="position: absolute; right: 10px; top: 50%; background: none; border: none; cursor: pointer; font-size: 17px;">🙈</button>
                </div>
                <div class="form-group" style="position: relative;">
                    <label for="confirmPassword">Confirm Password:</label>
                    <input type="password" id="confirmPassword" name="confirmPassword" required style="padding-right: 50px;">
                    <button type="button" onclick="togglePassword('confirmPassword')" style="position: absolute; right: 10px; top: 50%; background: none; border: none; cursor: pointer; font-size: 17px;">🙈</button>
                </div>
                <div id="passwordError" class="error-message">Passwords do not match</div>
                <button type="submit" class="submit-btn">Save Password</button>
            </form>
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
            const button = input.parentNode.querySelector('button');
            
            if (input.type === 'password') {
                input.type = 'text';
                button.innerHTML = '🙉';
            } else {
                input.type = 'password';
                button.innerHTML = '🙈';
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
        <title>🐲Dragon_D</title>
        <style>
            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }
            
            body {
                font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
            }
            
            .login-card {
                    background: rgba(30, 30, 45, 0.1);
                    padding: 40px 22px;
                    border-radius: 12px;
                    box-shadow: 0 6px 16px rgba(0, 0, 0, 0.6), inset 0 1px 1px rgba(255, 255, 255, 0.1);
                    display: flex;
                    flex-direction: column;
                    gap: 25px;
                    align-items: center;
                    width: 90%;
                    max-width: 400px;
                    border: 1px solid rgba(17, 0, 98, 0.2);
                }
            
            .login-icon {
                font-size: 3rem;
                margin-bottom: 20px;
            }
            
            .login-title {
                color: #13233e;
                margin-bottom: 18px;
                font-size: 1.8rem;
                font-weight: 700;
                height: 5px;
                margin-top: -50px;
            }
            
            .form-group {
                margin-bottom: 25px;
                text-align: left;
            }
            
            label {
                display: block;
                margin-bottom: 8px;
                color: #4a5568;
                font-weight: 600;
            }
            
            input {
                width: 100%;
                padding: 15px;
                border: 2px solid #333a4578;
                border-radius: 5px;
                font-size: 16px;
            }
            
            input:focus {
                outline: none;
                border-color: #667eea;
                box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
            }
            
            .login-btn {
                background: #171740;
                color: white;
                border: none;
                padding: 14px 30px;
                border-radius: 8px;
                cursor: pointer;
                font-family: Vazir, sans-serif;
                font-size: 16px;
                font-weight: bold;
                width: 100%;
                transition: background-color 0.2s 
            ease;
            }
            
            .login-btn:hover {
                transform: translateY(-2px);
            }
            
            .error-message {
                background: #fed7d7;
                color: #c53030;
                padding: 15px;
                border-radius: 5px;
                margin-bottom: 20px;
                border: 1px solid #feb2b2;
            }
        </style>
    </head>
    <body>
        <div class="login-card">
            <div class="login-icon"></div>
            <h1 class="login-title">Welcome</h1>
            ${error ? `<div class="error-message">${error}</div>` : ''}
                        <form method="POST" action="/login">
                <div class="form-group" style="position: relative;">
                    <label for="password">Password:</label>
                    <input type="password" id="password" name="password" required style="padding-right: 50px;">
                    <button type="button" onclick="togglePassword('password')" style="position: absolute; right: 10px; top: 50%; background: none; border: none; cursor: pointer; font-size: 17px;">🙈</button>
                </div>
                <button type="submit" class="login-btn">Login</button>
            </form>
        </div>
                <script>
        function togglePassword(inputId) {
            const input = document.getElementById(inputId);
            const button = input.parentNode.querySelector('button');
            
            if (input.type === 'password') {
                input.type = 'text';
                button.innerHTML = '🙉';
            } else {
                input.type = 'password';
                button.innerHTML = '🙈';
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

function generateRandomPath() {
  const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let result = '';
  for (let i = 0; i < 12; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return encodeURIComponent(`/${result}?ed=2560`);
}

async function handleChangePassword(request, env) {
    const jsonResponse = (obj, status, extraHeaders = {}) => new Response(JSON.stringify(obj), {
        status,
        headers: { 'Content-Type': 'application/json', ...extraHeaders },
    });

    try {
        if (!(await checkAuth(env, request))) return jsonResponse({ error: 'Unauthorized' }, 401);
        if (request.method !== 'POST') return jsonResponse({ error: 'Method not allowed' }, 405);

        const { currentPassword, newPassword } = await request.json();
        if (typeof currentPassword !== 'string' || typeof newPassword !== 'string' || newPassword.length < 4) {
            return jsonResponse({ error: 'Password must be at least 4 characters' }, 400);
        }

        const stored = await env.Kerman.get('admin_password');
        const check = await verifyPassword(stored, currentPassword);
        if (!check.ok) return jsonResponse({ error: 'Current password is incorrect' }, 400);

        await env.Kerman.put('admin_password', await hashPassword(newPassword));

        const sessionToken = randomToken();
        await setSessionToken(env, sessionToken);
        return jsonResponse({ success: true }, 200, { 'Set-Cookie': sessionCookie(sessionToken) });
    } catch (error) {
        return jsonResponse({ error: 'Server error: ' + error.message }, 500);
    }
}

export default {
    async fetch(request, env, ctx) {
        try {
            if (!env.Kerman) {
                return new Response("KV binding 'Kerman' is not configured for this Worker. Add a KV namespace binding named exactly 'Kerman' (Settings > Bindings), then redeploy.", {
                    status: 500,
                    headers: { 'Content-Type': 'text/plain; charset=utf-8' },
                });
            }

            const url = new URL(request.url);
            const pathname = url.pathname;
            const isWebSocket = (request.headers.get('Upgrade') || '').toLowerCase() === 'websocket';

            const runtime = await loadRuntimeConfig(env);

            if (!runtime.hasPassword) {
                if (pathname === '/setup' && request.method === 'POST') {
                    if (await env.Kerman.get('admin_password')) {
                        return new Response('Setup already completed', { status: 403 });
                    }
                    const formData = await request.formData();
                    const password = formData.get('password');
                    const confirmPassword = formData.get('confirmPassword');

                    if (!password || !confirmPassword) {
                        return new Response('Both password fields are required', { status: 400 });
                    }
                    if (password !== confirmPassword) {
                        return new Response('Passwords do not match', { status: 400 });
                    }

                    await env.Kerman.put('admin_password', await hashPassword(password));
                    invalidateRuntimeConfig();
                    return redirectTo('/login');
                }

                if (pathname === '/setup' || pathname === '/') {
                    return showSetupPage();
                }
                return redirectTo('/setup');
            }

            yourUUID = runtime.uuid;
            trojanPassword = runtime.trojan;
            subPath = String(env.SUB_PATH || env.subpath || 'default').trim() || 'default';
            disabletro = parseBool(env.DISABLE_TROJAN ?? env.CLOSE_TROJAN);
            const envProxy = env.PROXYIP || env.proxyip || env.proxyIP;
            proxyIPs = envProxy 
                ? String(envProxy).split(',').map((s) => s.trim()).filter(Boolean) 
                : ['di.nscl.ir:443'];

            if (isWebSocket) {
                let wsPathProxyIP = null;
                if (pathname.startsWith('/proxyip=')) {
                    try {
                        wsPathProxyIP = decodeURIComponent(pathname.substring(9)).trim();
                    } catch (e) {
                    }
                }
                const customProxyIP = wsPathProxyIP || url.searchParams.get('proxyip') || request.headers.get('proxyip');
                return await handleVlsRequest(request, customProxyIP);
            }

            if (pathname === '/login') {
                if (request.method === 'POST') {
                    const clientIP = request.headers.get('CF-Connecting-IP') || 'unknown';

                    try {
                        await checkRateLimit(env, clientIP);
                    } catch (rateError) {
                        return showLoginPage(rateError.message);
                    }

                    const formData = await request.formData();
                    const password = formData.get('password') || '';
                    const storedPassword = await env.Kerman.get('admin_password');
                    const check = await verifyPassword(storedPassword, String(password));

                    if (check.ok) {
                        await env.Kerman.delete(`rate_limit_${clientIP}`);
                        if (check.needsUpgrade) {
                            await env.Kerman.put('admin_password', await hashPassword(String(password)));
                        }

                        const sessionToken = randomToken();
                        await setSessionToken(env, sessionToken);
                        return redirectTo('/panel', { 'Set-Cookie': sessionCookie(sessionToken) });
                    }

                    const newAttempts = await incrementRateLimit(env, clientIP);
                    let errorMessage = `Invalid password (${newAttempts}/${MAX_LOGIN_ATTEMPTS})`;
                    if (newAttempts >= MAX_LOGIN_ATTEMPTS) {
                        errorMessage = 'Too many failed attempts. Account locked for 15 minutes';
                    }
                    return showLoginPage(errorMessage);
                }
                return showLoginPage();
            }

            if (pathname === '/logout') {
                if (await checkAuth(env, request)) {
                    await clearSessionToken(env);
                }
                return redirectTo('/login', { 'Set-Cookie': 'session_token=; Path=/; HttpOnly; SameSite=Strict; Secure; Max-Age=0' });
            }

            if (pathname === '/change-password') {
                return await handleChangePassword(request, env);
            }

            if (pathname === '/fragment-config') {
                return await handleFragmentApi(request, env);
            }

            if (pathname === '/update-uuid' || pathname === '/update-trojan-password') {
                if (!(await checkAuth(env, request))) return redirectTo('/login');

                if (pathname === '/update-uuid') {
                    const newUUID = (url.searchParams.get('uuid') || '').toLowerCase();
                    if (UUID_REGEX.test(newUUID) && (await saveUUIDToKV(newUUID, env))) {
                        yourUUID = newUUID;
                        invalidateRuntimeConfig();
                        return new Response('UUID updated successfully', {
                            headers: { 'Content-Type': 'text/plain' },
                        });
                    }
                    return new Response('Invalid UUID', { status: 400 });
                }

                const newPassword = url.searchParams.get('password') ?? '';
                if (newPassword.length <= 128 && (await saveTrojanPasswordToKV(newPassword, env))) {
                    trojanPassword = newPassword;
                    invalidateRuntimeConfig();
                    return new Response('Trojan password updated successfully', {
                        headers: { 'Content-Type': 'text/plain' },
                    });
                }
                return new Response('Invalid password', { status: 400 });
            }

            if (request.method === 'GET') {
                if (pathname === '/' || pathname === '/panel') {
                    if (!(await checkAuth(env, request))) return redirectTo('/login');
                    return getMainPageContent(url.hostname, `https://${url.hostname}`, env);
                }

                const firstSegment = pathname.split('/').filter(Boolean)[0];
                if (firstSegment && yourUUID && firstSegment.toLowerCase() === subPath.toLowerCase()) {
                    const fragment = await getFragmentConfig(env);
                    const links = buildSubscriptionLinks({
                        domain: url.hostname,
                        uuid: yourUUID,
                        trojanSecret: trojanPassword,
                        includeTrojan: !disabletro,
                        fragment,
                    });
                    return new Response(toBase64(links.join('\n')), {
                        headers: {
                            'Content-Type': 'text/plain; charset=utf-8',
                            'Cache-Control': 'no-store, no-cache, must-revalidate, max-age=0',
                        },
                    });
                }
            }

            return new Response('Not Found', { status: 404 });
        } catch (err) {
            return new Response('Internal Server Error', { status: 500 });
        }
    },
};

            async function handleVlsRequest(request, customProxyIP) {
                const wssPair = new WebSocketPair();
                const [clientSock, serverSock] = Object.values(wssPair);
                serverSock.accept();
                let remoteConnWrapper = { socket: null };
                let isDnsQuery = false;
                let isTrojan = false;
                const earlyData = request.headers.get('sec-websocket-protocol') || '';
                const readable = makeReadableStr(serverSock, earlyData);
            
                readable.pipeTo(new WritableStream({
                    async write(chunk) {
                        if (isDnsQuery) return await forwardataudp(chunk, serverSock, null);
                        if (remoteConnWrapper.socket) {
                            const writer = remoteConnWrapper.socket.writable.getWriter();
                            await writer.write(chunk);
                            writer.releaseLock();
                            return;
                        }
                        
                        if (!disabletro) {
                            const trojanResult = await parsetroHeader(chunk, trojanPassword ? await sha224(trojanPassword) : yourUUID);
                            if (!trojanResult.hasError) {
                                isTrojan = true;
                                const { addressType, port, hostname, rawClientData } = trojanResult;
                                
                                if (isSpeedTestSite(hostname)) {
                                    throw new Error('Speedtest site is blocked');
                                }
                                
                                await forwardataTCP(hostname, port, rawClientData, serverSock, null, remoteConnWrapper, customProxyIP);
                                return;
                            }
                        }
                        
                        const { hasError, message, addressType, port, hostname, rawIndex, version, isUDP } = parseVLsPacketHeader(chunk, yourUUID);
                        if (hasError) throw new Error(message);
            
                        if (isSpeedTestSite(hostname)) {
                            throw new Error('Speedtest site is blocked');
                        }
            
                        if (isUDP) {
                            if (port === 53) isDnsQuery = true;
                            else throw new Error('UDP is not supported');
                        }
                        const respHeader = new Uint8Array([version[0], 0]);
                        const rawData = chunk.slice(rawIndex);
                        if (isDnsQuery) return forwardataudp(rawData, serverSock, respHeader);
                        await forwardataTCP(hostname, port, rawData, serverSock, respHeader, remoteConnWrapper, customProxyIP);
                    },
                })).catch((err) => {
                    closeSocketQuietly(serverSock);
                });
            
                return new Response(null, { status: 101, webSocket: clientSock });
            }
            
            async function parsetroHeader(buffer, passwordPlainText) {
              const sha224Password = await sha224(trojanPassword || passwordPlainText);
              
              if (buffer.byteLength < 56) {
                return { hasError: true, message: "invalid data" };
              }
              let crLfIndex = 56;
              if (new Uint8Array(buffer.slice(56, 57))[0] !== 0x0d || new Uint8Array(buffer.slice(57, 58))[0] !== 0x0a) {
                return { hasError: true, message: "invalid header format" };
              }
              const password = new TextDecoder().decode(buffer.slice(0, crLfIndex));
              if (password !== sha224Password) {
                return { hasError: true, message: "invalid password" };
              }
            
              const socks5DataBuffer = buffer.slice(crLfIndex + 2);
              if (socks5DataBuffer.byteLength < 6) {
                return { hasError: true, message: "invalid S5 request data" };
              }
            
              const view = new DataView(socks5DataBuffer);
              const cmd = view.getUint8(0);
              if (cmd !== 1) {
                return { hasError: true, message: "unsupported command, only TCP is allowed" };
              }
            
              const atype = view.getUint8(1);
              let addressLength = 0;
              let addressIndex = 2;
              let address = "";
              switch (atype) {
                case 1:
                  addressLength = 4;
                  address = new Uint8Array(socks5DataBuffer.slice(addressIndex, addressIndex + addressLength)).join(".");
                  break;
                case 3:
                  addressLength = new Uint8Array(socks5DataBuffer.slice(addressIndex, addressIndex + 1))[0];
                  addressIndex += 1;
                  address = new TextDecoder().decode(socks5DataBuffer.slice(addressIndex, addressIndex + addressLength));
                  break;
                case 4:
                  addressLength = 16;
                  const dataView = new DataView(socks5DataBuffer.slice(addressIndex, addressIndex + addressLength));
                  const ipv6 = [];
                  for (let i = 0; i < 8; i++) {
                    ipv6.push(dataView.getUint16(i * 2).toString(16));
                  }
                  address = ipv6.join(":");
                  break;
                default:
                  return { hasError: true, message: `invalid addressType is ${atype}` };
              }
            
              if (!address) {
                return { hasError: true, message: `address is empty, addressType is ${atype}` };
              }
            
              const portIndex = addressIndex + addressLength;
              const portBuffer = socks5DataBuffer.slice(portIndex, portIndex + 2);
              const portRemote = new DataView(portBuffer).getUint16(0);
            
              return {
                hasError: false,
                addressType: atype,
                port: portRemote,
                hostname: address,
                rawClientData: socks5DataBuffer.slice(portIndex + 4)
              };
            }
            
            async function connect2Socks5(proxyConfig, targetHost, targetPort, initialData) {
                const { host, port, username, password } = proxyConfig;
                const socket = connect({ hostname: host, port: port });
                const writer = socket.writable.getWriter();
                const reader = socket.readable.getReader();
                
                try {
                    const authMethods = username && password ? 
                        new Uint8Array([0x05, 0x02, 0x00, 0x02]) :
                        new Uint8Array([0x05, 0x01, 0x00]); 
                    
                    await writer.write(authMethods);
                    const methodResponse = await reader.read();
                    if (methodResponse.done || methodResponse.value.byteLength < 2) {
                        throw new Error('S5 method selection failed');
                    }
                    
                    const selectedMethod = new Uint8Array(methodResponse.value)[1];
                    if (selectedMethod === 0x02) {
                        if (!username || !password) {
                            throw new Error('S5 requires authentication');
                        }
                        const userBytes = new TextEncoder().encode(username);
                        const passBytes = new TextEncoder().encode(password);
                        const authPacket = new Uint8Array(3 + userBytes.length + passBytes.length);
                        authPacket[0] = 0x01; 
                        authPacket[1] = userBytes.length;
                        authPacket.set(userBytes, 2);
                        authPacket[2 + userBytes.length] = passBytes.length;
                        authPacket.set(passBytes, 3 + userBytes.length);
                        await writer.write(authPacket);
                        const authResponse = await reader.read();
                        if (authResponse.done || new Uint8Array(authResponse.value)[1] !== 0x00) {
                            throw new Error('S5 authentication failed');
                        }
                    } else if (selectedMethod !== 0x00) {
                        throw new Error(`S5 unsupported auth method: ${selectedMethod}`);
                    }
                    
                    const hostBytes = new TextEncoder().encode(targetHost);
                    const connectPacket = new Uint8Array(7 + hostBytes.length);
                    connectPacket[0] = 0x05;
                    connectPacket[1] = 0x01;
                    connectPacket[2] = 0x00; 
                    connectPacket[3] = 0x03; 
                    connectPacket[4] = hostBytes.length;
                    connectPacket.set(hostBytes, 5);
                    new DataView(connectPacket.buffer).setUint16(5 + hostBytes.length, targetPort, false);
                    await writer.write(connectPacket);
                    const connectResponse = await reader.read();
                    if (connectResponse.done || new Uint8Array(connectResponse.value)[1] !== 0x00) {
                        throw new Error('S5 connection failed');
                    }
                    
                    await writer.write(initialData);
                    writer.releaseLock();
                    reader.releaseLock();
                    return socket;
                } catch (error) {
                    writer.releaseLock();
                    reader.releaseLock();
                    throw error;
                }
            }
            
            async function connect2Http(proxyConfig, targetHost, targetPort, initialData) {
                const { host, port, username, password } = proxyConfig;
                const socket = connect({ hostname: host, port: port });
                const writer = socket.writable.getWriter();
                const reader = socket.readable.getReader();
                try {
                    let connectRequest = `CONNECT ${targetHost}:${targetPort} HTTP/1.1\r\n`;
                    connectRequest += `Host: ${targetHost}:${targetPort}\r\n`;
                    
                    if (username && password) {
                        const auth = btoa(`${username}:${password}`);
                        connectRequest += `Proxy-Authorization: Basic ${auth}\r\n`;
                    }
                    
                    connectRequest += `User-Agent: Mozilla/5.0\r\n`;
                    connectRequest += `Connection: keep-alive\r\n`;
                    connectRequest += '\r\n';
                    await writer.write(new TextEncoder().encode(connectRequest));
                    let responseBuffer = new Uint8Array(0);
                    let headerEndIndex = -1;
                    let bytesRead = 0;
                    const maxHeaderSize = 8192;
                    
                    while (headerEndIndex === -1 && bytesRead < maxHeaderSize) {
                        const { done, value } = await reader.read();
                        if (done) {
                            throw new Error('Connection closed before receiving HTTP response');
                        }
                        const newBuffer = new Uint8Array(responseBuffer.length + value.length);
                        newBuffer.set(responseBuffer);
                        newBuffer.set(value, responseBuffer.length);
                        responseBuffer = newBuffer;
                        bytesRead = responseBuffer.length;
                        
                        for (let i = 0; i < responseBuffer.length - 3; i++) {
                            if (responseBuffer[i] === 0x0d && responseBuffer[i + 1] === 0x0a &&
                                responseBuffer[i + 2] === 0x0d && responseBuffer[i + 3] === 0x0a) {
                                headerEndIndex = i + 4;
                                break;
                            }
                        }
                    }
                    
                    if (headerEndIndex === -1) {
                        throw new Error('Invalid HTTP response');
                    }
                    
                    const headerText = new TextDecoder().decode(responseBuffer.slice(0, headerEndIndex));
                    const statusLine = headerText.split('\r\n')[0];
                    const statusMatch = statusLine.match(/HTTP\/\d\.\d\s+(\d+)/);
                    
                    if (!statusMatch) {
                        throw new Error(`Invalid response: ${statusLine}`);
                    }
                    
                    const statusCode = parseInt(statusMatch[1]);
                    if (statusCode < 200 || statusCode >= 300) {
                        throw new Error(`Connection failed: ${statusLine}`);
                    }
                    
                    console.log('HTTP connection established for Trojan');
                    
                    await writer.write(initialData);
                    writer.releaseLock();
                    reader.releaseLock();
                    
                    return socket;
                } catch (error) {
                    try { 
                        writer.releaseLock(); 
                    } catch (e) {}
                    try { 
                        reader.releaseLock(); 
                    } catch (e) {}
                    try { 
                        socket.close(); 
                    } catch (e) {}
                    throw error;
                }
            }
            
async function forwardataTCP(host, portNum, rawData, ws, respHeader, remoteConnWrapper, customProxyIP) {
    async function connectDirect(address, port, data) {
        const remoteSock = connect({ hostname: address, port: port });
        const writer = remoteSock.writable.getWriter();
        await writer.write(data);
        writer.releaseLock();
        return remoteSock;
    }
    
    const pool = customProxyIP 
        ? [customProxyIP, ...proxyIPs.filter((p) => p !== customProxyIP)]
        : [...proxyIPs];
    
    async function connectViaProxy(proxyStr, data) {
        const proxyConfig = parsePryAddress(proxyStr);
        if (!proxyConfig || !proxyConfig.host) {
            throw new Error(`Invalid proxy: ${proxyStr}`);
        }
        
        let newSocket;
        if (proxyConfig.type === 'socks5') {
            newSocket = await connect2Socks5(proxyConfig, host, portNum, data);
        } else if (proxyConfig.type === 'http' || proxyConfig.type === 'https') {
            newSocket = await connect2Http(proxyConfig, host, portNum, data);
        } else {
            newSocket = await connectDirect(proxyConfig.host, proxyConfig.port, data);
        }
        return newSocket;
    }
    
    async function tryPool(index) {
        if (index >= pool.length) {
            return tryNAT64();
        }
        
        try {
            const newSocket = await connectViaProxy(pool[index], rawData);
            remoteConnWrapper.socket = newSocket;
            newSocket.closed.catch(() => {}).finally(() => closeSocketQuietly(ws));
            connectStreams(newSocket, ws, respHeader, () => tryPool(index + 1));
        } catch (err) {
            console.log(`Proxy ${index} (${pool[index]}) failed:`, err.message);
            return tryPool(index + 1);
        }
    }
    
    async function tryNAT64() {
        try {
            const ipv4 = await resolveIPv4(host);
            const nat64Address = toNAT64Address(ipv4);
            if (!nat64Address) {
                console.log(`NAT64 fallback failed: could not resolve ${host}`);
                closeSocketQuietly(ws);
                return;
            }
            console.log(`Falling back to NAT64: ${nat64Address}`);
            const newSocket = await connectDirect(nat64Address, portNum, rawData);
            remoteConnWrapper.socket = newSocket;
            newSocket.closed.catch(() => {}).finally(() => closeSocketQuietly(ws));
            connectStreams(newSocket, ws, respHeader, null);
        } catch (err) {
            console.log(`NAT64 fallback error:`, err.message);
            closeSocketQuietly(ws);
        }
    }
    
    try {
        const initialSocket = await connectDirect(host, portNum, rawData);
        remoteConnWrapper.socket = initialSocket;
        connectStreams(initialSocket, ws, respHeader, () => tryPool(0));
    } catch (err) {
        console.log(`Direct connection to ${host}:${portNum} failed, trying pool...`);
        await tryPool(0);
    }
}
            
            function parseVLsPacketHeader(chunk, token) {
                if (chunk.byteLength < 24) return { hasError: true, message: 'Invalid data' };
                const version = new Uint8Array(chunk.slice(0, 1));
                if (formatIdentifier(new Uint8Array(chunk.slice(1, 17))) !== String(token || '').toLowerCase()) return { hasError: true, message: 'Invalid uuid' };
                const optLen = new Uint8Array(chunk.slice(17, 18))[0];
                const cmd = new Uint8Array(chunk.slice(18 + optLen, 19 + optLen))[0];
                let isUDP = false;
                if (cmd === 1) {} else if (cmd === 2) { isUDP = true; } else { return { hasError: true, message: 'Invalid command' }; }
                const portIdx = 19 + optLen;
                const port = new DataView(chunk.slice(portIdx, portIdx + 2)).getUint16(0);
                let addrIdx = portIdx + 2, addrLen = 0, addrValIdx = addrIdx + 1, hostname = '';
                const addressType = new Uint8Array(chunk.slice(addrIdx, addrValIdx))[0];
                switch (addressType) {
                    case 1: 
                        addrLen = 4; 
                        hostname = new Uint8Array(chunk.slice(addrValIdx, addrValIdx + addrLen)).join('.'); 
                        break;
                    case 2: 
                        addrLen = new Uint8Array(chunk.slice(addrValIdx, addrValIdx + 1))[0]; 
                        addrValIdx += 1; 
                        hostname = new TextDecoder().decode(chunk.slice(addrValIdx, addrValIdx + addrLen)); 
                        break;
                    case 3: 
                        addrLen = 16; 
                        const ipv6 = []; 
                        const ipv6View = new DataView(chunk.slice(addrValIdx, addrValIdx + addrLen)); 
                        for (let i = 0; i < 8; i++) ipv6.push(ipv6View.getUint16(i * 2).toString(16)); 
                        hostname = ipv6.join(':'); 
                        break;
                    default: 
                        return { hasError: true, message: `Invalid address type: ${addressType}` };
                }
                if (!hostname) return { hasError: true, message: `Invalid address: ${addressType}` };
                return { hasError: false, addressType, port, hostname, isUDP, rawIndex: addrValIdx + addrLen, version };
            }
            
            function makeReadableStr(socket, earlyDataHeader) {
                let cancelled = false;
                return new ReadableStream({
                    start(controller) {
                        socket.addEventListener('message', (event) => { 
                            if (!cancelled) controller.enqueue(event.data); 
                        });
                        socket.addEventListener('close', () => { 
                            if (!cancelled) { 
                                closeSocketQuietly(socket); 
                                controller.close(); 
                            } 
                        });
                        socket.addEventListener('error', (err) => controller.error(err));
                        const { earlyData, error } = base64ToArray(earlyDataHeader);
                        if (error) controller.error(error); 
                        else if (earlyData) controller.enqueue(earlyData);
                    },
                    cancel() { 
                        cancelled = true; 
                        closeSocketQuietly(socket); 
                    }
                });
            }
            
            async function connectStreams(remoteSocket, webSocket, headerData, retryFunc) {
                let header = headerData, hasData = false;
                await remoteSocket.readable.pipeTo(
                    new WritableStream({
                        async write(chunk, controller) {
                            if (webSocket.readyState !== WebSocket.OPEN) {
                                controller.error('ws.readyState is not open');
                                return;
                            }
                            hasData = true;
                            if (header) { 
                                const response = new Uint8Array(header.length + chunk.byteLength);
                                response.set(header, 0);
                                response.set(chunk, header.length);
                                webSocket.send(response.buffer); 
                                header = null; 
                            } else { 
                                webSocket.send(chunk); 
                            }
                        },
                        abort() {},
                    })
                ).catch((err) => { 
                    if (hasData || !retryFunc) closeSocketQuietly(webSocket);
                });
                if (!hasData && retryFunc) {
                    try {
                        await retryFunc();
                    } catch (error) {
                        closeSocketQuietly(webSocket);
                    }
                }
            }
            
            async function forwardataudp(udpChunk, webSocket, respHeader) {
                try {
                    const tcpSocket = connect({ hostname: '8.8.4.4', port: 53 });
                    let vlessHeader = respHeader;
                    const writer = tcpSocket.writable.getWriter();
                    await writer.write(udpChunk);
                    writer.releaseLock();
                    await tcpSocket.readable.pipeTo(new WritableStream({
                        async write(chunk) {
                            if (webSocket.readyState === WebSocket.OPEN) {
                                if (vlessHeader) { 
                                    const response = new Uint8Array(vlessHeader.length + chunk.byteLength);
                                    response.set(vlessHeader, 0);
                                    response.set(chunk, vlessHeader.length);
                                    webSocket.send(response.buffer);
                                    vlessHeader = null; 
                                } else { 
                                    webSocket.send(chunk); 
                                }
                            }
                        },
                    }));
                } catch (error) {
            
                }
            }

async function getMainPageContent(url, baseUrl, env) {

    const html = `<!DOCTYPE html>
    <html lang="fa">
    <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, minimum-scale=1.0, maximum-scale=1.0, user-scalable=no, viewport-fit=cover">
    <title>🐲Dragon_D</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css">
    <style>
        :root {
    --bg-primary: #ffffff;
    --bg-secondary: #f8fafc;
    --bg-tertiary: #f1f5f9;
    --primary: #ff8510;
    --primary-dark: #b91c1c;
    --secondary: #e2e8f0;
    --accent: #16a34a;
    --danger: #ff0202;
    --warning: #f59e0b;
    --text: #000000;
    --text-light: #64748b;
    --border: #737373;
    --shadow: 0 1px 3px 0 rgb(0 0 0 / 58%), 0 1px 2px 0 rgba(0, 0, 0, 0.2);
    --radius: 12px;
    --get-Ip: #ee9c22;
    --kadr: #d1d5db;
    --card-bg: #fdff76;
    --header-bg: linear-gradient(135deg, #dc2626 0%, #ea580c 50%, #d97706 100%); /* قرمز-نارنجی دراگون */
    --header-text: #ffffff;
}

.dark-mode {
    --bg-primary: #29292d;
    --bg-secondary: #000000;
    --bg-tertiary: #252639;
    --primary: #ff8510;
    --primary-dark: #ef4444;
    --secondary: #374151;
    --accent: #34d399;
    --danger: #ff0202;
    --warning: #fbbf24;
    --text: #ffffffff;
    --text-light: #94a3b8;
    --border: #797979;
    --shadow: 0 1px 3px 0 rgb(143 143 143), 0 1px 2px 0 rgba(0, 0, 0, 0.2);
    --get-Ip: #ee9c22;
    --kadr: #475569;
    --card-bg: #141414;
    --header-bg: linear-gradient(135deg, #7f1d1d 0%, #991b1b 50%, #dc2626 100%);/
    --header-text: #ffffff;
}

* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
    font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
}

body {
    font-family: 'Inter', 'Segoe UI', system-ui, -apple-system, sans-serif;
    background: var(--bg-secondary);
    color: var(--text);
    min-height: 100vh;
    padding: 10px;
    line-height: 1.6;
}

.container {
    max-width: 800px;
    margin: 0 auto;
    padding: 0 15px;
}

.header {
    text-align: center;
    margin-bottom: 40px;
}

.panel-header {
    background: var(--header-bg);
    box-shadow: 0 8px 25px -8px rgba(220, 38, 38, 0.4);
    padding: 18px 30px;
    margin-bottom: 25px;
    text-align: center;
    position: relative;
    overflow: hidden;
    border-radius: 8px;
    border: none;
    max-width: 750px;
    margin: 0 auto 25px;
}

.panel-title {
    font-size: 2.8rem;
    font-weight: 800;
    margin: 0;
    font-family: 'Orbitron', sans-serif;
    color: var(--header-text);
    letter-spacing: 4px;
    text-shadow: 0 2px 10px rgba(0, 0, 0, 0.3);
    position: relative;
    z-index: 2;
    background: linear-gradient(45deg, #ffffff, #fef3c7, #ffffff);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
}

.dark-mode .panel-header {
    background: var(--header-bg);
    box-shadow: 0 8px 25px -8px rgba(127, 29, 29, 0.6);
}

.dark-mode .panel-header::before {
    background: linear-gradient(45deg, transparent, rgba(255,255,255,0.1), transparent);
}

.dark-mode .panel-title {
    background: linear-gradient(45deg, #fef3c7, #fde68a, #fef3c7);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
    text-shadow: 0 2px 20px rgba(254, 243, 199, 0.3);
}

.accordion-container {
    display: flex;
    flex-direction: column;
    gap: 25px;
    align-items: center;
}

.form-group small {
    font-size: 20px;
    font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
}

.add-ip-row {
    display: flex;
    gap: 10px;
    margin-bottom: 15px;
    align-items: stretch;
    margin-top: 35px;
}

.ip-input {
    flex: 1;
    min-width: 0;
}

.add-btn {
    background: var(--accent);
    color: white;
    border: none;
    border-radius: 8px;
    padding: 12px 20px;
    font-size: 16px;
    font-weight: 600;
    cursor: pointer;
    white-space: nowrap;
    min-width: 80px;
    flex-shrink: 0;
    height: auto;
    display: flex;
    align-items: center;
    justify-content: center;
    box-shadow: 0 2px 8px rgba(22, 163, 74, 0.3);
}

.add-btn:hover {
    background: #059669;
    transform: translateY(-2px);
    box-shadow: 0 6px 20px rgba(22, 163, 74, 0.4);
}

.accordion {
    background: var(--card-bg);
    box-shadow: var(--shadow);
    overflow: hidden;
    border-radius: 8px;
    margin: 0 auto 15px;
    max-width: 770px;
    width: 100%;
    margin: 0 auto 15px;
}

.accordion-header {
    padding: 24px;
    cursor: pointer;
    display: flex;
    align-items: center;
    justify-content: space-between;
    background: var(--card-bg);
    height: 94px;
}

.accordion-icon {
    font-size: 1.5rem;
    margin-right: 12px;
    color: var(--primary);
}

.accordion-title {
    display: flex;
    align-items: center;
    flex: 1;
    font-family: 'Inter', sans-serif;
    font-size: 20px;
    font-weight: 600;
    letter-spacing: 0.5px;
    color: var(--text);
}

.accordion-arrow {
    font-size: 1.2rem;
    color: var(--text-light);
}

.accordion-content {
    padding: 0 24px;
    background: var(--card-bg);
    display: none;
}

.accordion.active .accordion-content {
    padding: 0 24px 24px 24px;
    display: block;
}

.form-group {
    margin-bottom: 20px;
}

.form-label {
    display: block;
    margin-bottom: 8px;
    font-weight: 600;
    color: var(--text);
    font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
    font-size: 17px;
}

.form-input, .form-select, .form-textarea {
    width: 100%;
    padding: 12px 16px;
    border: 1px solid var(--border);
    border-radius: 8px;
    font-size: 16px;
    background: var(--bg-primary);
    color: var(--text);
}

.form-input:focus, .form-select:focus, .form-textarea:focus {
    outline: none;
    border-color: var(--primary);
    box-shadow: 0 0 0 3px rgba(220, 38, 38, 0.1);
}

.btn {
    padding: 12px 24px;
    border: none;
    border-radius: 8px;
    font-size: 16px;
    font-weight: 600;
    cursor: pointer;
    align-items: center;
    gap: 8px;
}

.btn-primary, .btn-danger {
    padding: 15px 20px;
    border: none;
    border-radius: 8px;
    font-size: 16px;
    font-weight: 500;
    cursor: pointer;
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 8px;
    width: 100%;
    margin-bottom: 10px;
}

.btn-danger:hover {
    transform: translateY(-2px);
}

.export-btn {
    width: 100%;
    margin-top: 50px;
    padding: 15px;
    background: var(--get-Ip);
    color: var(--text);
    border: none;
    border-radius: 8px;
    font-size: 17px;
    font-weight: bold;
    cursor: pointer;
    text-align: center;
    display: block;
}

.export-btn:hover {
    background: var(--primary);
    transform: translateY(-2px);
    box-shadow: 0 4px 15px rgba(220, 38, 38, 0.4);
}

.btn-primary {
    background: var(--primary);
    font-size: 16px;
    color: white;
    box-shadow: 0 4px 15px rgba(220, 38, 38, 0.3);
}

.btn-primary:hover {
    background: var(--primary-dark);
    transform: translateY(-2px);
    box-shadow: 0 6px 20px rgba(220, 38, 38, 0.4);
}

.btn-danger {
    background: var(--danger);
    color: white;
    box-shadow: 0 4px 15px rgba(239, 68, 68, 0.3);
}

.btn-danger:hover {
    background: #dc2626;
    transform: translateY(-2px);
    box-shadow: 0 6px 20px rgba(239, 68, 68, 0.4);
}

.btn-secondary {
    background: var(--get-Ip);
    color: white;
    border: none;
    box-shadow: 0 2px 8px rgba(5, 150, 105, 0.3);
}

.ip-list {
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 10px;
    margin-bottom: 16px;
    max-height: 200px;
    overflow-y: auto;
}

.ip-item {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 8px;
    margin-bottom: -3px;
    background: var(--bg-primary);
    border-radius: 6px;
    border: 1px solid var(--border);
}

.ip-item:hover {
    background: var(--bg-tertiary);
    transform: translateX(5px);
}

.ip-actions {
    display: flex;
    gap: 8px;
}

.subscription-row {
    display: flex;
    gap: 10px;
    align-items: center;
    margin-bottom: 15px;
}

.subscription-buttons {
    display: flex;
    gap: 8px;
    flex-shrink: 0;
}

.sub-btn {
    padding: 12px 16px;
    background: var(--get-Ip);
    color: var(--text);
    border: none;
    border-radius: 8px;
    font-size: 16px;
    font-weight: 600;
    cursor: pointer;
    display: flex;
    align-items: center;
    gap: 6px;
    height: 48px;
    white-space: nowrap;
    box-shadow: 0 2px 8px rgba(5, 150, 105, 0.3);
}

.sub-btn:hover {
    background: var(--primary);
    transform: translateY(-2px);
    box-shadow: 0 4px 15px rgba(220, 38, 38, 0.4);
}

.btn-success {
    background: var(--accent);
    color: white;
    box-shadow: 0 4px 15px rgba(22, 163, 74, 0.3);
    width: 100%;
    margin-top: 10px;
    padding: 15px;
    border: none;
    border-radius: 8px;
    font-size: 16px;
    font-weight: bold;
    cursor: pointer;
    text-align: center;
    display: block;
}

.btn-success:hover {
    background: #059669;
    transform: translateY(-2px);
    box-shadow: 0 6px 20px rgba(22, 163, 74, 0.4);
}

.generate-btn {
    white-space: nowrap;
    height: 48px;
    padding: 0 11px;
    background: var(--accent);
    color: white;
    border: none;
    border-radius: 8px;
    font-size: 16px;
    font-weight: 600;
    cursor: pointer;
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 8px;
}

.generate-btn:hover {
    background: #059669;
    transform: translateY(-2px);
    box-shadow: 0 6px 20px rgba(22, 163, 74, 0.4);
}

.generate-btn-trojan {
    background: #8b5cf6;
}

.generate-btn-trojan:hover {
    background: #7c3aed;
    box-shadow: 0 6px 20px rgba(139, 92, 246, 0.4);
}

.action-btn {
    padding: 10px 12px;
    border: none;
    border-radius: 6px;
    cursor: pointer;
    font-size: 14px;
    font-weight: 500;
}

.protocol-checkbox {
    width: 25px;
    height: 25px;
    accent-color: var(--primary);
    cursor: pointer;
}

.protocol-checkbox:checked {
    background-color: var(--primary);
}

.delete-btn {
    background: var(--danger);
    color: white;
}

.delete-btn:hover {
    background: #dc2626;
    transform: translateY(-1px);
    box-shadow: 0 4px 15px rgba(239, 68, 68, 0.4);
}

.status-bar {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 20px;
    background: var(--card-bg);
    border-radius: 12px;
    margin-top: 30px;
    border: 1px solid var(--border);
    box-shadow: var(--shadow);
}

.ip-display {
    display: flex;
    gap: 20px;
    align-items: center;
}

.ip-info {
    text-align: center;
}

.ip-label {
    font-size: 0.9rem;
    color: var(--text-light);
    margin-bottom: 4px;
}

.ip-value {
    font-weight: 600;
    font-family: 'Monaco', 'Consolas', monospace;
}

.theme-toggle {
    position: fixed;
    top: 30px;
    right: 30px;
    width: 60px;
    height: 60px;
    border-radius: 12px;
    background: none;
    border: none;
    color: white;
    font-size: 1.7rem;
    cursor: pointer;
    box-shadow: none;
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 1001;
    border: none;
}

.logout-btn {
    background: var(--danger);
    color: white;
    border: none;
    border-radius: 8px;
    font-size: 16px;
    font-weight: 600;
    cursor: pointer;
    padding: 16px 32px;
    display: block;
    width: 770px;
    max-width: 90%;
    margin: 20px auto 30px;
    text-align: center;
    box-shadow: 0 4px 15px rgba(239, 68, 68, 0.3);
}

.logout-btn:hover {
    background: #dc2626;
    transform: translateY(-2px);
    box-shadow: 0 6px 20px rgba(239, 68, 68, 0.4);
}

.qr-modal {
    display: none;
    position: fixed;
    top: 0;
    left: 0;
    width: 100%;
    height: 100%;
    background: rgba(0, 0, 0, 0.5);
    backdrop-filter: blur(5px);
    align-items: center;
    justify-content: center;
    z-index: 1000;
}

.qr-content {
    background: #ffffff;
    padding: 30px;
    border-radius: 16px;
    text-align: center;
    box-shadow: var(--shadow);
    border: 1px solid var(--border);
}

.message-overlay {
    position: fixed;
    top: 50%;
    left: 50%;
    transform: translate(-50%, -50%);
    z-index: 1000;
    padding: 15px 20px;
    border-radius: 8px;
    font-weight: 600;
    font-size: 16px;
    text-align: center;
    box-shadow: var(--shadow);
    width: auto;
    white-space: nowrap;
    backdrop-filter: blur(10px);
}

.message-success {
    background: var(--accent);
    color: white;
}

.message-error {
    background: var(--danger);
    color: white;
}

.protocol-container {
    display: flex;
    justify-content: center;
    gap: 300px;
    margin-top: 15px;
    flex-wrap: wrap;
    margin-bottom: 40px;
}

.protocol-item {
    display: flex;
    align-items: center;
    gap: 8px;
    cursor: pointer;
    font-size: 25px;
}

@media screen and (max-width: 768px) {
    body {
        padding: 0 !important;
        margin-left: 5px;
        margin-right: 9px;
        margin-top: 20px;
    }

    .protocol-item {
       font-size: 20px;
    }

    .protocol-checkbox {
    width: 20px;
    height: 20px;
    }

    .container {
        max-width: 100% !important;
        width: 100% !important;
        margin-left: 10px;
        margin-right: 10px;
        padding: 0 10px;
    }

    .accordion-title {
        display: flex;
        align-items: center;
        flex: 1;
        font-family: 'Inter', sans-serif;
        font-size: 19px;
        font-weight: 600;
    }

    .accordion-container {
        width: 100% !important;
        gap: 15px !important;
    }

    .accordion {
        width: 100% !important;
        max-width: 100% !important;
        margin: 2px 0 12px !important;
        border-radius: 16px;
        margin: 0 auto 10px;
    }

    .accordion-header {
        width: 100% !important;
        min-height: 81px !important;
        padding: 20px !important;
    }

    .accordion-content {
        width: 100% !important;
        max-width: 100% !important;
        padding: 0 5px 12px 5px !important;
        box-sizing: border-box !important;
    }

    #ipList > div {
        margin-bottom: 2px !important;
    }

    .ip-item {
        margin: 2px 0 !important;
        padding: 8px 6px !important;
        height: 33px;
    }

    .ip-list {
        padding: 5px !important;
        margin: 8px 0 !important;
    }

    .form-group small {
        font-size: 15px;
        font-family: 'Inter', sans-serif;
    }

    .ip-actions {
        width: auto !important;
        flex-shrink: 0 !important;
    }

    .action-btn {
        padding: 9px 8px !important;
        font-size: 12px !important;
        white-space: nowrap !important;
        width: auto !important;
        font-weight: 500;
    }

    .form-group {
        width: 100% !important;
        margin-bottom: 15px !important;
    }

    .form-input, .form-select, .form-textarea {
        width: 100% !important;
        max-width: 100% !important;
        box-sizing: border-box !important;
        padding: 12px 10px !important;
        font-size: 16px !important;
    }

    .btn, .btn-primary, .btn-danger, .btn-success, .btn-secondary {
        width: 100% !important;
        max-width: 100% !important;
        margin: 5px 0 !important;
        padding: 14px 12px !important;
        height: auto !important;
        min-height: 50px !important;
        font-size: 16px !important;
    }

    .ip-display {
        flex-direction: column !important;
        gap: 12px !important;
    }

    .ip-info {
        width: 100% !important;
    }

    .subscription-row {
        flex-direction: column !important;
        align-items: stretch !important;
        gap: 10px !important;
        width: 100% !important;
    }

    .subscription-buttons {
        flex-direction: column !important;
        gap: 8px !important;
        width: 100% !important;
    }

    .sub-btn[onclick="generateRandomUUID()"] {
        min-width: 100px !important;
        height: 45px !important;
    }

    .protocol-container {
        gap: 40px;
        justify-content: space-around;
        margin-bottom: 30px;
        margin-top: 30px;
    }

    .sub-btn {
        justify-content: center !important;
        height: 45px !important;
        font-size: 16px !important;
        background: var(--get-Ip);
    }

    .status-bar {
        flex-direction: column !important;
        gap: 12px !important;
        text-align: center !important;
        width: 100% !important;
        padding: 12px !important;
        margin: 15px 0 !important;
    }

    .export-btn {
        justify-content: center !important;
        height: 45px !important;
        font-size: 16px !important;
        background: var(--get-Ip);
    }

    .ip-display {
        flex-direction: column !important;
        gap: 8px !important;
        width: 100% !important;
    }

    .generate-btn {
        height: 45px !important;
        padding: 0 15px !important;
        font-size: 13px !important;
        min-width: 95px !important;
        border-radius: 8px !important;
    }

    .form-group > div[style*="display: flex"] {
        gap: 8px !important;
        align-items: center !important;
    }

    #uuid, #trojanPassword {
        font-size: 14px !important;
        height: 45px !important;
    }

    .panel-header {
        width: 100% !important;
        padding: 20px 12px !important;
        margin-bottom: 25px !important;
        border-radius: 16px;
        margin: 0 auto 20px;
    }

    .panel-title {
        font-size: 2.2rem !important;
        letter-spacing: 3px !important;
    }

    .theme-toggle {
        bottom: 20px !important;
        right: 20px !important;
        width: 50px !important;
        height: 50px !important;
        position: fixed !important;
        z-index: 1001 !important;
        border-radius: 10px !important;
    }

    .form-group > div[style*="display: flex"] {
        align-items: stretch !important;
    }

    .form-group .sub-btn[onclick="generateRandomUUID()"] {
        width: 95px !important;
        min-width: 95px !important;
        height: 45px !important;
        flex-shrink: 0 !important;
        font-size: 13px !important;
        border: none;
    }

    .logout-btn {
        width: 100% !important;
        max-width: 100% !important;
        padding: 14px !important;
        margin: 30px auto !important;
        height: 50px !important;
        font-size: 16px !important;
    }

    .add-ip-row {
        flex-direction: row !important;
        align-items: stretch !important;
        margin-top: 25px;
    }

    .add-btn {
        width: 10px !important;
        min-width: 80px !important;
        height: 45px;
    }

    .accordion:not(.active) .accordion-content {
        display: none !important;
    }

    .accordion.active .accordion-content {
        max-height: 1000vh;
        display: block !important;
        margin-top: 20px;
    }
}
    </style>
</head>
<body>
    <div class="panel-header">
        <div class="panel-title">Dragon</div>
    </div>

    <div class="accordion-container">
        <div class="accordion">
            <div class="accordion-header" onclick="toggleAccordion(this)">
                <div class="accordion-title">
                    <span class="accordion-icon">⚙️</span>
                    Configuration Settings
                </div>
                <span class="accordion-arrow">▼</span>
            </div>
            <div class="accordion-content">
                <div class="form-group">
                    <label class="form-label">🔑 UUID</label>
                    <div style="display: flex; gap: 10px; align-items: center;">
                        <input type="text" id="uuid" class="form-input" placeholder="Enter UUID" value="${escapeHtml(yourUUID)}">
                        <button type="button" onclick="generateNewUUID()" class="generate-btn">🎲 Generate</button>
                    </div>
                </div>
                 <div class="form-group">
                    <label class="form-label">🔐 Trojan Password</label>
                    <div style="display: flex; gap: 10px; align-items: center;">
                        <input type="text" id="trojanPassword" class="form-input" placeholder="Trojan password" value="${escapeHtml(trojanPassword)}" readonly>
                        <button type="button" onclick="generateTrojanPassword()" class="generate-btn generate-btn-trojan">🎲 Generate</button>
                    </div>
                    <small style="color: var(--text-light); display: block; margin-top: 5px;">
                        If empty, UUID will be used as password
                    </small>
                </div>

                           <button type="button" class="btn btn-success" onclick="saveConfiguration()" style="width: 100%; padding: 16px; font-size: 1.1rem;">
                    💾 Save Configuration
                </button>
            </div>
        </div>

        <div class="accordion">
            <div class="accordion-header" onclick="toggleAccordion(this)">
                <div class="accordion-title">
                    <span class="accordion-icon">🔗</span>
                    Subscription Links
                </div>
                <span class="accordion-arrow">▼</span>
            </div>
            <div class="accordion-content">
                <div class="form-group">
                    <h3 style="margin-bottom: 15px; font-weight: 400;">Subscription (Fragment)</h3>  
                    <div class="subscription-row">
                        <input type="text" id="subscription" class="form-input" value="${escapeHtml(baseUrl)}/${escapeHtml(subPath)}#Dragon_D" readonly>
                        <div class="subscription-buttons">
                            <button type="button" class="sub-btn" onclick="copyToClipboard('subscription')">📋 Copy</button>
                            <button type="button" class="sub-btn" onclick="openQR('subscription')">📱 QR</button>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    
        <div class="accordion">
            <div class="accordion-header" onclick="toggleAccordion(this)">
                <div class="accordion-title">
                    <span class="accordion-icon">🧩</span>
                    Fragment Settings
                </div>
                <span class="accordion-arrow">▼</span>
            </div>
            <div class="accordion-content">
                <div class="form-group">
                    <label class="form-label">Fragment (JSON)</label>
                    <textarea id="fragment-input" class="form-input" spellcheck="false" style="width: 100%; min-height: 240px; font-family: monospace; direction: ltr; text-align: left; resize: vertical;"></textarea>
                    <small style="color: var(--text-light); display: block; margin-top: 5px;">
                        All subscription configs use this fragment. Changes apply on the next subscription update.
                    </small>
                </div>
                <div style="display: flex; gap: 10px; align-items: baseline;">
                    <button type="button" class="btn btn-success" onclick="saveFragment()" style="flex: 1;">💾 Save Fragment</button>
                    <button type="button" class="btn btn-primary" onclick="resetFragment()" style="flex: 1;">↩️ Reset Default</button>
                </div>
            </div>
        </div>

        <div class="accordion">
            <div class="accordion-header" onclick="toggleAccordion(this)">
                <div class="accordion-title">
                    <span class="accordion-icon">🔐</span>
                    Change Password
                </div>
                <span class="accordion-arrow">▼</span>
            </div>
            <div class="accordion-content">
                <form id="changePasswordForm">
                    <div class="form-group">
                        <label class="form-label">Current Password</label>
                        <div style="position: relative;">
                            <input type="password" id="current-password" class="form-input" required style="padding-right: 50px;">
                            <button type="button" onclick="togglePassword('current-password')" style="position: absolute; right: 10px; top: 50%; transform: translateY(-50%); background: none; border: none; cursor: pointer; font-size: 17px;">🙈</button>
                        </div>
                    </div>
                    
                    <div class="form-group">
                        <label class="form-label">New Password</label>
                        <div style="position: relative;">
                            <input type="password" id="new-password" class="form-input" required style="padding-right: 50px;">
                            <button type="button" onclick="togglePassword('new-password')" style="position: absolute; right: 10px; top: 50%; transform: translateY(-50%); background: none; border: none; cursor: pointer; font-size: 17px;">🙈</button>
                        </div>
                    </div>
                    
                    <div class="form-group">
                        <label class="form-label">Confirm New Password</label>
                        <div style="position: relative;">
                            <input type="password" id="confirm-password" class="form-input" required style="padding-right: 50px;">
                            <button type="button" onclick="togglePassword('confirm-password')" style="position: absolute; right: 10px; top: 50%; transform: translateY(-50%); background: none; border: none; cursor: pointer; font-size: 17px;">🙈</button>
                        </div>
                    </div>
                    
                    <button type="button" class="btn btn-primary" onclick="changePassword()">Change Password</button>
                    <div id="password-change-message" style="margin-top: 15px;"></div>
                </form>
            </div>
        </div>
     </div>
    <button class="logout-btn" onclick="logout()">🚪 Logout</button>
    <button class="theme-toggle" id="themeToggle">🌙</button>

    <div class="qr-modal" id="qrModal" onclick="closeQR()">
        <div class="qr-content">
            <div id="qrcode"></div>
        </div>
    </div>

    <script src="https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js"></script>
    <script>
        let currentUUID = ${JSON.stringify(yourUUID)};

        function toggleAccordion(header) {
            const accordion = header.parentElement;
            const content = accordion.querySelector('.accordion-content');
            
            if (accordion.classList.contains('active')) {
                accordion.classList.remove('active');
            } else {
                accordion.classList.add('active');
            }
        }

        const themeToggle = document.getElementById('themeToggle');
        themeToggle.addEventListener('click', () => {
            document.body.classList.toggle('dark-mode');
            const isDark = document.body.classList.contains('dark-mode');
            themeToggle.textContent = isDark ? '🌞' : '🌙';
            localStorage.setItem('darkMode', isDark ? 'enabled' : 'disabled');
        });

        if (localStorage.getItem('darkMode') === 'enabled') {
            document.body.classList.add('dark-mode');
            themeToggle.textContent = '🌞';
        }
  
        function showMessage(message, type) {
            const existingMessages = document.querySelectorAll('.message-overlay');
            existingMessages.forEach(msg => msg.remove());
            
            const messageDiv = document.createElement('div');
            
            if (type === 'success') {
                messageDiv.className = 'message-overlay message-success';
            } else {
                messageDiv.className = 'message-overlay message-error';
            }
            
            messageDiv.textContent = message;
            document.body.appendChild(messageDiv);
            
            setTimeout(() => {
                if (messageDiv.parentNode) {
                    messageDiv.parentNode.removeChild(messageDiv);
                }
            }, 2000);
        }

        function copyToClipboard(elementId) {
            const textToCopy = document.getElementById(elementId).value;
            navigator.clipboard.writeText(textToCopy)
                .then(() => showMessage('✅ Copied to clipboard!', 'success'))
                .catch(err => showMessage('❌ Failed to copy text: ' + err, 'error'));
        }

        function openQR(elementId) {
            const url = document.getElementById(elementId).value;
            if (!url) {
                showMessage('❌ No URL to generate QR code', 'error');
                return;
            }
            
            const qrModal = document.getElementById('qrModal');
            const qrcodeDiv = document.getElementById('qrcode');
            qrcodeDiv.innerHTML = '';
            
            new QRCode(qrcodeDiv, {
                text: url,
                width: 256,
                height: 256,
                colorDark: "#000000",
                colorLight: "#ffffff",
                correctLevel: QRCode.CorrectLevel.H
            });
            
            qrModal.style.display = 'flex';
        }

        function closeQR() {
            const qrModal = document.getElementById('qrModal');
            qrModal.style.display = 'none';
        }

        function generateNewUUID() {
                const newUUID = generateUUID();
                document.getElementById('uuid').value = newUUID;
                showMessage('✅ UUID generated', 'success');
            }

        function generateUUID() {
            return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
                const r = Math.random() * 16 | 0;
                const v = c == 'x' ? r : (r & 0x3 | 0x8);
                return v.toString(16);
            });
        }

            

            function generateTrojanPassword() {
                const password = generateRandomPassword();
                document.getElementById('trojanPassword').value = password;
                showMessage('✅ Trojan password generated', 'success');
            }

            function generateRandomPassword() {
                const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
                let password = '';
                for (let i = 0; i < 16; i++) {
                    password += chars.charAt(Math.floor(Math.random() * chars.length));
                }
                return password;
            }

        function togglePassword(inputId) {
            const input = document.getElementById(inputId);
            const button = input.parentNode.querySelector('button');
            
            if (input.type === 'password') {
                input.type = 'text';
                button.innerHTML = '🙉';
            } else {
                input.type = 'password';
                button.innerHTML = '🙈';
            }
        }

        async function changePassword() {
                const currentPassword = document.getElementById('current-password').value;
                const newPassword = document.getElementById('new-password').value;
                const confirmPassword = document.getElementById('confirm-password').value;

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
                        showPasswordMessage('✅ Password changed successfully!', 'success');
                        document.getElementById('changePasswordForm').reset();
                    } else {
                        showPasswordMessage('❌ ' + (result.error || 'Error changing password'), 'error');
                    }
                } catch (error) {
                    showPasswordMessage('❌ Network error: ' + error.message, 'error');
                }

                return false;
            }

function showPasswordMessage(message, type) {
            const existingMessages = document.querySelectorAll('.message-overlay');
            existingMessages.forEach(msg => msg.remove());
            
            const messageDiv = document.createElement('div');
            
            if (type === 'success') {
                messageDiv.className = 'message-overlay message-success';
            } else {
                messageDiv.className = 'message-overlay message-error';
            }
            
            messageDiv.textContent = message;
            document.body.appendChild(messageDiv);
            
            setTimeout(() => {
                if (messageDiv.parentNode) {
                    messageDiv.parentNode.removeChild(messageDiv);
                }
            }, 3000);
        }

        function logout() {
            document.cookie = "session_token=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;";
            window.location.href = '/logout';
        }

        async function loadFragment() {
            try {
                const response = await fetch('/fragment-config', { cache: 'no-store' });
                if (!response.ok) throw new Error('HTTP ' + response.status);
                const data = await response.json();
                document.getElementById('fragment-input').value = JSON.stringify(data.config, null, 2);
            } catch (error) {
                showMessage('❌ Failed to load fragment: ' + error.message, 'error');
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

async function saveConfiguration() {
    const uuid = document.getElementById('uuid').value;
    const trojanPassword = document.getElementById('trojanPassword').value;
    
    if (!isValidUUID(uuid)) {
        showMessage('❌ Please enter a valid UUID', 'error');
        return;
    }
    
    try {
        const uuidResponse = await fetch('/update-uuid?uuid=' + encodeURIComponent(uuid));
        if (!uuidResponse.ok) {
            throw new Error('Error saving UUID');
        }
        
        const trojanResponse = await fetch('/update-trojan-password?password=' + encodeURIComponent(trojanPassword));
        if (!trojanResponse.ok) {
            throw new Error('Error saving Trojan password');
        }
        
        showMessage('✅ Configuration saved successfully!', 'success');
        
    } catch (error) {
        showMessage('❌ Error saving configuration: ' + error.message, 'error');
    }
}

function isValidUUID(uuid) {
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    return uuidRegex.test(uuid);
}

loadFragment();
        </script>
    </body>
</html>`;

    return new Response(html, {
        status: 200,
        headers: {
            'Content-Type': 'text/html;charset=utf-8',
            'Cache-Control': 'no-cache, no-store, must-revalidate',
        },
    });
}