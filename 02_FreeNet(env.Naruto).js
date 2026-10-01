import { connect } from "cloudflare:sockets";

const CIPHER_SUITES = 'TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256:TLS_AES_128_GCM_SHA256:TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA:TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256:TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256';

const DEFAULT_FRAGMENT = {
    tcp: [
        { type: 'fragment', settings: { packets: 'tlshello', lengths: ['0', '104', '1'], delays: ['0'], maxSplit: '0' } },
        { type: 'fragment', settings: { packets: '1-1', lengths: ['114', '1'], delays: ['1'], maxSplit: '11' } },
    ],
};

const MAX_LOGIN_ATTEMPTS = 5;
const LOGIN_WINDOW_MS = 15 * 60 * 1000;

async function checkAuth(env, req) {
  try {
    const cookieHeader = req.headers.get("Cookie");
    let sessionToken;

    if (cookieHeader) {
      const cookies = Object.fromEntries(
        cookieHeader.split(";").map((c) => {
          const idx = c.indexOf("=");
          const k = c.slice(0, idx).trim();
          const v = idx >= 0 ? c.slice(idx + 1).trim() : "";
          return [k, v];
        })
      );
      sessionToken = cookies.session_token;
    }

    if (!sessionToken) {
      const auth =
        req.headers.get("Authorization") || req.headers.get("authorization");
      if (auth && auth.startsWith("Bearer ")) {
        sessionToken = auth.slice(7).trim();
      }
    }

    if (!sessionToken) return false;

    const storedToken = await env.Naruto.get("session_token");
    return sessionToken === storedToken;
  } catch (error) {
    return false;
  }
}

async function setSessionToken(env, token) {
  await env.Naruto.put("session_token", token);
}

async function clearSessionToken(env) {
  await env.Naruto.delete("session_token");
}

async function checkRateLimit(env, ip) {
  const key = `rate_limit_${ip}`;
  const attempts = await env.Naruto.get(key);
  if (attempts && parseInt(attempts) >= MAX_LOGIN_ATTEMPTS) {
    throw new Error("Too many failed attempts. Try again in 15 minutes.");
  }
  return attempts ? parseInt(attempts) : 0;
}

async function incrementRateLimit(env, ip) {
  const key = `rate_limit_${ip}`;
  const current = await env.Naruto.get(key);
  const newCount = current ? parseInt(current) + 1 : 1;
  await env.Naruto.put(key, newCount.toString(), {
    expirationTtl: LOGIN_WINDOW_MS / 1000,
  });
  return newCount;
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
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
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
                box-shadow: 0 20px 40px rgba(0, 0, 0, 0.1);
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
                transition: all 0.3s ease;
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
            
            @media (max-width: 480px) {
                .setup-card {
                    padding: 30px 20px;
                }
                
                .setup-title {
                    font-size: 1.5rem;
                }
            }
        </style>
    </head>
    <body>
        <div class="setup-card">
            <div class="setup-icon">🔐</div>
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
      "Content-Type": "text/html; charset=utf-8",
    },
  });
}

function showLoginPage(error = "") {
  const html = `<!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>🗽FreeNet</title>
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
            }
            
            .login-card {
                background: rgba(255, 255, 255, 0.95);
                backdrop-filter: blur(10px);
                padding: 40px;
                border-radius: 12px;
                box-shadow: 0px 0px 15px rgba(0, 0, 0, 0.25);
                max-width: 400px;
                width: 100%;
                text-align: center;
                border: 2px solid #627286ff
            }
            
            .login-icon {
                font-size: 2rem;
                margin-bottom: 20px;
                position: absolute;
                margin-left: 75px;
                margin-top: -5px;
            }
            
            .login-title {
                color: #2d3748;
                margin-bottom: 30px;
                font-size: 1.8rem;
                font-weight: 700;
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
                border: 2px solid #6989b5;
                border-radius: 5px;
                font-size: 16px;
                transition: all 0.3s ease;
            }
            
            input:focus {
                outline: none;
                border-color: #667eea;
                box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
            }
            
            .login-btn {
                width: 100%;
                padding: 15px;
                background: linear-gradient(135deg, #667eea, #764ba2);
                color: white;
                border: none;
                border-radius: 8px;
                font-size: 16px;
                font-weight: 600;
                cursor: pointer;
                transition: transform 0.2s ease;
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
            
            @media (max-width: 480px) {
                  body {
                padding: 0 !important; margin-left: 20px; margin-right: 20px; margin-top: -30px;
                 }

                .login-card {
                    padding: 30px 20px;
                }
                
                .login-title {
                    font-size: 1.5rem;
                }
            }
        </style>
    </head>
    <body>
        <div class="login-card">
            <h1 class="login-title">WELCOME</h1>
            ${error ? `<div class="error-message">${error}</div>` : ""}
            <form method="POST" action="/login">
                <div class="form-group" style="position: relative;">
                    <label for="password">Password:</label>
                    <input type="password" id="password" name="password" required style="padding-right: 50px;">
                    <button type="button" onclick="togglePassword('password')" style="position: absolute; right: 10px; top: 50%; background: none; border: none; cursor: pointer; font-size: 18px;">🙈</button>                </div>
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
      "Content-Type": "text/html; charset=utf-8",
    },
  });
}

function generateRandomPath() {
  const chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  let result = "";
  for (let i = 0; i < 12; i++) {
    result += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return encodeURIComponent(`${result}?ed=2048`);
}

async function MainConfig(env) {
  const config = await loadFromKV(env);

  globalThis.uzerID = config.custom_uuid || "";
  globalThis.UzKey = globalThis.uzerID;
  globalThis.qrexyIP = atob("Y2lwLnRyb25iYW5rLnNpdGU=");

  if (!globalThis.UzKey) {
    globalThis.AccessAdvancedConfig = "panel";
  }
}

function WebConfig() {
  globalThis.AccessSubscription = "_SubscriptionURL_";
  globalThis.AccessAdvancedConfig = "_AdvancedConfigURL_";
  globalThis.fpaths = "js,css,assets,wp-content,themes,app,cdn,jquery,live";
  globalThis.CleanIPDomain = "\u0074\u0069\u006D\u0065\u002E\u0069\u0073";
  globalThis.ConfigName = "FreeNet";
}

async function saveToKV(env, configData) {
  try {
    await env.Naruto.put("custom_config", JSON.stringify(configData));
    return { success: true };
  } catch (error) {
    return { success: false, error: error.message };
  }
}

async function loadFromKV(env) {
  const defaults = {
    custom_uuid: globalThis.uzerID,
  };

  try {
    const data = await env.Naruto.get("custom_config", "json");
    const merged = Object.assign({}, defaults, data || {});

    return merged;
  } catch (error) {
    return defaults;
  }
}

async function getFragmentConfig(env) {
    try {
        const raw = await env.Naruto.get('fragment_config');
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
            await env.Naruto.put('fragment_config', JSON.stringify(config));
            return json({ success: true, config });
        }

        if (request.method === 'DELETE') {
            await env.Naruto.delete('fragment_config');
            return json({ success: true, config: DEFAULT_FRAGMENT });
        }

        return json({ error: 'Method not allowed' }, 405);
    } catch (error) {
        return json({ error: 'Server error: ' + error.message }, 500);
    }
}

async function handleChangePassword(request, env) {
  try {
    if (!(await checkAuth(env, request))) {
      return new Response(JSON.stringify({ error: "Unauthorized" }), {
        status: 401,
        headers: { "Content-Type": "application/json" },
      });
    }

    const { currentPassword, newPassword } = await request.json();
    const storedPassword = await env.Naruto.get("admin_password");

    if (currentPassword !== storedPassword) {
      return new Response(
        JSON.stringify({ error: "Current password is incorrect" }),
        {
          status: 400,
          headers: { "Content-Type": "application/json" },
        }
      );
    }

    await env.Naruto.put("admin_password", newPassword);

    return new Response(JSON.stringify({ success: true }), {
      status: 200,
      headers: { "Content-Type": "application/json" },
    });
  } catch (error) {
    return new Response(
      JSON.stringify({ error: "Server error: " + error.message }),
      {
        status: 500,
        headers: { "Content-Type": "application/json" },
      }
    );
  }
}

export default {
  async fetch(request, env) {
    try {
      await MainConfig(env);
      const rawProxy = env.PROXYIP || globalThis.qrexyIP || '';
      globalThis.CLxIPs = rawProxy
          .split(',')
          .map((s) => s.trim())
          .filter(Boolean);
          if (globalThis.CLxIPs.length === 0) {
              globalThis.CLxIPs = [
                  'cip.tronbank.site',
                  'di.nscl.ir:443',
                  'tr.diam4.ggff.net:443'
              ];
          }

      const url = new URL(request.url);
      globalThis.pathName = url.pathname;

      const hasPassword = await env.Naruto.get("admin_password");

      if (!hasPassword) {
        if (globalThis.pathName === "/setup" && request.method === "POST") {
          const formData = await request.formData();
          const password = formData.get("password");
          const confirmPassword = formData.get("confirmPassword");

          if (!password || !confirmPassword) {
            return new Response("Both password fields are required", {
              status: 400,
            });
          }

          if (password !== confirmPassword) {
            return new Response("Passwords do not match", { status: 400 });
          }

          await env.Naruto.put("admin_password", password);

          const headers = new Headers();
          headers.append("Location", "/login");
          return new Response(null, { status: 302, headers });
        }

        if (globalThis.pathName === "/setup" || globalThis.pathName === "/") {
          return showSetupPage();
        }

        const headers = new Headers();
        headers.append("Location", "/setup");
        return new Response(null, { status: 302, headers });
      }

      if (!globalThis.UzKey || !isValidUUID(globalThis.UzKey)) {
        const allowedPaths = [
          "/panel",
          `/${globalThis.AccessAdvancedConfig}`,
          "/save-custom-config",
          "/load-custom-config",
          "/login",
        ];
        if (!allowedPaths.includes(globalThis.pathName)) {
          throw new Error(`First register the UID.`);
        }
      }

      const upgradeHeader = request.headers.get("Upgrade");
      if (!upgradeHeader || upgradeHeader !== "websocket") {
        WebConfig();
        globalThis.hostName = request.headers.get("Host");
        if (
          globalThis.AccessAdvancedConfig ==
          "_" + "AdvancedConfigURL" + "_"
        ) {
          globalThis.AccessAdvancedConfig = globalThis.UzKey;
        }
        if (globalThis.AccessSubscription == "_" + "SubscriptionURL" + "_") {
          globalThis.AccessSubscription = "sub";
        }
        const GetParams = new URLSearchParams(url.search);
        globalThis.GetPath = GetParams.get("path");
        globalThis.CnfgName = globalThis.hostName.split(".")[0];

        if (globalThis.pathName === "/" && hasPassword) {
          const headers = new Headers();
          headers.append("Location", "/login");
          return new Response(null, { status: 302, headers });
        }

        const protectedRoutes = [
          "/panel",
          "/save-custom-config",
          "/load-custom-config",
          "/fragment-config",
        ];
        if (protectedRoutes.includes(globalThis.pathName)) {
          if (!(await checkAuth(env, request))) {
            const headers = new Headers();
            headers.append("Location", "/login");
            return new Response(null, { status: 302, headers });
          }
        }

        switch (globalThis.pathName) {
          case "/login":
            if (request.method === "POST") {
              const clientIP =
                request.headers.get("CF-Connecting-IP") || "unknown";

              try {
                await checkRateLimit(env, clientIP);
              } catch (rateError) {
                return showLoginPage(rateError.message);
              }

              const formData = await request.formData();
              const password = formData.get("password");
              const storedPassword = await env.Naruto.get("admin_password");

              if (password === storedPassword) {
                await env.Naruto.delete(`rate_limit_${clientIP}`);

                const sessionToken = "logged_in_" + Date.now();
                await setSessionToken(env, sessionToken);

                const headers = new Headers();
                headers.append("Location", "/panel");
                headers.append(
                  "Set-Cookie",
                  `session_token=${sessionToken}; Path=/; HttpOnly; SameSite=Strict; Secure`
                );
                return new Response(null, { status: 302, headers });
              } else {
                const newAttempts = await incrementRateLimit(env, clientIP);
                let errorMessage = `Invalid password (${newAttempts}/${MAX_LOGIN_ATTEMPTS})`;

                if (newAttempts >= MAX_LOGIN_ATTEMPTS) {
                  errorMessage =
                    "Too many failed attempts. Account locked for 15 minutes";
                }

                return showLoginPage(errorMessage);
              }
            } else {
              const url = new URL(request.url);
              const error = url.searchParams.get("error") || "";
              return showLoginPage(error);
            }
          case "/logout":
            await clearSessionToken(env);
            const headers = new Headers();
            headers.append("Location", "/login");
            headers.append(
              "Set-Cookie",
              "session_token=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT"
            );
            return new Response(null, { status: 302, headers });
          case "/panel":
            return await AdvancedConfig();
          case `/${globalThis.AccessSubscription}`:
            return await getVVConfig(env);
          case `/${globalThis.AccessAdvancedConfig}`:
            return await AdvancedConfig();
          case `/${globalThis.AccessSubscription}`:
            return await getVVConfig(env);
          case "/save-custom-config":
            return await handleSaveConfig(request, env);
          case "/load-custom-config":
            return await handleLoadConfig(env);
          case "/change-password":
            return await handleChangePassword(request, env);
          case "/fragment-config":
            return await handleFragmentApi(request, env);
          default:
            return new Response("Not found", { status: 404 });
        }
      } else {
        return await vOWSHandler(request, env);
      }
    } catch (err) {
      /** @type {Error} */ let e = err;
      return new Response(e.toString());
    }
  },
};

async function vOWSHandler(request, env) {
  const webSocketPair = new WebSocketPair();
  const [client, webSocket] = Object.values(webSocketPair);

  webSocket.accept();

  const config = await loadFromKV(env);
  const currentUUID = config.custom_uuid || globalThis.uzerID;

  let address = "";
  let portWithRandomLog = "";
  const log = (
    /** @type {string} */ info,
    /** @type {string | undefined} */ event
  ) => {
    console.log(`[${address}:${portWithRandomLog}] ${info}`, event || "");
  };
  const earlyDataHeader = request.headers.get("sec-websocket-protocol") || "";

  const readableWebSocketStream = mkRdWSktStrm(
    webSocket,
    earlyDataHeader,
    log,
    currentUUID
  );
  let remoteSocketWapper = {
    value: null,
  };
  let udpStreamWrite = null;
  let isDns = false;

  readableWebSocketStream
    .pipeTo(
      new WritableStream({
        async write(chunk, controller) {
          if (isDns && udpStreamWrite) {
            return udpStreamWrite(chunk);
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
            portRemote = 443,
            addressRemote = "",
            rawDataIndex,
            vVvVersion = new Uint8Array([0, 0]),
            isUDP,
          } = prssVvHeader(chunk, currentUUID);
          address = addressRemote;
          portWithRandomLog = `${portRemote}--${Math.random()} ${
            isUDP ? "udp " : "tcp "
          } `;
          if (hasError) {
            throw new Error(message);
            return;
          }
          if (isUDP) {
            if (portRemote === 53) {
              isDns = true;
            } else {
              throw new Error("UDP use only enable for DNS which is port 53");
              return;
            }
          }
          const vvResponseHeader = new Uint8Array([vVvVersion[0], 0]);
          const rawClientData = chunk.slice(rawDataIndex);

          if (isDns) {
            const { write } = await hUOBnd(webSocket, vvResponseHeader, log);
            udpStreamWrite = write;
            udpStreamWrite(rawClientData);
            return;
          }
          hTOBound(
            remoteSocketWapper,
            addressRemote,
            portRemote,
            rawClientData,
            webSocket,
            vvResponseHeader,
            log
          );
        },
        close() {},
        abort(reason) {},
      })
    )
    .catch((err) => {});

  return new Response(null, {
    status: 101,
    webSocket: client,
  });
}

async function hTOBound(
  remoteSocket,
  addressRemote,
  portRemote,
  rawClientData,
  webSocket,
  vvResponseHeader,
  log
) {
  async function connectAndWrite(address, port) {
    if (
      /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?).){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(
        address
      )
    )
      address = `${atob("d3d3Lg==")}${address}${atob("LnNzbGlwLmlv")}`;
    const tcpSocket = connect({
      hostname: address,
      port: port,
    });
    remoteSocket.value = tcpSocket;
    const writer = tcpSocket.writable.getWriter();
    await writer.write(rawClientData);
    writer.releaseLock();
    return tcpSocket;
  }

  const pnlPxIP = globalThis.pathName.split("/")[2];
  const pnlPxIPs = pnlPxIP ? atob(pnlPxIP).split(",") : null;
  const pool = pnlPxIPs && pnlPxIPs.length > 0
    ? pnlPxIPs
    : (globalThis.CLxIPs && globalThis.CLxIPs.length > 0
        ? globalThis.CLxIPs
        : []);

  async function tryPool(index) {
    if (index >= pool.length) {
      return tryNAT64();
    }
    try {
      const tcpSocket = await connectAndWrite(pool[index], portRemote);
      tcpSocket.closed
        .catch((error) => {})
        .finally(() => {
          safeCloseWebSocket(webSocket);
        });
      rmtSkt2WS(tcpSocket, webSocket, vvResponseHeader, () => tryPool(index + 1), log);
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
        .catch((error) => {})
        .finally(() => {
          safeCloseWebSocket(webSocket);
        });
      rmtSkt2WS(tcpSocket, webSocket, vvResponseHeader, null, log);
    } catch (err) {
      console.log(`NAT64 fallback error:`, err.message);
      safeCloseWebSocket(webSocket);
    }
  }

  try {
    const tcpSocket = await connectAndWrite(addressRemote, portRemote);
    rmtSkt2WS(tcpSocket, webSocket, vvResponseHeader, () => tryPool(0), log);
  } catch (err) {
    console.log(`Direct connection to ${addressRemote}:${portRemote} failed, trying pool...`);
    await tryPool(0);
  }
}

function mkRdWSktStrm(webSocketServer, earlyDataHeader, log, currentUUID) {
  let readableStreamCancel = false;
  const stream = new ReadableStream({
    start(controller) {
      webSocketServer.addEventListener("message", (event) => {
        if (readableStreamCancel) {
          return;
        }
        const message = event.data;
        controller.enqueue(message);
      });

      webSocketServer.addEventListener("close", () => {
        safeCloseWebSocket(webSocketServer);
        if (readableStreamCancel) {
          return;
        }
        controller.close();
      });
      webSocketServer.addEventListener("error", (err) => {
        controller.error(err);
      });
      const { earlyData, error } = base64ToArrayBuffer(earlyDataHeader);
      if (error) {
        controller.error(error);
      } else if (earlyData) {
        controller.enqueue(earlyData);
      }
    },

    pull(controller) {},
    cancel(reason) {
      if (readableStreamCancel) {
        return;
      }
      readableStreamCancel = true;
      safeCloseWebSocket(webSocketServer);
    },
  });

  return stream;
}

function prssVvHeader(vVvBuffer, UrKey) {
  if (vVvBuffer.byteLength < 24) {
    return {
      hasError: true,
      message: "invalid data",
    };
  }
  const version = new Uint8Array(vVvBuffer.slice(0, 1));
  let isValidUser = false;
  let isUDP = false;
  if (stringify(new Uint8Array(vVvBuffer.slice(1, 17))) === UrKey) {
    isValidUser = true;
  }
  if (!isValidUser) {
    return {
      hasError: true,
      message: "invalid user",
    };
  }

  const optLength = new Uint8Array(vVvBuffer.slice(17, 18))[0];

  const command = new Uint8Array(
    vVvBuffer.slice(18 + optLength, 18 + optLength + 1)
  )[0];

  if (command === 1) {
  } else if (command === 2) {
    isUDP = true;
  } else {
    return {
      hasError: true,
      message: `command ${command} is not support, command 01-tcp,02-udp,03-mux`,
    };
  }
  const portIndex = 18 + optLength + 1;
  const portBuffer = vVvBuffer.slice(portIndex, portIndex + 2);
  const portRemote = new DataView(portBuffer).getUint16(0);

  let addressIndex = portIndex + 2;
  const addressBuffer = new Uint8Array(
    vVvBuffer.slice(addressIndex, addressIndex + 1)
  );

  const addressType = addressBuffer[0];
  let addressLength = 0;
  let addressValueIndex = addressIndex + 1;
  let addressValue = "";
  switch (addressType) {
    case 1:
      addressLength = 4;
      addressValue = new Uint8Array(
        vVvBuffer.slice(addressValueIndex, addressValueIndex + addressLength)
      ).join(".");
      break;
    case 2:
      addressLength = new Uint8Array(
        vVvBuffer.slice(addressValueIndex, addressValueIndex + 1)
      )[0];
      addressValueIndex += 1;
      addressValue = new TextDecoder().decode(
        vVvBuffer.slice(addressValueIndex, addressValueIndex + addressLength)
      );
      break;
    case 3:
      addressLength = 16;
      const dataView = new DataView(
        vVvBuffer.slice(addressValueIndex, addressValueIndex + addressLength)
      );
      const ipv6 = [];
      for (let i = 0; i < 8; i++) {
        ipv6.push(dataView.getUint16(i * 2).toString(16));
      }
      addressValue = ipv6.join(":");
      break;
    default:
      return {
        hasError: true,
        message: `invild  addressType is ${addressType}`,
      };
  }
  if (!addressValue) {
    return {
      hasError: true,
      message: `addressValue is empty, addressType is ${addressType}`,
    };
  }

  return {
    hasError: false,
    addressRemote: addressValue,
    addressType,
    portRemote,
    rawDataIndex: addressValueIndex + addressLength,
    vVvVersion: version,
    isUDP,
  };
}

async function rmtSkt2WS(
  remoteSocket,
  webSocket,
  vvResponseHeader,
  retry,
  log
) {
  let remoteChunkCount = 0;
  let chunks = [];
  let vVvHeader = vvResponseHeader;
  let hasIncomingData = false;
  await remoteSocket.readable
    .pipeTo(
      new WritableStream({
        start() {},

        async write(chunk, controller) {
          hasIncomingData = true;
          if (webSocket.readyState !== WS_READY_STATE_OPEN) {
            controller.error("webSocket.readyState is not open, maybe close");
          }
          if (vVvHeader) {
            webSocket.send(await new Blob([vVvHeader, chunk]).arrayBuffer());
            vVvHeader = null;
          } else {
            webSocket.send(chunk);
          }
        },
        close() {},
        abort(reason) {
          console.error(`rmtConct!.redbl X`, reason);
        },
      })
    )
    .catch((error) => {
      console.error(`rmtSkt2WS has exception `, error.stack || error);
      safeCloseWebSocket(webSocket);
    });

  if (hasIncomingData === false && retry) {
    retry();
  }
}

function base64ToArrayBuffer(base64Str) {
  if (!base64Str) {
    return { error: null };
  }
  try {
    base64Str = base64Str.replace(/-/g, "+").replace(/_/g, "/");
    const decode = atob(base64Str);
    const arryBuffer = Uint8Array.from(decode, (c) => c.charCodeAt(0));
    return { earlyData: arryBuffer.buffer, error: null };
  } catch (error) {
    return { error };
  }
}

function isValidUUID(uuid) {
  const uuidRegex =
    /^[0-9a-f]{8}-[0-9a-f]{4}-[4][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  return uuidRegex.test(uuid);
}

const WS_READY_STATE_OPEN = 1;
const WS_READY_STATE_CLOSING = 2;

function safeCloseWebSocket(socket) {
  try {
    if (
      socket.readyState === WS_READY_STATE_OPEN ||
      socket.readyState === WS_READY_STATE_CLOSING
    ) {
      socket.close();
    }
  } catch (error) {
    console.error("loadingLargeFile error", error);
  }
}

const byteToHex = [];
for (let i = 0; i < 256; ++i) {
  byteToHex.push((i + 256).toString(16).slice(1));
}
function unsafeStringify(arr, offset = 0) {
  return (
    byteToHex[arr[offset + 0]] +
    byteToHex[arr[offset + 1]] +
    byteToHex[arr[offset + 2]] +
    byteToHex[arr[offset + 3]] +
    "-" +
    byteToHex[arr[offset + 4]] +
    byteToHex[arr[offset + 5]] +
    "-" +
    byteToHex[arr[offset + 6]] +
    byteToHex[arr[offset + 7]] +
    "-" +
    byteToHex[arr[offset + 8]] +
    byteToHex[arr[offset + 9]] +
    "-" +
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
  if (!isValidUUID(uuid)) {
    throw TypeError("Stringified UUID is invalid");
  }
  return uuid;
}

async function hUOBnd(webSocket, vvResponseHeader, log) {
  let isvVvHeaderSent = false;
  const transformStream = new TransformStream({
    start(controller) {},
    transform(chunk, controller) {
      for (let index = 0; index < chunk.byteLength; ) {
        const lengthBuffer = chunk.slice(index, index + 2);
        const udpPakcetLength = new DataView(lengthBuffer).getUint16(0);
        const udpData = new Uint8Array(
          chunk.slice(index + 2, index + 2 + udpPakcetLength)
        );
        index = index + 2 + udpPakcetLength;
        controller.enqueue(udpData);
      }
    },
    flush(controller) {},
  });

  transformStream.readable
    .pipeTo(
      new WritableStream({
        async write(chunk) {
          const dohServers = [
            "https://1.1.1.1/dns-query",
            "https://dns.google/dns-query",
            "https://dns.quad9.net/dns-query",
            "https://doh.opendns.com/dns-query",
          ];

          let resp;
          let lastError;

          for (const dohServer of dohServers) {
            try {
              resp = await fetch(dohServer, {
                method: "POST",
                headers: {
                  "content-type": "application/dns-message",
                },
                body: chunk,
              });

              if (resp.ok) {
                break;
              } else {
                throw new Error(`HTTP ${resp.status}`);
              }
            } catch (error) {
              lastError = error;
              console.log(`DoH server ${dohServer} failed, trying next...`);
              continue;
            }
          }

          if (!resp || !resp.ok) {
            throw new Error(`All DoH servers failed: ${lastError?.message}`);
          }

          const dnsQueryResult = await resp.arrayBuffer();
          const udpSize = dnsQueryResult.byteLength;
          const udpSizeBuffer = new Uint8Array([
            (udpSize >> 8) & 0xff,
            udpSize & 0xff,
          ]);
          if (webSocket.readyState === WS_READY_STATE_OPEN) {
            if (isvVvHeaderSent) {
              webSocket.send(
                await new Blob([udpSizeBuffer, dnsQueryResult]).arrayBuffer()
              );
            } else {
              webSocket.send(
                await new Blob([
                  vvResponseHeader,
                  udpSizeBuffer,
                  dnsQueryResult,
                ]).arrayBuffer()
              );
              isvVvHeaderSent = true;
            }
          }
        },
      })
    )
    .catch((error) => {});

  const writer = transformStream.writable.getWriter();

  return {
    write(chunk) {
      writer.write(chunk);
    },
  };
}

async function resolveDNS(domain) {
  const dohServers = [
    "https://cloudflare-dns.com/dns-query",
    "https://dns.google/dns-query",
    "https://dns.quad9.net/dns-query",
    "https://doh.opendns.com/dns-query",
  ];

  let lastError;

  for (let dohURL of dohServers) {
    try {
      const dohURLv4 = `${dohURL}?name=${encodeURIComponent(domain)}&type=A`;
      const dohURLv6 = `${dohURL}?name=${encodeURIComponent(domain)}&type=AAAA`;

      const [ipv4Response, ipv6Response] = await Promise.all([
        fetch(dohURLv4, {
          headers: { accept: "application/dns-json" },
          signal: AbortSignal.timeout(5000),
        }),
        fetch(dohURLv6, {
          headers: { accept: "application/dns-json" },
          signal: AbortSignal.timeout(5000),
        }),
      ]);

      if (!ipv4Response.ok || !ipv6Response.ok) {
        throw new Error(
          `HTTP error: IPv4 ${ipv4Response.status}, IPv6 ${ipv6Response.status}`
        );
      }

      const ipv4Addresses = await ipv4Response.json();
      const ipv6Addresses = await ipv6Response.json();

      const ipv4 = ipv4Addresses.Answer
        ? ipv4Addresses.Answer.map((record) => record.data)
        : [];
      const ipv6 = ipv6Addresses.Answer
        ? ipv6Addresses.Answer.map((record) => record.data)
        : [];

      if (ipv4.length > 0 || ipv6.length > 0) {
        return { ipv4, ipv6 };
      } else {
        throw new Error("No valid IP addresses found in response");
      }
    } catch (error) {
      lastError = error;
      console.log(
        `DNS server ${dohURL} failed: ${error.message}, trying next...`
      );
      continue;
    }
  }

  throw new Error(
    `All DNS servers failed for domain ${domain}. Last error: ${lastError?.message}`
  );
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

async function AdvancedConfig() {
  const AdvancedPage = `<!DOCTYPE html>
  <html lang="en">
  <head>
      <meta charset="UTF-8">
      <meta name="viewport" content="width=device-width, initial-scale=1.0">
      <title>🗽 FreeNet</title>
      <link rel="manifest" href="/manifest.json">
      <link href="https://fonts.googleapis.com/css2?family=Orbitron:wght@700&family=Audiowide&family=Rajdhani:wght@700&family=Exo+2:wght@700&display=swap" rel="stylesheet">
      <meta name="mobile-web-app-capable" content="yes">
      <meta name="apple-mobile-web-app-capable" content="yes">
      <meta name="theme-color" content="#ffffff">
      <meta name="apple-mobile-web-app-status-bar-style" content="default">
      <style>
          :root {
                --bg-primary: linear-gradient(135deg, #25dfc56b, #f9fb989d);
                --bg-secondary: #fff;
                --bg-tertiary: #272d3e;
                --primary: #721fc3;
                --primary-dark: #4f46e5;
                --secondary: #f8fafc;
                --accent: #9b0296;
                --danger: #df2222;
                --warning: #f59e0b;
                --text: #1e293b;
                --text-light: #64748b;
                --border: #848484;
                --shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.1);
                --radius: 16px;
                --get-Ip: #00ffe7;
                --kadr: #003f00;
             }

          .dark-mode {
            --bg-primary: linear-gradient(135deg, #0000004f, #1e1e45);
            --bg-secondary: #0f1a2f;
            --bg-tertiary: #dddddde3;
            --primary: #721fc3;
            --primary-dark: #6366f1;
            --secondary: #1e293b;
            --accent: #09ea2f;
            --danger: #df2222;
            --warning: #fbbf24;
            --text: #f1f5f9;
            --text-light: #94a3b8;
            --border: #82878e;
            --shadow: 0 10px 25px -5px rgba(0, 0, 0, 0.3);
            --get-Ip: #006aff;
            --kadr: #065259
          }

          * {
              margin: 0;
              padding: 0;
              box-sizing: border-box;
          }

          body {
              font-family: 'Inter', 'Segoe UI', system-ui, -apple-system, sans-serif;
              background: var(--bg-secondary);
              color: var(--text);
              min-height: 100vh;
              padding: 20px;
              line-height: 1.6;
          }

          .container {
              max-width: 1200px;
              margin: 0 auto;
          }

                .header {
                    text-align: center;
                    margin-bottom: 40px;
                }

                .panel-header {
                    background: var(--bg-primary);
                    backdrop-filter: blur(20px);
                    box-shadow: 0 10px 25px rgba(0, 0, 0, 0.1);
                    padding: 18px 30px;
                    text-align: center;
                    position: relative;
                    overflow: hidden;
                    border-radius: 8px;
                    border: none;
                    max-width: 850px;
                    margin: 0 auto 25px;
                    width: 70%;
                }

                .dark-mode .panel-header {
                    background: var(--bg-primary);
                }

            .panel-title {
                font-size: 2rem;
                font-weight: 700;
                margin: 0;
              font-family: 'Audiowide', cursive;
              font-weight: 200;
            }


          .header h1 {
              font-size: 3rem;
              font-weight: 800;
              margin-bottom: 10px;
              background: linear-gradient(135deg, var(--primary), var(--accent));
              -webkit-background-clip: text;
              -webkit-text-fill-color: transparent;
              background-clip: text;
          }

          .header p {
              font-size: 1.2rem;
              color: var(--text-light);
          }

          .accordion-container {
              display: flex;
              flex-direction: column;
              gap: 20px;
          }

            .form-group small {
                   font-size: 20px;
                }

          .accordion {
              backdrop-filter: blur(20px);
              box-shadow: var(--shadow);
              border: 1px solid var(--border);
              overflow: hidden;
              transition: var(--transition);
                border: double var(--kadr);
                border-width: 2px 4px;
                border-radius: 40px;
          }

          .simple-panel {
              display: flex;
              flex-direction: column;
              gap: 25px;
              align-items: center;
            }

            .panel-section {
                background: var(--bg-primary);
                padding: 25px;
                border-radius: var(--radius);
                border: 1px solid var(--border);
                box-shadow: var(--shadow);
                max-width: 850px;
                width: 70%;
            }

            .panel-section h3 {
                margin-bottom: 20px;
                color: var(--primary);
                font-size: 1.3rem;
                border-bottom: 2px solid var(--primary);
                padding-bottom: 10px;
            }

          .dark-mode .accordion {
             /* background: rgba(30, 41, 59, 0.95); */
          }

          .accordion:hover {
              transform: translateY(-2px);
              box-shadow: 0 20px 40px -10px rgba(0, 0, 0, 0.15);
          }

          .accordion-header {
              padding: 24px;
              cursor: pointer;
              display: flex;
              align-items: center;
              justify-content: space-between;
              font-weight: 600;
              font-size: 1.1rem;
              transition: var(--transition);
              background: var(--bg-primary);
              height: 81px;
        }

          .accordion-icon {
              font-size: 1.5rem;
              margin-right: 12px;
        }

          .accordion-title {
            display: flex;
            align-items: center;
            flex: 1;
            font-family: monospace;
            font-size: 20px;
            font-weight: 100;
        }

          .accordion-arrow {
              transition: var(--transition);
              font-size: 1.2rem;
          }

          .accordion.active .accordion-arrow {
              transform: rotate(180deg);
          }

          .accordion-content {
              padding: 0 24px;
              max-height: 0;
              overflow: visible;
              transition: var(--transition);
              background: var(--bg-secondary);
          }

          .accordion.active .accordion-content {
            padding: 0 10px 24px 10px;
            max-height: 100vh;
            overflow-y: auto;
            margin-top: 20px;
        }

          .form-group {
              margin-bottom: 20px;
          }

          .form-label {
              display: block;
              margin-bottom: 8px;
              font-weight: 600;
              color: var(--text);
          }

          .form-input, .form-select, .form-textarea {
              width: 100%;
              padding: 12px 16px;
              border: 1px solid var(--border);
              border-radius: 5px;
              font-size: 16px;
              transition: var(--transition);
              background: var(--secondary);
              color: var(--text);
          }

          .form-input:focus, .form-select:focus, .form-textarea:focus {
              outline: none;
              border-color: var(--primary);
              box-shadow: 0 0 0 3px rgba(99, 102, 241, 0.1);
          }

          .btn {
              padding: 12px 24px;
              border: none;
              border-radius: 5px;
              font-size: 16px;
              font-weight: 600;
              cursor: pointer;
              transition: var(--transition);
              align-items: center;
              gap: 8px;
          }

             .btn-primary, .btn-danger {
                border: none;
                border-radius: 5px;
                font-size: 16px;
                font-weight: 600;
                cursor: pointer;
                transition: var(--transition);
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

                .btn-primary {
                    background: linear-gradient(135deg, var(--primary), var(--primary-dark));
                    color: white;
                }

                    .btn-primary:hover {
                    transform: translateY(-2px);
                  }


                .btn-danger {
                    background: var(--danger);
                    color: white;
                }

          .btn-secondary {
              background: var(--get-Ip);
              color: var(--text);
              border: none;
          }

          .btn-success {
              background: linear-gradient(135deg, #10b981, #059669);
              color: white;
          }

            .btn-success:hover {
             transform: translateY(-2px);
          }

          .ip-list {
              border: 2px solid var(--border);
              border-radius: 5px;
              padding: 16px;
              margin-bottom: 16px;
              max-height: 200px;
              overflow-y: auto;
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
                border-radius: 5px;
                font-size: 14px;
                font-weight: 600;
                cursor: pointer;
                transition: var(--transition);
                display: flex;
                align-items: center;
                gap: 6px;
                height: 48px;
                white-space: nowrap;
            }

            .sub-btn:hover {
                transform: translateY(-2px);
                box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
                background: var(--primary);
                color: white;
                border-color: var(--primary);
            }

          .status-bar {
              display: flex;
              justify-content: space-between;
              align-items: center;
              padding: 20px;
              background: var(--bg-primary);
              border-radius: var(--radius);
              margin-top: 30px;
              border: 1px solid var(--border);

          }

        .theme-toggle {
            position: fixed;
            top: 30px;  
            right: 30px; 
            width: 60px;
            height: 60px;
            border-radius: 50%;
            background: none;
            border: none;
            color: white;
            font-size: 1.7rem;
            cursor: pointer;
            box-shadow: none;
            transition: var(--transition);
            display: flex;
            align-items: center;
            justify-content: center;
            z-index: 1001;
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
                width: 70%;
                max-width: 850px;
                margin: 20px auto 30px;
                text-align: center;
            }

            .logout-btn:hover {
                box-shadow: 0 6px 20px rgba(239, 68, 68, 0.4);
            }

          .qr-modal {
              display: none;
              position: fixed;
              top: 0;
              left: 0;
              width: 100%;
              height: 100%;
              background: rgba(0, 0, 0, 0.8);
              backdrop-filter: blur(10px);
              align-items: center;
              justify-content: center;
              z-index: 1000;
          }

          .qr-content {
              background: #ffffff;
              padding: 30px;
              border-radius: var(--radius);
              text-align: center;
              box-shadow: var(--shadow);
          }

            .message-overlay {
                position: fixed;
                top: 50%;
                left: 50%;
                transform: translate(-50%, -50%);
                z-index: 1000;
                padding: 20px 30px;
                border-radius: 8px;
                font-weight: 600;
                font-size: 16px;
                text-align: center;
                box-shadow: 0 10px 30px rgba(0, 0, 0, 0.3);
                max-width: 300px;
                width: 90%;
                backdrop-filter: blur(10px);
            }

            .message-success {
                background: linear-gradient(135deg, #10b981ab, #059668a8);
                color: white;
                border: 1px solid #34d399;
            }

            .message-error {
                background: linear-gradient(135deg, #ef4444b7, #dc26269c);
                color: white;
                border: 1px solid #f87171;
            }

             @media screen and (max-width: 768px) {
                             body {
                padding: 0 !important; margin-left: 5px; margin-right: 9px; margin-top: 20px;
                 }
    
                .container {
                    max-width: 100% !important;
                    width: 100% !important;
                    margin-left: 10px;
                    margin-right: 10px;
                }

                .accordion-title {
                display: flex;
                align-items: center;
                flex: 1;
                font-family: monospace;
                font-size: 16px;
                font-weight: 200;
                    }

            .accordion-container {
                width: 100% !important;
                gap: 12px !important;
            }

            .accordion {
                width: 100% !important;
                max-width: 100% !important;
                margin: 2px 0 12px  !important;
                border: double var(--kadr);
                border-width: 1px 3px;
                border-radius: 40px;
            }

            .accordion-header {
                width: 100% !important;
                min-height: 81px !important;
            }

            .accordion-content {
                width: 100% !important;
                max-width: 100% !important;
                padding: 0 12px 12px 12px !important;
                box-sizing: border-box !important;
            }

               #ipList > div {
                    margin-bottom: 2px !important;
                }

                .ip-item {
                    margin: 2px 0 !important;
                    padding: 8px 6px !important;
                }

                .ip-list {
                    padding: 5px !important;
                    margin: 8px 0 !important;
                }
                 
                .form-group small {
                   font-size: 15px;
                }
            
            .ip-actions {
                width: auto !important;
                flex-shrink: 0 !important;
            }
            
            .action-btn {
                padding: 10px 12px !important;
                font-size: 11px !important;
                white-space: nowrap !important;
                width: auto !important;
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
                font-size: 15px !important;
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
            
            .sub-btn {
                width: 100% !important;
                justify-content: center !important;
                height: 45px !important;
                font-size: 17px !important;
                background: var(--get-Ip);
            }
            
            .ip-display {
                flex-direction: column !important;
                gap: 8px !important;
                width: 100% !important;
            }

            .panel-header {
                width: 100% !important;
            }

            .panel-section {
                width: 100% !important;
            }

            .panel-title {
                font-size: 1.6rem !important;
            }

            .panel-subtitle {
                font-size: 0.9rem !important;
            }

            .simple-panel {
                width: 100% !important;
            }

            .theme-toggle {
                bottom: 20px !important;
                right: 20px !important;
                width: 50px !important;
                height: 50px !important;
                position: fixed !important;
                z-index: 1001 !important;
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
                padding: 14px !important;
                margin: 30px 0 !important;
                position: relative !important;
                height: 50px !important;
                font-size: 15px !important;
            }

            .add-ip-row {
                flex-direction: row !important;
                align-items: stretch !important; 
                margin-top: 25px;
                    }

            .add-btn {
                width: auto !important;
                min-width: 80px !important;
                height: 45px;
                    }

            .accordion:not(.active) .accordion-content {
                display: none !important;
            }
            
            .accordion.active .accordion-content {
                max-height: 100vh;
                display: block !important;
                margin-top: 20px;
            }
        }
      </style>
  </head>
  <body>
        <div class="panel-header">
            <div class="panel-title">FreeNet</div>
        </div>

         <div class="simple-panel">
    <div class="panel-section">
        <h3>🔑 UUID Settings</h3>
        <div class="form-group">
            <div style="display: flex; gap: 10px; align-items: center;">
                <input type="text" id="uuid" class="form-input" placeholder="Enter UUID" value="" style="flex: 1;">
                <button type="button" onclick="generateRandomUUID()" class="sub-btn" style="white-space: nowrap;height: 48px;background: linear-gradient(135deg, #10b981, #059669);color: white;border: none;">🎲 Generate</button>
            </div>
        </div>
        <button type="button" class="btn btn-success" onclick="importToKV()" style="width: 100%; padding: 16px; font-size: 1.1rem; margin-bottom: 20px;">
            💾 Save UUID
        </button>
    </div>

    <div class="panel-section">
        <h3>🔗 Subscription Link</h3>
        <div class="form-group">
            <div class="subscription-row">
                <input type="text" id="subscription" class="form-input" value="https://${globalThis.hostName}/${globalThis.AccessSubscription}#FreeNet_D" readonly>
                <div class="subscription-buttons">
                    <button type="button" class="sub-btn" onclick="copyToClipboard('subscription')">📋 Copy</button>
                    <button type="button" class="sub-btn" onclick="openQR('subscription')">📱 QR</button>
                </div>
            </div>
        </div>
    </div>

    <div class="panel-section">
        <h3>🔐 Change Password</h3>
        <form id="changePasswordForm">
            <div class="form-group">
                <label class="form-label">Current Password</label>
                <div style="position: relative;">
                    <input type="password" id="current-password" class="form-input" required>
                    <button type="button" onclick="togglePassword('current-password')" style="position: absolute; right: 10px; top: 50%; transform: translateY(-50%); background: none; border: none; cursor: pointer;font-size: 17px;">🙈</button>
                </div>
            </div>
            
            <div class="form-group">
                <label class="form-label">New Password</label>
                <div style="position: relative;">
                    <input type="password" id="new-password" class="form-input" required>
                    <button type="button" onclick="togglePassword('new-password')" style="position: absolute; right: 10px; top: 50%; transform: translateY(-50%); background: none; border: none; cursor: pointer;font-size: 17px;">🙈</button>
                </div>
            </div>
            
            <div class="form-group">
                <label class="form-label">Confirm New Password</label>
                <div style="position: relative;">
                    <input type="password" id="confirm-password" class="form-input" required>
                    <button type="button" onclick="togglePassword('confirm-password')" style="position: absolute; right: 10px; top: 50%; transform: translateY(-50%); background: none; border: none; cursor: pointer;font-size: 17px;">🙈</button>
                </div>
            </div>
            
            <button type="button" class="btn btn-primary" onclick="changePassword()">Change Password</button>
            <div id="password-change-message" style="margin-top: 15px;"></div>
        </form>
    </div>

    <div class="panel-section">
        <h3>🧩 Fragment Settings</h3>
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

      <button class="logout-btn" onclick="logout()">🚪 Logout</button>
      <button class="theme-toggle" id="themeToggle">🌙</button>

      <div class="qr-modal" id="qrModal" onclick="closeQR()">
          <div class="qr-content">
              <div id="qrcode"></div>
          </div>
      </div>

      <script src="https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js"></script>
      <script>
          let defalt_uuid = "${globalThis.UzKey}";
          let defalt_AcsSub = "${globalThis.AccessSubscription}";
          let defalt_CnfgName = "${globalThis.CnfgName}";

            function toggleAccordion(header) {
                const accordion = header.parentElement;
                const content = accordion.querySelector('.accordion-content');
                
                if (accordion.classList.contains('active')) {
                    accordion.classList.remove('active');
                    content.style.maxHeight = '0';
                } else {
                    accordion.classList.add('active');
                    content.style.maxHeight = content.scrollHeight + 'px';
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

async function importToKV() {
    try {
        const configData = {
            custom_uuid: document.getElementById('uuid').value || defalt_uuid
        };
        
        const saveResponse = await fetch('/save-custom-config', {
            method: 'POST',
            headers: {'Content-Type': 'application/json'},
            body: JSON.stringify(configData)
        });
        
        const result = await saveResponse.json();
        if (result.success) {
            showMessage('✅ Config saved successfully!', 'success');
        } else {
            showMessage('❌ Failed to save config: ' + result.error, 'error');
        }
    } catch (error) {
        showMessage('❌ Error saving config: ' + error.message, 'error');
    }
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

          async function logout() {
              await fetch('/logout', { method: 'POST' });
              window.location.href = '/login';
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

            function generateRandomUUID() {
                const uuid = 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(c) {
                    const r = Math.random() * 16 | 0;
                    const v = c == 'x' ? r : (r & 0x3 | 0x8);
                    return v.toString(16);
                });
                
                document.getElementById('uuid').value = uuid;
                showMessage('✅ UUID generated successfully!', 'success');
            }

          async function changePassword() {
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
                    credentials: 'same-origin',
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
                const messageDiv = document.getElementById('password-change-message');
                messageDiv.innerHTML = message;
                messageDiv.style.display = 'block';
                
                if (type === 'success') {
                    messageDiv.className = 'message-overlay message-success';
                } else {
                    messageDiv.className = 'message-overlay message-error';
                }
                
                setTimeout(() => {
                    messageDiv.style.display = 'none';
                }, 2000);
            }

                async function load_defalt() {
                    try {
                        const configResponse = await fetch('/load-custom-config', { cache: 'no-store' });
                        const savedConfig = await configResponse.json();
                        document.getElementById('uuid').value = savedConfig.custom_uuid || defalt_uuid;
                    } catch (error) {
                        document.getElementById('uuid').value = defalt_uuid;
                    }
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

          document.addEventListener('DOMContentLoaded', function() {
              load_defalt();
              loadFragment();
              
              document.getElementById('domain-new-input').addEventListener('keypress', function(e) {
                  if (e.key === 'Enter') {
                      addSingleIP();
                  }
              });

                if ('serviceWorker' in navigator) {
                    navigator.serviceWorker.register('/sw.js')
                        .then(() => console.log('Service Worker Registered'))
                        .catch(err => console.log('SW registration failed: ', err));
                }
          });
      </script>
  </body>
  </html>`;

  return new Response(AdvancedPage, {
    status: 200,
    headers: {
      "Content-Type": "text/html;charset=utf-8",
      "Cache-Control":
        "no-store, no-cache, must-revalidate, proxy-revalidate, no-transform",
      "CDN-Cache-Control": "no-store",
    },
  });
}

async function getVVConfig(env) {
  const protocol = atob("dmxlc3M=");

  const getDomainIPs1 = await resolveDNS(globalThis.hostName);
  const getDomainIPs2 = await resolveDNS(globalThis.CleanIPDomain);
  const getDomainIPs3 = await resolveDNS(
    "\u0062\u0070\u0062\u002E\u0079\u006F\u0075\u0073\u0065\u0066\u002E\u0069\u0073\u0065\u0067\u0061\u0072\u006F\u002E\u0063\u006F\u006D"
  );
  const getDomainIPs4 = await resolveDNS(
    "\u006E\u0069\u006D\u0061\u002E\u006E\u0073\u0063\u006C\u002E\u0069\u0072"
  );
  const getDomainIPs5 = await resolveDNS(
    "\u0061\u0070\u0069\u002E\u0069\u0070\u0069\u0066\u0079\u002E\u006F\u0072\u0067"
  );

  const getDomainIP4s = [
    ...getDomainIPs1.ipv4,
    ...getDomainIPs2.ipv4,
    ...getDomainIPs3.ipv4,
    ...getDomainIPs4.ipv4,
    ...getDomainIPs5.ipv4,
  ];

  const MAX_IPS = 50;
  const selectedIPs = [...getDomainIP4s].sort(() => 0.5 - Math.random()).slice(0, MAX_IPS);

  const config = await loadFromKV(env);
  const currentUUID = config.custom_uuid || globalThis.uzerID;
  const fragmentConfig = await getFragmentConfig(env);

  const dfltPrts = ["443", "8443", "2053", "2083", "2087", "2096"];
  const dfltIcns = ["%F0%9F%97%BD"];
  const dfltFp = ["chrome", "unsafe"];
  const fpath = globalThis.fpaths.split(",");

  var CnfgCntr = 1;
  const fm = encodeURIComponent(JSON.stringify(fragmentConfig));
  const cs = encodeURIComponent(CIPHER_SUITES);

  let firstPath = generateRandomPath();
  if (globalThis.GetPath) {
    globalThis.GetPath = globalThis.GetPath.replace(/=/g, "%3D");
    const randomFpath = fpath[Math.floor(Math.random() * fpath.length)];
    firstPath =
      randomFpath + "%2F" + globalThis.GetPath + "%2F" + generateRandomPath();
  }

  var vVvMain =
    `${protocol}` +
    `://${currentUUID}@${globalThis.hostName}:443` +
      `?encryption=none&security=tls&sni=${globalThis.hostName}&fp=${thisFp}&allowInsecure=0&alpn=http%2F1.1&type=ws&host=${globalThis.hostName}&path=%2F${thisPath}&cs=${cs}&fm=${fm}#${CnfgCntr}%20-%20${thisIcn}%20FreeNet_D\n`;

  let icnCounter = 0;
  let fpCounter = 0;
  for (var thisIP of selectedIPs) {
    CnfgCntr++;
    if (thisIP.slice(-1) == ".") {
      thisIP = thisIP.substr(0, thisIP.length - 1);
    }

    let thisPrt;
    if (
      getDomainIPs3.ipv4.includes(thisIP) ||
      getDomainIPs4.ipv4.includes(thisIP) ||
      getDomainIPs5.ipv4.includes(thisIP)
    ) {
      thisPrt = "443";
    } else {
      thisPrt = dfltPrts[Math.floor(Math.random() * dfltPrts.length)];
    }

    const thisIcn = dfltIcns[icnCounter % dfltIcns.length];
    icnCounter++;

    const thisFp = dfltFp[fpCounter % dfltFp.length];
    fpCounter++;

    let thisPath = generateRandomPath();
    if (globalThis.GetPath) {
      const randomFpath = fpath[Math.floor(Math.random() * fpath.length)];
      thisPath =
        randomFpath + "%2F" + globalThis.GetPath + "%2F" + generateRandomPath();
    }

    vVvMain +=
      `${protocol}` +
      `://${currentUUID}@${thisIP}:${thisPrt}` +
      `?encryption=none&security=tls&sni=${globalThis.hostName}&fp=unsafe&allowInsecure=0&alpn=http%2F1.1&type=ws&host=${globalThis.hostName}&path=%2F${thisPath}&cs=${cs}&fm=${fm}#${CnfgCntr}%20-%20${thisIcn}%20FreeNet_D\n`;
  }

  vVvMain = btoa(vVvMain);

  return new Response(vVvMain, {
    status: 200,
    headers: {
      "Content-Type": "text/plain;charset=utf-8",
    },
  });
}

async function handleSaveConfig(request, env) {
  try {
    const configData = await request.json();

    const simplifiedConfig = {
      custom_uuid: configData.custom_uuid,
    };

    const result = await saveToKV(env, simplifiedConfig);

    if (result.success) {
      return new Response(JSON.stringify({ success: true }), {
        headers: { "Content-Type": "application/json" },
      });
    } else {
      return new Response(
        JSON.stringify({ success: false, error: result.error }),
        {
          status: 500,
          headers: { "Content-Type": "application/json" },
        }
      );
    }
  } catch (error) {
    return new Response(
      JSON.stringify({ success: false, error: error.message }),
      {
        status: 400,
        headers: { "Content-Type": "application/json" },
      }
    );
  }
}

async function handleLoadConfig(env) {
  try {
    const config = await loadFromKV(env);
    return new Response(JSON.stringify(config), {
      headers: { "Content-Type": "application/json" },
    });
  } catch (error) {
    return new Response(JSON.stringify({ error: error.message }), {
      status: 500,
      headers: { "Content-Type": "application/json" },
    });
  }
}
