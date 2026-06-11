const COOKIE  = "cookplanner_auth";
const MSG     = "cookplanner-v1";
const MAX_AGE = 60 * 60 * 24 * 30; // 30 days

export async function onRequest(context) {
  const { request, env, next } = context;

  if (!env.SITE_PASSWORD) {
    return new Response("No password configured. Set SITE_PASSWORD in Cloudflare Pages settings.", { status: 500 });
  }

  const url     = new URL(request.url);
  const cookies = parseCookie(request.headers.get("Cookie") || "");
  const expected = await makeToken(env.SITE_PASSWORD, MSG);

  // Logout
  if (url.pathname === "/logout") {
    return new Response(null, {
      status: 302,
      headers: { Location: "/", "Set-Cookie": clearCookie(COOKIE) }
    });
  }

  // Login form submission
  if (url.pathname === "/login" && request.method === "POST") {
    const form = await request.formData();
    const entered = form.get("password") || "";
    if (timingSafeEqual(entered, env.SITE_PASSWORD)) {
      return new Response(null, {
        status: 302,
        headers: { Location: "/", "Set-Cookie": setCookie(COOKIE, expected) }
      });
    }
    return loginPage(true);
  }

  // Check auth cookie
  const authed = cookies[COOKIE] && timingSafeEqual(cookies[COOKIE], expected);
  if (!authed) return loginPage(false);

  // Authenticated — serve the real site
  return next();
}

async function makeToken(secret, msg) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw", enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false, ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(msg));
  return btoa(String.fromCharCode(...new Uint8Array(sig)))
    .replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function setCookie(name, value) {
  return `${name}=${value}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${MAX_AGE}`;
}
function clearCookie(name) {
  return `${name}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`;
}
function parseCookie(str) {
  const out = {};
  str.split(";").forEach(p => {
    const i = p.indexOf("=");
    if (i > -1) out[p.slice(0, i).trim()] = p.slice(i + 1).trim();
  });
  return out;
}
function timingSafeEqual(a, b) {
  const enc = new TextEncoder();
  const ab = enc.encode(a), bb = enc.encode(b);
  if (ab.length !== bb.length) return false;
  let diff = 0;
  for (let i = 0; i < ab.length; i++) diff |= ab[i] ^ bb[i];
  return diff === 0;
}

function loginPage(error) {
  return new Response(
    `<!doctype html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Cook Period Planner</title>
  <style>
    body {
      margin: 0;
      font-family: system-ui, -apple-system, sans-serif;
      background: #FAF9F0;
      display: flex;
      align-items: center;
      justify-content: center;
      min-height: 100vh;
    }
    .box {
      background: #F2EFE1;
      border: 1px solid #E0DDCA;
      border-radius: 12px;
      padding: 40px 36px;
      width: 100%;
      max-width: 360px;
    }
    h1 {
      font-size: 22px;
      font-weight: 700;
      color: #513620;
      margin: 0 0 6px;
    }
    p {
      font-size: 13px;
      color: #8C7462;
      margin: 0 0 28px;
    }
    .error {
      font-size: 13px;
      color: #F64C14;
      margin: -16px 0 20px;
    }
    input[type=password] {
      width: 100%;
      padding: 10px 12px;
      border: 1px solid #E0DDCA;
      border-radius: 7px;
      font-size: 14px;
      font-family: inherit;
      color: #513620;
      background: #FAF9F0;
      box-sizing: border-box;
      margin-bottom: 12px;
    }
    input[type=password]:focus {
      outline: none;
      border-color: #513620;
    }
    button {
      width: 100%;
      padding: 11px;
      background: #F7FE28;
      color: #513620;
      border: none;
      border-radius: 7px;
      font-size: 14px;
      font-weight: 600;
      font-family: inherit;
      cursor: pointer;
    }
    button:hover { opacity: 0.85; }
  </style>
</head>
<body>
  <div class="box">
    <h1>Cook Period Planner</h1>
    <p>Enter the team password to continue.</p>
    ${error ? '<p class="error">Wrong password — try again.</p>' : ''}
    <form method="POST" action="/login">
      <input type="password" name="password" placeholder="Password" autofocus>
      <button type="submit">Log in</button>
    </form>
  </div>
</body>
</html>`,
    { status: error ? 401 : 200, headers: { "Content-Type": "text/html; charset=UTF-8" } }
  );
}
