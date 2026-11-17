const JSON_HEADERS = { "content-type": "application/json; charset=utf-8" };

function json(data, status = 200, extra = {}) {
  return new Response(JSON.stringify(data), { status, headers: { ...JSON_HEADERS, ...extra } });
}

function corsHeaders(request, env) {
  const origin = request.headers.get("Origin") || "";
  if (!env.ALLOWED_ORIGIN || origin !== env.ALLOWED_ORIGIN) return {};
  return {
    "Access-Control-Allow-Origin": origin,
    "Access-Control-Allow-Methods": "GET, POST, PATCH, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Max-Age": "86400",
    "Vary": "Origin"
  };
}

function withCors(response, request, env) {
  const headers = new Headers(response.headers);
  for (const [key, value] of Object.entries(corsHeaders(request, env))) headers.set(key, value);
  return new Response(response.body, { status: response.status, statusText: response.statusText, headers });
}

function clean(value, max = 160) {
  return String(value ?? "").trim().replace(/[<>]/g, "").slice(0, max);
}

function base64url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

function fromBase64url(value) {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - value.length % 4) % 4);
  return Uint8Array.from(atob(padded), c => c.charCodeAt(0));
}

async function hmac(value, secret) {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
  return new Uint8Array(await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(value)));
}

async function issueToken(secret) {
  const payload = base64url(new TextEncoder().encode(JSON.stringify({ exp: Date.now() + 8 * 60 * 60 * 1000, scope: "admin" })));
  const signature = base64url(await hmac(payload, secret));
  return payload + "." + signature;
}

async function validToken(token, secret) {
  if (!token || !secret || token.length > 1000) return false;
  const parts = token.split(".");
  if (parts.length !== 2) return false;
  const expected = await hmac(parts[0], secret);
  const supplied = fromBase64url(parts[1]);
  if (expected.length !== supplied.length) return false;
  let diff = 0;
  for (let i = 0; i < expected.length; i++) diff |= expected[i] ^ supplied[i];
  if (diff !== 0) return false;
  try {
    const payload = JSON.parse(new TextDecoder().decode(fromBase64url(parts[0])));
    return payload.scope === "admin" && Number(payload.exp) > Date.now();
  } catch {
    return false;
  }
}

async function hash(value) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return [...new Uint8Array(digest)].map(b => b.toString(16).padStart(2, "0")).join("");
}

async function rateLimit(db, key, limit, windowSeconds) {
  const now = Math.floor(Date.now() / 1000);
  const bucket = Math.floor(now / windowSeconds);
  const id = await hash(key + ":" + bucket);
  await db.prepare(
    "INSERT INTO rate_limits (id, hits, expires_at) VALUES (?, 1, ?) ON CONFLICT(id) DO UPDATE SET hits = hits + 1"
  ).bind(id, now + windowSeconds * 2).run();
  const row = await db.prepare("SELECT hits FROM rate_limits WHERE id = ?").bind(id).first();
  await db.prepare("DELETE FROM rate_limits WHERE expires_at < ?").bind(now).run();
  return Number(row?.hits || 0) <= limit;
}

function clientKey(request) {
  return request.headers.get("CF-Connecting-IP") || "unknown";
}

function adminPage() {
  return new Response(ADMIN_HTML, { headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" } });
}

async function sendNotification(env, enquiry) {
  if (!env.RESEND_API_KEY || !env.MAIL_FROM || !env.MAIL_TO) return false;
  const safe = value => String(value || "").replace(/[<>&"]/g, "");
  const body = [
    "A new NORISKLIFE information request has been received.",
    "",
    "Name: " + safe(enquiry.name),
    "Mobile: " + safe(enquiry.mobile),
    "Email: " + safe(enquiry.email || "Not provided"),
    "City: " + safe(enquiry.city),
    "Interest: " + safe(enquiry.interest),
    "Preferred callback: " + safe(enquiry.callback_time),
    "Received: " + safe(enquiry.created_at),
    "",
    "Please access the private NORISKLIFE admin dashboard to manage this enquiry."
  ].join("\n");
  try {
    const response = await fetch("https://api.resend.com/emails", {
      method: "POST",
      headers: { "Authorization": "Bearer " + env.RESEND_API_KEY, "Content-Type": "application/json" },
      body: JSON.stringify({ from: env.MAIL_FROM, to: [env.MAIL_TO], subject: "New NORISKLIFE information request", text: body })
    });
    return response.ok;
  } catch {
    return false;
  }
}

async function handlePublicEnquiry(request, env) {
  if (!env.DB) return json({ error: "Enquiry service is not configured." }, 503);
  let data;
  try { data = await request.json(); } catch { return json({ error: "Please submit a valid request." }, 400); }
  if (clean(data.website, 200)) return json({ ok: true });
  if (!(await rateLimit(env.DB, "enquiry:" + clientKey(request), 4, 3600))) {
    return json({ error: "Please wait before submitting another request." }, 429);
  }

  const name = clean(data.name, 80);
  const mobile = clean(data.mobile, 24);
  const email = clean(data.email, 254).toLowerCase();
  const city = clean(data.city, 80);
  const interest = clean(data.interest, 40);
  const callbackTime = clean(data.callback_time, 40);
  const mobileDigits = mobile.replace(/\D/g, "");
  const interests = ["Life Insurance", "Health Insurance", "General Information"];
  const times = ["Morning (9 AM–12 PM)", "Afternoon (12 PM–4 PM)", "Evening (4 PM–7 PM)"];

  if (name.length < 2 || !/^[\p{L}\p{M} .'-]+$/u.test(name)) return json({ error: "Please enter a valid name." }, 400);
  if (mobileDigits.length < 10 || mobileDigits.length > 15) return json({ error: "Please enter a valid mobile number." }, 400);
  if (email && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return json({ error: "Please enter a valid email address." }, 400);
  if (city.length < 2 || !/^[\p{L}\p{M} .'-]+$/u.test(city)) return json({ error: "Please enter a valid city." }, 400);
  if (!interests.includes(interest) || !times.includes(callbackTime)) return json({ error: "Please select the requested options." }, 400);
  if (data.consent !== true) return json({ error: "Please confirm consent before submitting." }, 400);

  const id = crypto.randomUUID();
  const createdAt = new Date().toISOString();
  const enquiry = { id, name, mobile, email, city, interest, callback_time: callbackTime, status: "New", created_at: createdAt };
  await env.DB.prepare(
    "INSERT INTO enquiries (id, name, mobile, email, city, interest, callback_time, consent, status, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, 1, 'New', ?)"
  ).bind(id, name, mobile, email || null, city, interest, callbackTime, createdAt).run();

  const notified = await sendNotification(env, enquiry);
  return json({ ok: true, notification_sent: notified });
}

async function handleAdminLogin(request, env) {
  if (!env.ADMIN_PASSWORD || !env.SESSION_SECRET || !env.DB) return json({ error: "Admin service is not configured." }, 503);
  if (!(await rateLimit(env.DB, "login:" + clientKey(request), 8, 900))) return json({ error: "Too many login attempts. Please try again later." }, 429);
  let data;
  try { data = await request.json(); } catch { return json({ error: "Invalid request." }, 400); }
  const supplied = await hash(String(data.password || ""));
  const expected = await hash(env.ADMIN_PASSWORD);
  if (supplied.length !== expected.length || ![...supplied].every((char, i) => char === expected[i])) {
    return json({ error: "The password is incorrect." }, 401);
  }
  return json({ ok: true, token: await issueToken(env.SESSION_SECRET) }, 200, { "cache-control": "no-store" });
}

async function requireAdmin(request, env) {
  const auth = request.headers.get("Authorization") || "";
  const token = auth.startsWith("Bearer ") ? auth.slice(7) : "";
  return validToken(token, env.SESSION_SECRET);
}

async function handleAdminList(request, env) {
  if (!(await requireAdmin(request, env))) return json({ error: "Please sign in again." }, 401);
  const rows = await env.DB.prepare(
    "SELECT id, name, mobile, email, city, interest, callback_time, status, created_at FROM enquiries ORDER BY created_at DESC LIMIT 500"
  ).all();
  return json({ enquiries: rows.results || [] }, 200, { "cache-control": "no-store" });
}

async function handleAdminUpdate(request, env, id) {
  if (!(await requireAdmin(request, env))) return json({ error: "Please sign in again." }, 401);
  let data;
  try { data = await request.json(); } catch { return json({ error: "Invalid request." }, 400); }
  const status = clean(data.status, 20);
  if (!["New", "Contacted", "Closed"].includes(status)) return json({ error: "Invalid status." }, 400);
  const result = await env.DB.prepare("UPDATE enquiries SET status = ? WHERE id = ?").bind(status, id).run();
  if (!result.meta?.changes) return json({ error: "Enquiry not found." }, 404);
  return json({ ok: true });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (request.method === "OPTIONS") return new Response(null, { status: 204, headers: corsHeaders(request, env) });
    let response;
    if (url.pathname === "/health" && request.method === "GET") {
      response = json({ ok: true, service: "NORISKLIFE enquiry API" });
    } else if (url.pathname === "/admin" && request.method === "GET") {
      response = adminPage();
    } else if (url.pathname === "/api/enquiries" && request.method === "POST") {
      response = await handlePublicEnquiry(request, env);
    } else if (url.pathname === "/api/admin/login" && request.method === "POST") {
      response = await handleAdminLogin(request, env);
    } else if (url.pathname === "/api/admin/enquiries" && request.method === "GET") {
      response = await handleAdminList(request, env);
    } else if (url.pathname.startsWith("/api/admin/enquiries/") && request.method === "PATCH") {
      const id = url.pathname.split("/").pop();
      response = await handleAdminUpdate(request, env, id);
    } else if (url.pathname === "/api/admin/logout" && request.method === "POST") {
      response = json({ ok: true });
    } else {
      response = json({ error: "Not found." }, 404);
    }
    return withCors(response, request, env);
  }
};

const ADMIN_HTML = String.raw\`<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>NORISKLIFE | Private Enquiry Dashboard</title>
<style>
*{box-sizing:border-box}body{margin:0;background:#f3f6f8;color:#26394b;font:15px Arial,sans-serif}.top{background:#102b46;color:white;padding:20px 5%;display:flex;justify-content:space-between;align-items:center}.top strong{font-size:20px;letter-spacing:1px}.wrap{max-width:1100px;margin:34px auto;padding:0 18px}.panel{background:white;border:1px solid #dce4ea;border-radius:12px;padding:24px;box-shadow:0 8px 24px #102b4610}.login{max-width:420px;margin:55px auto}.field{display:block;width:100%;padding:13px;border:1px solid #cbd6df;border-radius:6px;margin:10px 0 16px;font-size:16px}button{border:0;border-radius:6px;padding:11px 17px;background:#087f70;color:white;font-weight:700;cursor:pointer}button.secondary{background:#e9eff3;color:#26394b}button:disabled{opacity:.5;cursor:not-allowed}.muted{color:#68798a;font-size:13px}.error{color:#a12b2b;margin-top:12px}.toolbar{display:flex;justify-content:space-between;gap:12px;align-items:center;margin-bottom:18px;flex-wrap:wrap}.table-wrap{overflow-x:auto}table{width:100%;border-collapse:collapse;min-width:850px}th,td{text-align:left;padding:12px 10px;border-bottom:1px solid #e7edf1;vertical-align:top}th{font-size:12px;text-transform:uppercase;color:#68798a;letter-spacing:.04em}select{padding:8px;border:1px solid #cbd6df;border-radius:5px;background:white}#dashboard[hidden],#login[hidden]{display:none}.status{font-weight:700;color:#087f70}.empty{text-align:center;padding:35px;color:#68798a}@media(max-width:600px){.panel{padding:17px}.top{padding:17px 5%}}
</style></head><body><header class="top"><strong>NORISKLIFE</strong><span>Private Enquiry Dashboard</span></header>
<main class="wrap"><section id="login" class="panel login"><h2>Admin sign in</h2><p class="muted">This area is restricted to authorised administrators.</p><form id="loginForm"><label for="password">Admin password</label><input class="field" id="password" type="password" autocomplete="current-password" required><button type="submit">Sign in</button><p id="loginError" class="error" role="alert"></p></form></section>
<section id="dashboard" hidden><div class="toolbar"><div><h2>Enquiries</h2><p class="muted">Private records · latest 500 requests</p></div><button class="secondary" id="logout">Sign out</button></div><div class="panel"><div id="message" class="muted" aria-live="polite">Loading enquiries…</div><div class="table-wrap"><table><thead><tr><th>Received</th><th>Name / Contact</th><th>City</th><th>Interest</th><th>Callback</th><th>Status</th></tr></thead><tbody id="rows"></tbody></table></div></div></section></main>
<script>
(function(){const api=location.origin;let token=sessionStorage.getItem("norisk_admin_token")||"";const $=id=>document.getElementById(id);
async function call(path,options={}){const headers=Object.assign({"Content-Type":"application/json"},options.headers||{});if(token)headers.Authorization="Bearer "+token;const response=await fetch(api+path,Object.assign({},options,{headers}));const data=await response.json().catch(()=>({}));if(!response.ok)throw new Error(data.error||"Request failed");return data}
function showLogin(){ $("login").hidden=false;$("dashboard").hidden=true; }
function showDashboard(){ $("login").hidden=true;$("dashboard").hidden=false;load(); }
async function load(){ $("message").textContent="Loading enquiries…";$("rows").replaceChildren();try{const data=await call("/api/admin/enquiries");$("message").textContent=data.enquiries.length?data.enquiries.length+" enquiry record(s).":"No enquiries received yet.";data.enquiries.forEach(item=>{const tr=document.createElement("tr");const add=(value)=>{const td=document.createElement("td");td.textContent=value||"—";tr.appendChild(td);};add(new Date(item.created_at).toLocaleString());add(item.name+" · "+item.mobile+(item.email?" · "+item.email:""));add(item.city);add(item.interest);add(item.callback_time);const td=document.createElement("td");const select=document.createElement("select");["New","Contacted","Closed"].forEach(status=>{const option=document.createElement("option");option.value=status;option.textContent=status;select.appendChild(option)});select.value=item.status;select.addEventListener("change",async()=>{try{await call("/api/admin/enquiries/"+encodeURIComponent(item.id),{method:"PATCH",body:JSON.stringify({status:select.value})})}catch(error){$("message").textContent=error.message;select.value=item.status}});td.appendChild(select);tr.appendChild(td);$("rows").appendChild(tr)});}catch(error){$("message").textContent=error.message;if(error.message.includes("sign in")){token="";sessionStorage.removeItem("norisk_admin_token");showLogin()}}}
$("loginForm").addEventListener("submit",async event=>{event.preventDefault();$("loginError").textContent="";try{const data=await call("/api/admin/login",{method:"POST",body:JSON.stringify({password:$("password").value})});token=data.token;sessionStorage.setItem("norisk_admin_token",token);$("password").value="";showDashboard()}catch(error){$("loginError").textContent=error.message}});
$("logout").addEventListener("click",()=>{token="";sessionStorage.removeItem("norisk_admin_token");showLogin()});if(token)showDashboard();else showLogin();})();
</script></body></html>\`;
