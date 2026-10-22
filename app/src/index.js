/* Stagebook: servidor na Cloudflare
   - entrada com a conta Google
   - a IA e a transcrição passam por aqui, com a chave da Groq guardada só no servidor
   - conta os minutos de cada pessoa e libera conforme a assinatura (Mercado Pago)
   - guarda e publica os e-books e atas (link fixo para o QR code)
*/

const GROQ = env => (env.GROQ_BASE || "https://api.groq.com").replace(/\/$/, "");
const MP = env => (env.MP_BASE || "https://api.mercadopago.com").replace(/\/$/, "");
const JWKS_URL = env => env.GOOGLE_JWKS || "https://www.googleapis.com/oauth2/v3/certs";
const MODELS = env => (env.MODELOS || "openai/gpt-oss-120b,openai/gpt-oss-20b,qwen/qwen3.8-27b").split(",").map(s => s.trim()).filter(Boolean);
const STT_MODEL = "whisper-large-v3-turbo";
const TOK_POR_MIN = 15000;          // teto de IA por minuto de fala (protege contra abuso pelo modo "digitar")
const DAY = 86400e3;

/* ---------- utilidades ---------- */
const json = (data, status = 200, extra) => new Response(JSON.stringify(data), { status, headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", ...(extra || {}) } });
const err = (status, erro, msg, extra) => json({ erro, msg }, status, extra);
const num = (v, d) => { const n = parseFloat(v); return isFinite(n) ? n : d; };
const enc = new TextEncoder();
const b64u = buf => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const b64uDec = s => { s = s.replace(/-/g, "+").replace(/_/g, "/"); while (s.length % 4) s += "="; const bin = atob(s), out = new Uint8Array(bin.length); for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i); return out; };
const mesBR = (t = Date.now()) => new Date(t - 3 * 3600e3).toISOString().slice(0, 7);   // horário de Brasília
const isAdmin = (env, email) => (env.ADMIN_EMAILS || "").toLowerCase().split(",").map(s => s.trim()).filter(Boolean).includes((email || "").toLowerCase());
function slugify(t){ return (t || "").toLowerCase().normalize("NFD").replace(/[̀-ͯ]/g, "").replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 40) || "documento"; }
function randId(n = 8){ const a = "abcdefghjkmnpqrstuvwxyz23456789", b = crypto.getRandomValues(new Uint8Array(n)); return [...b].map(x => a[x % a.length]).join(""); }
function cookieOf(req, name){ const m = (req.headers.get("cookie") || "").match(new RegExp("(?:^|;\\s*)" + name + "=([^;]+)")); return m ? m[1] : ""; }

/* ---------- banco de dados (cria as tabelas sozinho na primeira vez) ---------- */
let schemaOk = false;
async function ensureSchema(env){
  if (schemaOk) return;
  await env.DB.batch([
    env.DB.prepare(`CREATE TABLE IF NOT EXISTS usuarios (
      id TEXT PRIMARY KEY, email TEXT UNIQUE, nome TEXT, foto TEXT, criado INTEGER,
      pago_ate INTEGER DEFAULT 0, mp_assinatura TEXT DEFAULT '', mp_status TEXT DEFAULT '', mp_conferido INTEGER DEFAULT 0,
      min_extra REAL DEFAULT 0, bloqueado INTEGER DEFAULT 0, visto INTEGER DEFAULT 0)`),
    env.DB.prepare(`CREATE TABLE IF NOT EXISTS uso (
      usuario TEXT, mes TEXT, audio_s REAL DEFAULT 0, tokens INTEGER DEFAULT 0, chamadas INTEGER DEFAULT 0,
      PRIMARY KEY (usuario, mes))`),
    env.DB.prepare(`CREATE TABLE IF NOT EXISTS documentos (
      id TEXT PRIMARY KEY, usuario TEXT, titulo TEXT, evento TEXT, tipo TEXT, html TEXT, criado INTEGER, atualizado INTEGER)`),
    env.DB.prepare(`CREATE INDEX IF NOT EXISTS documentos_usuario ON documentos (usuario, criado)`),
    env.DB.prepare(`CREATE TABLE IF NOT EXISTS contatos (
      id TEXT PRIMARY KEY, doc TEXT, nome TEXT, email TEXT, empresa TEXT, cargo TEXT, aceite INTEGER DEFAULT 0, criado INTEGER)`),
    env.DB.prepare(`CREATE UNIQUE INDEX IF NOT EXISTS contatos_doc_email ON contatos (doc, email)`),
    env.DB.prepare(`CREATE TABLE IF NOT EXISTS leituras (
      doc TEXT, leitor TEXT, item TEXT, segundos REAL DEFAULT 0, vezes INTEGER DEFAULT 0, primeiro INTEGER, ultimo INTEGER,
      PRIMARY KEY (doc, leitor, item))`)
  ]);
  // colunas novas em bancos já existentes (ignora se já existem)
  for (const c of ["cadastro INTEGER DEFAULT 0", "organizador TEXT DEFAULT ''", "capitulos TEXT DEFAULT '[]'"]){
    try { await env.DB.prepare("ALTER TABLE documentos ADD COLUMN " + c).run(); } catch(e){}
  }
  schemaOk = true;
}

/* ---------- sessão (cookie assinado) ---------- */
async function hmacKey(env){
  if (!env.SESSION_SECRET) throw new Error("SESSION_SECRET ausente");
  return crypto.subtle.importKey("raw", enc.encode(env.SESSION_SECRET), { name: "HMAC", hash: "SHA-256" }, false, ["sign", "verify"]);
}
async function makeSession(env, uid){
  const exp = Date.now() + 30 * DAY;
  const payload = b64u(enc.encode(uid)) + "." + exp;
  const sig = b64u(await crypto.subtle.sign("HMAC", await hmacKey(env), enc.encode(payload)));
  return payload + "." + sig;
}
async function readSession(env, req){
  const c = cookieOf(req, "pv"); if (!c) return null;
  const parts = c.split("."); if (parts.length !== 3) return null;
  const [u, exp, sig] = parts;
  if (!(+exp > Date.now())) return null;
  let ok = false;
  try { ok = await crypto.subtle.verify("HMAC", await hmacKey(env), b64uDec(sig), enc.encode(u + "." + exp)); } catch(e){ return null; }
  if (!ok) return null;
  return new TextDecoder().decode(b64uDec(u));
}
const sessionCookie = (val, maxAge) => `pv=${val}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`;

/* ---------- login com Google (confere a assinatura do token do Google) ---------- */
let JWKS = { at: 0, keys: [] };
async function googleKeys(env){
  if (Date.now() - JWKS.at < 3600e3 && JWKS.keys.length) return JWKS.keys;
  const r = await fetch(JWKS_URL(env)); if (!r.ok) throw new Error("jwks");
  const d = await r.json(); JWKS = { at: Date.now(), keys: d.keys || [] }; return JWKS.keys;
}
async function verifyGoogle(env, token){
  const [h, p, s] = String(token || "").split(".");
  if (!h || !p || !s) return null;
  const head = JSON.parse(new TextDecoder().decode(b64uDec(h)));
  const claims = JSON.parse(new TextDecoder().decode(b64uDec(p)));
  const jwk = (await googleKeys(env)).find(k => k.kid === head.kid);
  if (!jwk || head.alg !== "RS256") return null;
  const key = await crypto.subtle.importKey("jwk", jwk, { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" }, false, ["verify"]);
  const ok = await crypto.subtle.verify("RSASSA-PKCS1-v1_5", key, b64uDec(s), enc.encode(h + "." + p));
  if (!ok) return null;
  if (!["accounts.google.com", "https://accounts.google.com"].includes(claims.iss)) return null;
  if (!env.GOOGLE_CLIENT_ID || claims.aud !== env.GOOGLE_CLIENT_ID) return null;
  if (!(claims.exp * 1000 > Date.now())) return null;
  if (!claims.email || claims.email_verified === false || claims.email_verified === "false") return null;
  return claims;
}
async function upsertUser(env, id, email, nome, foto){
  const now = Date.now();
  const byEmail = await env.DB.prepare("SELECT id FROM usuarios WHERE email = ?").bind(email.toLowerCase()).first();
  if (byEmail && byEmail.id !== id) id = byEmail.id;   // mesma pessoa, outro jeito de entrar
  await env.DB.prepare(`INSERT INTO usuarios (id, email, nome, foto, criado, visto) VALUES (?, ?, ?, ?, ?, ?)
    ON CONFLICT(id) DO UPDATE SET nome = excluded.nome, foto = excluded.foto, visto = excluded.visto`)
    .bind(id, email.toLowerCase(), nome || "", foto || "", now, now).run();
  return id;
}

/* ---------- saldo: quantos minutos a pessoa ainda tem ---------- */
async function getUser(env, uid){ return uid ? env.DB.prepare("SELECT * FROM usuarios WHERE id = ?").bind(uid).first() : null; }
async function saldo(env, u){
  const admin = isAdmin(env, u.email);
  const ativo = u.pago_ate > Date.now();
  const chave = ativo ? mesBR() : "total";
  const row = await env.DB.prepare("SELECT audio_s, tokens, chamadas FROM uso WHERE usuario = ? AND mes = ?").bind(u.id, chave).first() || { audio_s: 0, tokens: 0, chamadas: 0 };
  const limiteMin = admin ? 1e9 : ativo ? num(env.MIN_PLANO, 600) : num(env.MIN_TESTE, 30) + (u.min_extra || 0);
  const usadoMin = row.audio_s / 60;
  return {
    admin, ativo, teste: !ativo && !admin,
    pagoAte: u.pago_ate || 0, assinatura: u.mp_status || "",
    limiteMin: admin ? null : Math.round(limiteMin),
    usadoMin: Math.round(usadoMin * 10) / 10,
    restanteMin: admin ? null : Math.max(0, Math.round((limiteMin - usadoMin) * 10) / 10),
    tokens: row.tokens,
    bloqueado: !!u.bloqueado,
    pode: !u.bloqueado && (admin || (usadoMin < limiteMin && row.tokens < limiteMin * TOK_POR_MIN))
  };
}
async function addUso(env, u, audio_s, tokens){
  const keys = [mesBR(), "total"];
  await env.DB.batch(keys.map(m => env.DB.prepare(`INSERT INTO uso (usuario, mes, audio_s, tokens, chamadas) VALUES (?, ?, ?, ?, 1)
    ON CONFLICT(usuario, mes) DO UPDATE SET audio_s = audio_s + excluded.audio_s, tokens = tokens + excluded.tokens, chamadas = chamadas + 1`).bind(u.id, m, audio_s || 0, tokens || 0)));
}
const SEM_SALDO = s => err(402, "sem_saldo", s.bloqueado ? "Esta conta foi pausada. Fale com o responsável pelo Stagebook." : s.ativo ? "Os minutos deste mês acabaram. Eles voltam no dia 1º." : "Os minutos de teste acabaram. Assine para continuar usando.");

/* ---------- IA (texto) pela Groq ---------- */
async function aiChat(env, req, u){
  if (!env.GROQ_KEY) return err(503, "sem_chave", "O servidor ainda não tem a chave da Groq.");
  let b; try { b = await req.json(); } catch(e){ return err(400, "pedido", "Pedido inválido."); }
  const models = MODELS(env);
  const model = models.includes(b.model) ? b.model : models[0];
  const messages = Array.isArray(b.messages) ? b.messages.filter(m => m && typeof m.content === "string" && ["user", "system", "assistant"].includes(m.role)).slice(0, 6) : [];
  const size = messages.reduce((a, m) => a + m.content.length, 0);
  if (!messages.length || size > 90000) return err(413, "grande", "Pedido grande demais.");
  const body = { model, messages, temperature: Math.max(0, Math.min(1, num(b.temperature, 0.3))), max_completion_tokens: Math.max(64, Math.min(4700, num(b.max_completion_tokens, 1600) | 0)) };
  if (b.response_format && b.response_format.type === "json_object") body.response_format = { type: "json_object" };
  if (["none", "low", "medium", "default"].includes(b.reasoning_effort)) body.reasoning_effort = b.reasoning_effort;
  if (b.include_reasoning === false) body.include_reasoning = false;
  const r = await fetch(GROQ(env) + "/openai/v1/chat/completions", { method: "POST", headers: { "authorization": "Bearer " + env.GROQ_KEY, "content-type": "application/json" }, body: JSON.stringify(body) });
  const extra = {}; const ra = r.headers.get("retry-after"); if (ra) extra["retry-after"] = ra;
  if (r.status === 401 || r.status === 403) return err(502, "servidor_groq", "A chave da Groq do servidor foi recusada.");
  const text = await r.text();
  if (r.ok){
    let tokens = 0; try { const d = JSON.parse(text); tokens = ((d.usage && d.usage.prompt_tokens) || 0) + ((d.usage && d.usage.completion_tokens) || 0); } catch(e){}
    await addUso(env, u, 0, tokens);
  }
  return new Response(text, { status: r.status, headers: { "content-type": r.headers.get("content-type") || "application/json", "cache-control": "no-store", ...extra } });
}

/* ---------- transcrição (Whisper) pela Groq ---------- */
async function aiStt(env, req, u){
  if (!env.GROQ_KEY) return err(503, "sem_chave", "O servidor ainda não tem a chave da Groq.");
  let fd; try { fd = await req.formData(); } catch(e){ return err(400, "pedido", "Áudio inválido."); }
  const file = fd.get("file");
  if (!file || typeof file === "string" || !file.size) return err(400, "pedido", "Áudio vazio.");
  if (file.size > 8e6) return err(413, "grande", "Trecho de áudio grande demais.");
  const out = new FormData();
  out.append("file", file, file.name || "trecho.webm");
  out.append("model", STT_MODEL);
  out.append("language", "pt");
  out.append("temperature", "0");
  out.append("response_format", "verbose_json");
  const p = String(fd.get("prompt") || "").slice(0, 900); if (p) out.append("prompt", p);
  const r = await fetch(GROQ(env) + "/openai/v1/audio/transcriptions", { method: "POST", headers: { "authorization": "Bearer " + env.GROQ_KEY }, body: out });
  const extra = {}; const ra = r.headers.get("retry-after"); if (ra) extra["retry-after"] = ra;
  if (r.status === 401 || r.status === 403) return err(502, "servidor_groq", "A chave da Groq do servidor foi recusada.");
  if (!r.ok) return new Response(await r.text(), { status: r.status, headers: { "content-type": "application/json", ...extra } });
  const d = await r.json();
  const dur = Math.max(1, num(d.duration, num(fd.get("dur"), 10)));
  await addUso(env, u, dur, 0);
  return json({ text: d.text || "", duration: dur });
}

/* ---------- e-books e atas ---------- */
async function saveDoc(env, req, u, origin){
  let b; try { b = await req.json(); } catch(e){ return err(400, "pedido", "Pedido inválido."); }
  const html = String(b.html || "");
  if (html.length < 200) return err(400, "pedido", "Documento vazio.");
  if (html.length > 1.9e6) return err(413, "grande", "Documento grande demais.");
  const now = Date.now();
  const tipo = b.tipo === "ata" ? "ata" : "ebook";
  const cadastro = tipo === "ebook" && b.cadastro ? 1 : 0;
  const organizador = String(b.organizador || "").trim().slice(0, 120);
  const caps = [...html.matchAll(/<section[^>]*id="cap-(\d+)"[\s\S]*?<h2[^>]*>([\s\S]*?)<\/h2>/g)].map(m => ({ n: +m[1], titulo: m[2].replace(/<[^>]+>/g, "").trim() })).slice(0, 20);
  let id = String(b.id || "");
  if (id){
    const cur = await env.DB.prepare("SELECT usuario FROM documentos WHERE id = ?").bind(id).first();
    if (!cur || cur.usuario !== u.id) id = "";
  }
  if (id){
    await env.DB.prepare("UPDATE documentos SET html = ?, titulo = ?, evento = ?, atualizado = ?, cadastro = ?, organizador = ?, capitulos = ? WHERE id = ?").bind(html, String(b.titulo || "").slice(0, 200), String(b.evento || "").slice(0, 200), now, cadastro, organizador, JSON.stringify(caps), id).run();
  } else {
    id = randId(7) + "-" + slugify(b.titulo);
    await env.DB.prepare("INSERT INTO documentos (id, usuario, titulo, evento, tipo, html, criado, atualizado, cadastro, organizador, capitulos) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)")
      .bind(id, u.id, String(b.titulo || "").slice(0, 200), String(b.evento || "").slice(0, 200), tipo, html, now, now, cadastro, organizador, JSON.stringify(caps)).run();
  }
  return json({ id, url: origin + "/e/" + id + "/" });
}
async function listDocs(env, u, origin){
  const r = await env.DB.prepare(`SELECT d.id, d.titulo, d.evento, d.tipo, d.criado, d.cadastro,
      (SELECT COUNT(*) FROM contatos c WHERE c.doc = d.id) AS cadastros,
      (SELECT COUNT(*) FROM leituras l WHERE l.doc = d.id AND l.item = 'abriu') AS leitores
    FROM documentos d WHERE d.usuario = ? ORDER BY d.criado DESC LIMIT 100`).bind(u.id).all();
  return json({ docs: (r.results || []).map(d => Object.assign(d, { url: origin + "/e/" + d.id + "/" })) });
}
/* ---------- leitura pública do e-book: cadastro antes de abrir e medição do que foi lido ---------- */
const escH = t => String(t == null ? "" : t).replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const leitorCookie = (id, val) => `pvl=${val}; Path=/e/${id}/; HttpOnly; Secure; SameSite=Lax; Max-Age=${365 * 86400}`;
const LIDO_S = 8;   // segundos na tela para contar um capítulo como lido

function trackerJS(id){
  return `<script>(function(){var u="/e/${id}/ev";function s(t,c,n){try{var b=JSON.stringify({t:t,c:c||"",s:n||0});if(!(navigator.sendBeacon&&navigator.sendBeacon(u,b)))fetch(u,{method:"POST",body:b,keepalive:true})}catch(e){}}
s("abriu");
var secs=[].slice.call(document.querySelectorAll('section[id^="cap-"],#conclusao')),vis={},acc={};
if("IntersectionObserver" in window){var io=new IntersectionObserver(function(es){es.forEach(function(e){var k=e.target.id;if(e.isIntersecting&&e.intersectionRatio>=.3){if(!vis[k])vis[k]=Date.now()}else if(vis[k]){acc[k]=(acc[k]||0)+(Date.now()-vis[k])/1000;delete vis[k]}})},{threshold:[0,.3]});secs.forEach(function(x){io.observe(x)})}
function flush(){var now=Date.now();Object.keys(vis).forEach(function(k){acc[k]=(acc[k]||0)+(now-vis[k])/1000;vis[k]=now});Object.keys(acc).forEach(function(k){if(acc[k]>=1)s(k==="conclusao"?"fim":"cap",k,Math.round(acc[k]))});acc={}}
setInterval(flush,15000);document.addEventListener("visibilitychange",function(){if(document.visibilityState==="hidden")flush()});
window.addEventListener("beforeprint",function(){s("pdf")});})();</script>`;
}

function gatePage(doc, id, vals, erro){
  const v = vals || {};
  const org = doc.organizador || "";
  const quem = org ? "a organização do evento (" + escH(org) + ")" : "a organização do evento";
  return `<!doctype html><html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="robots" content="noindex"><title>${escH(doc.titulo || "E-book")}</title>
<link rel="stylesheet" href="/fonts.css">
<style>
:root{--ink:#1B1C20;--g:#4A4D53;--l:#E3E5EA;--bg:#F3F4F6;--o:#FF3D03;--od:#C92D00}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font-family:'Barlow NS','Barlow','Segoe UI',Roboto,Arial,sans-serif;font-size:16px;line-height:1.5}
main{max-width:480px;margin:0 auto;padding:32px 16px 40px}
.k{display:flex;align-items:center;gap:10px;font-size:13px;font-weight:600;letter-spacing:2px;text-transform:uppercase;color:var(--od)}
.k i{display:inline-flex;align-items:center}.k i::before,.k i::after{content:"";width:7px;height:7px;border-radius:50%;background:var(--o)}.k i b{width:16px;height:2px;background:var(--o)}
h1{margin:10px 0 8px;font-size:clamp(26px,7vw,34px);line-height:1.12;font-weight:300;text-transform:uppercase;letter-spacing:.3px;text-wrap:balance}
.ev{margin:0 0 6px;color:var(--g);font-size:15px}
.lead{margin:14px 0 22px;color:var(--g);text-wrap:pretty}
form{display:flex;flex-direction:column;gap:14px;background:#fff;border:1px solid var(--l);border-radius:12px;padding:20px 16px}
label{display:flex;flex-direction:column;gap:6px;font-size:14px;font-weight:600}
label .lb{font-weight:600;color:var(--ink)}
label .lb span{font-weight:400;color:var(--g)}
input[type=text],input[type=email]{font:inherit;font-size:16px;padding:12px;border:1px solid #C5CAD2;border-radius:8px;background:#fff;color:var(--ink);min-height:48px}
input:focus-visible,button:focus-visible{outline:2px solid var(--o);outline-offset:2px}
.ck{flex-direction:row;align-items:flex-start;gap:10px;font-weight:400;font-size:14px;color:var(--g)}
.ck input{width:22px;height:22px;margin:0;flex:0 0 auto;accent-color:var(--o)}
button{font:inherit;font-weight:700;font-size:17px;min-height:52px;border:0;border-radius:8px;background:var(--o);color:#fff;cursor:pointer;transition:background-color .15s ease-out,transform .1s ease-out}
button:hover{background:#E83600}button:active{transform:scale(.98)}
.err{margin:0;padding:10px 12px;border-radius:8px;background:#FFE9E1;color:#8A2000;font-size:14px}
.hp{position:absolute;left:-9999px;width:1px;height:1px;overflow:hidden}
.fine{margin:16px 2px 0;font-size:13px;color:var(--g)}
.by{margin:28px 0 0;font-size:12.5px;color:#6B7079;text-align:center}
.by a{color:inherit}
</style></head><body><main>
<div class="k"><i><b></b></i>E-book da palestra</div>
<h1>${escH(doc.titulo || "E-book")}</h1>
${doc.evento ? `<p class="ev">${escH(doc.evento)}</p>` : ""}
<p class="lead">Escrito ao vivo a partir da palestra, com os principais pontos, exemplos e um resumo para levar com você. Preencha para abrir e baixar em PDF.</p>
<form method="post" action="/e/${id}/cadastro" novalidate>
${erro ? `<p class="err" role="alert">${escH(erro)}</p>` : ""}
<label for="nome">Nome<input id="nome" name="nome" type="text" autocomplete="name" required value="${escH(v.nome)}"></label>
<label for="email">E-mail<input id="email" name="email" type="email" autocomplete="email" inputmode="email" required value="${escH(v.email)}"></label>
<label for="empresa">Empresa<input id="empresa" name="empresa" type="text" autocomplete="organization" required value="${escH(v.empresa)}"></label>
<label for="cargo"><span class="lb">Cargo <span>(opcional)</span></span><input id="cargo" name="cargo" type="text" autocomplete="organization-title" value="${escH(v.cargo)}"></label>
<label class="ck" for="aceite"><input id="aceite" name="aceite" type="checkbox" value="1"${v.aceite ? " checked" : ""}>Quero receber outros conteúdos d${org ? "a organização do evento (" + escH(org) + ")" : "a organização do evento"}.</label>
<div class="hp" aria-hidden="true"><label for="site">Não preencha<input id="site" name="site" type="text" tabindex="-1" autocomplete="off"></label></div>
<button type="submit">Abrir o e-book</button>
</form>
<p class="fine">Seus dados ficam com ${quem}, para enviar este e-book e, se você marcar a opção acima, outros conteúdos. Para remover seus dados, fale com ${quem}.</p>
<p class="by">Feito ao vivo com <a href="/">Stagebook</a></p>
</main></body></html>`;
}

async function showDoc(env, req, id){
  const d = await env.DB.prepare("SELECT id, titulo, evento, tipo, html, cadastro, organizador FROM documentos WHERE id = ?").bind(id).first();
  if (!d) return new Response("<!doctype html><meta charset=utf-8><title>Não encontrado</title><p style='font-family:sans-serif;padding:24px'>Este documento não existe ou foi apagado.</p>", { status: 404, headers: { "content-type": "text/html; charset=utf-8" } });
  let leitor = cookieOf(req, "pvl");
  const headers = { "content-type": "text/html; charset=utf-8", "cache-control": "private, no-store", "x-robots-tag": "noindex" };
  if (d.cadastro && !leitor.startsWith("c_")) return new Response(gatePage(d, id), { headers });
  if (!leitor){ leitor = "a_" + randId(10); headers["set-cookie"] = leitorCookie(id, leitor); }
  const html = d.html.includes("</body>") ? d.html.replace(/<\/body>(?![\s\S]*<\/body>)/, trackerJS(id) + "</body>") : d.html + trackerJS(id);
  return new Response(html, { headers });
}

async function cadastrar(env, req, id, origin){
  const d = await env.DB.prepare("SELECT id, titulo, evento, cadastro, organizador FROM documentos WHERE id = ?").bind(id).first();
  if (!d) return new Response("Não encontrado", { status: 404 });
  let f; try { f = await req.formData(); } catch(e){ return Response.redirect(origin + "/e/" + id + "/", 303); }
  const g = k => String(f.get(k) || "").trim().replace(/\s+/g, " ");
  const v = { nome: g("nome").slice(0, 120), email: g("email").toLowerCase().slice(0, 160), empresa: g("empresa").slice(0, 120), cargo: g("cargo").slice(0, 120), aceite: f.get("aceite") ? 1 : 0 };
  const html = (msg, st) => new Response(gatePage(d, id, v, msg), { status: st || 400, headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" } });
  if (g("site")) return Response.redirect(origin + "/e/" + id + "/", 303);   // robô
  if (v.nome.length < 2) return html("Escreva o seu nome.");
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]{2,}$/.test(v.email)) return html("Confira o e-mail: ele parece incompleto.");
  if (v.empresa.length < 2) return html("Escreva o nome da empresa onde você trabalha.");
  const old = await env.DB.prepare("SELECT id FROM contatos WHERE doc = ? AND email = ?").bind(id, v.email).first();
  const cid = old ? old.id : randId(12);
  if (old) await env.DB.prepare("UPDATE contatos SET nome = ?, empresa = ?, cargo = ?, aceite = MAX(aceite, ?) WHERE id = ?").bind(v.nome, v.empresa, v.cargo, v.aceite, cid).run();
  else await env.DB.prepare("INSERT INTO contatos (id, doc, nome, email, empresa, cargo, aceite, criado) VALUES (?, ?, ?, ?, ?, ?, ?, ?)").bind(cid, id, v.nome, v.email, v.empresa, v.cargo, v.aceite, Date.now()).run();
  return new Response(null, { status: 303, headers: { location: origin + "/e/" + id + "/", "set-cookie": leitorCookie(id, "c_" + cid) } });
}

async function registrarLeitura(env, req, id){
  const leitor = cookieOf(req, "pvl");
  if (!/^[ac]_[a-z0-9]{6,20}$/.test(leitor)) return new Response(null, { status: 204 });
  let b = {}; try { b = JSON.parse(await req.text()); } catch(e){ return new Response(null, { status: 204 }); }
  let item = "";
  if (b.t === "abriu" || b.t === "pdf" || b.t === "fim") item = b.t;
  else if (b.t === "cap" && /^cap-\d{1,2}$/.test(b.c || "")) item = b.c;
  if (!item) return new Response(null, { status: 204 });
  const ok = await env.DB.prepare("SELECT 1 AS x FROM documentos WHERE id = ?").bind(id).first();
  if (!ok) return new Response(null, { status: 204 });
  const sec = Math.max(0, Math.min(120, num(b.s, 0)));
  const now = Date.now();
  await env.DB.prepare(`INSERT INTO leituras (doc, leitor, item, segundos, vezes, primeiro, ultimo) VALUES (?, ?, ?, ?, 1, ?, ?)
    ON CONFLICT(doc, leitor, item) DO UPDATE SET segundos = segundos + excluded.segundos, vezes = vezes + 1, ultimo = excluded.ultimo`).bind(id, leitor, item, sec, now, now).run();
  return new Response(null, { status: 204 });
}

/* ---------- relatório para quem organizou: contatos e o que foi lido ---------- */
async function relatorio(env, u, id, csv, origin){
  const d = await env.DB.prepare("SELECT id, usuario, titulo, evento, tipo, criado, cadastro, organizador, capitulos FROM documentos WHERE id = ?").bind(id).first();
  if (!d || (d.usuario !== u.id && !isAdmin(env, u.email))) return err(404, "doc", "Documento não encontrado.");
  const contatos = (await env.DB.prepare("SELECT id, nome, email, empresa, cargo, aceite, criado FROM contatos WHERE doc = ? ORDER BY criado").bind(id).all()).results || [];
  const lt = (await env.DB.prepare("SELECT leitor, item, segundos, vezes FROM leituras WHERE doc = ?").bind(id).all()).results || [];
  let caps = []; try { caps = JSON.parse(d.capitulos || "[]"); } catch(e){}
  const por = new Map();
  lt.forEach(r => { if (!por.has(r.leitor)) por.set(r.leitor, {}); por.get(r.leitor)[r.item] = r; });
  const lidosDe = l => Object.keys(l).filter(k => k.startsWith("cap-") && l[k].segundos >= LIDO_S).length;
  const leitores = [...por.values()].filter(l => l.abriu);
  const capStats = caps.map(c => {
    const rows = lt.filter(r => r.item === "cap-" + c.n && r.segundos >= LIDO_S);
    return { n: c.n, titulo: c.titulo, leitores: rows.length, mediaSeg: rows.length ? Math.round(rows.reduce((a, r) => a + r.segundos, 0) / rows.length) : 0 };
  });
  const lista = contatos.map(c => {
    const l = por.get("c_" + c.id) || {};
    return { nome: c.nome, email: c.email, empresa: c.empresa, cargo: c.cargo, aceite: !!c.aceite, criado: c.criado, capitulosLidos: lidosDe(l), fim: !!(l.fim && l.fim.segundos >= 3), pdf: !!l.pdf, aberturas: l.abriu ? l.abriu.vezes : 0 };
  });
  if (csv){
    const q = x => '"' + String(x == null ? "" : x).replace(/"/g, '""') + '"';
    const dt = t => new Date(t - 3 * 3600e3).toISOString().replace("T", " ").slice(0, 16);
    const head = ["Nome", "E-mail", "Empresa", "Cargo", "Aceitou receber conteúdos", "Cadastrado em", "Capítulos lidos", "Leu até o fim", "Baixou o PDF"];
    const body = lista.map(c => [c.nome, c.email, c.empresa, c.cargo, c.aceite ? "sim" : "não", dt(c.criado), c.capitulosLidos + " de " + caps.length, c.fim ? "sim" : "não", c.pdf ? "sim" : "não"].map(q).join(";"));
    const name = "contatos-" + id + ".csv";
    return new Response("﻿" + [head.map(q).join(";"), ...body].join("\r\n"), { headers: { "content-type": "text/csv; charset=utf-8", "content-disposition": `attachment; filename="${name}"`, "cache-control": "no-store" } });
  }
  const empresas = {};
  contatos.forEach(c => { const k = (c.empresa || "").trim(); if (k) empresas[k] = (empresas[k] || 0) + 1; });
  return json({
    doc: { id: d.id, titulo: d.titulo, evento: d.evento, tipo: d.tipo, criado: d.criado, cadastro: !!d.cadastro, organizador: d.organizador, url: origin + "/e/" + d.id + "/" },
    totais: {
      cadastros: contatos.length,
      aceitaram: contatos.filter(c => c.aceite).length,
      leitores: leitores.length,
      leramAteFim: leitores.filter(l => l.fim && l.fim.segundos >= 3).length,
      baixaramPdf: leitores.filter(l => l.pdf).length,
      capitulos: caps.length
    },
    capitulos: capStats,
    empresas: Object.entries(empresas).sort((a, b) => b[1] - a[1]).map(([nome, n]) => ({ nome, n })),
    contatos: lista.reverse()
  });
}

/* ---------- assinatura pelo Mercado Pago ---------- */
async function mp(env, path, opts){
  const o = opts || {};
  const r = await fetch(MP(env) + path, { method: o.method || "GET", headers: { "authorization": "Bearer " + env.MP_TOKEN, ...(o.body ? { "content-type": "application/json" } : {}) }, body: o.body ? JSON.stringify(o.body) : undefined });
  let data = null; try { data = await r.json(); } catch(e){}
  return { ok: r.ok, status: r.status, data };
}
async function syncAssinatura(env, pre){
  if (!pre || !pre.id) return null;
  const uid = pre.external_reference;
  const u = uid ? await getUser(env, uid) : null;
  if (!u) return null;
  let pago = u.pago_ate || 0;
  if (pre.status === "authorized"){
    const next = Date.parse(pre.next_payment_date || "") || (Date.now() + 31 * DAY);
    pago = Math.max(pago, next + 2 * DAY);    // 2 dias de folga para a cobrança cair
  }
  await env.DB.prepare("UPDATE usuarios SET pago_ate = ?, mp_assinatura = ?, mp_status = ?, mp_conferido = ? WHERE id = ?").bind(pago, pre.id, pre.status || "", Date.now(), u.id).run();
  return pre.status;
}
async function assinar(env, req, u, origin){
  if (!env.MP_TOKEN) return err(503, "sem_mp", "A assinatura ainda não está ligada no servidor.");
  let b = {}; try { b = await req.json(); } catch(e){}
  const email = String(b.email || u.email).trim().toLowerCase();
  if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return err(400, "email", "Confira o e-mail da sua conta do Mercado Pago.");
  const r = await mp(env, "/preapproval", { method: "POST", body: {
    reason: "Stagebook: assinatura mensal",
    external_reference: u.id,
    payer_email: email,
    auto_recurring: { frequency: 1, frequency_type: "months", transaction_amount: num(env.PRECO, 39.9), currency_id: "BRL" },
    back_url: origin + "/api/assinatura/volta",
    status: "pending"
  }});
  if (!r.ok || !r.data || !r.data.init_point) return err(502, "mp", "O Mercado Pago não aceitou o pedido agora." + (r.data && r.data.message ? " (" + r.data.message + ")" : ""));
  await env.DB.prepare("UPDATE usuarios SET mp_assinatura = ?, mp_status = ? WHERE id = ?").bind(r.data.id, r.data.status || "pending", u.id).run();
  return json({ url: r.data.init_point });
}
async function conferirAssinatura(env, u, force){
  if (!env.MP_TOKEN || !u.mp_assinatura) return;
  if (!force && Date.now() - (u.mp_conferido || 0) < 60e3) return;
  if (!force && !["pending", "authorized"].includes(u.mp_status)) return;
  if (!force && u.mp_status === "authorized" && u.pago_ate - Date.now() > 3 * DAY) return;
  const r = await mp(env, "/preapproval/" + encodeURIComponent(u.mp_assinatura));
  if (r.ok) await syncAssinatura(env, r.data);
  else await env.DB.prepare("UPDATE usuarios SET mp_conferido = ? WHERE id = ?").bind(Date.now(), u.id).run();
}
async function cancelar(env, u){
  if (!env.MP_TOKEN || !u.mp_assinatura) return err(400, "sem_assinatura", "Não há assinatura para cancelar.");
  const r = await mp(env, "/preapproval/" + encodeURIComponent(u.mp_assinatura), { method: "PUT", body: { status: "cancelled" } });
  if (!r.ok) return err(502, "mp", "O Mercado Pago não confirmou o cancelamento. Tente de novo.");
  await env.DB.prepare("UPDATE usuarios SET mp_status = 'cancelled' WHERE id = ?").bind(u.id).run();
  return json({ ok: true });
}
async function avisoMP(env, req, url){
  // O aviso só diz "algo mudou": o servidor sempre confere direto no Mercado Pago, então um aviso falso não libera nada.
  let b = {}; try { b = await req.json(); } catch(e){}
  const tipo = b.type || b.topic || url.searchParams.get("type") || url.searchParams.get("topic") || "";
  const id = (b.data && b.data.id) || url.searchParams.get("data.id") || url.searchParams.get("id") || "";
  if (!env.MP_TOKEN || !id) return json({ ok: true });
  if (/preapproval/.test(tipo) && !/authorized_payment/.test(tipo)){
    const r = await mp(env, "/preapproval/" + encodeURIComponent(id)); if (r.ok) await syncAssinatura(env, r.data);
  } else if (/authorized_payment/.test(tipo)){
    const p = await mp(env, "/authorized_payments/" + encodeURIComponent(id));
    const pre = p.ok && p.data && p.data.preapproval_id;
    if (pre){ const r = await mp(env, "/preapproval/" + encodeURIComponent(pre)); if (r.ok) await syncAssinatura(env, r.data); }
  }
  return json({ ok: true });
}

/* ---------- administração ---------- */
async function adminResumo(env){
  const mes = mesBR();
  const r = await env.DB.prepare(`SELECT u.id, u.email, u.nome, u.criado, u.visto, u.pago_ate, u.mp_status, u.min_extra, u.bloqueado,
      COALESCE(m.audio_s, 0) AS mes_s, COALESCE(m.tokens, 0) AS mes_tok, COALESCE(t.audio_s, 0) AS total_s, COALESCE(t.tokens, 0) AS total_tok
    FROM usuarios u LEFT JOIN uso m ON m.usuario = u.id AND m.mes = ? LEFT JOIN uso t ON t.usuario = u.id AND t.mes = 'total'
    ORDER BY u.visto DESC LIMIT 500`).bind(mes).all();
  const docs = await env.DB.prepare("SELECT COUNT(*) AS n FROM documentos").first();
  return json({ mes, usuarios: r.results || [], documentos: docs ? docs.n : 0, preco: num(env.PRECO, 39.9), minPlano: num(env.MIN_PLANO, 600), minTeste: num(env.MIN_TESTE, 30) });
}
async function adminAcao(env, req){
  let b = {}; try { b = await req.json(); } catch(e){}
  const u = await env.DB.prepare("SELECT * FROM usuarios WHERE email = ?").bind(String(b.email || "").trim().toLowerCase()).first();
  if (!u) return err(404, "usuario", "Não achei ninguém com esse e-mail. A pessoa precisa entrar uma vez primeiro.");
  if (b.acao === "liberar_ate"){
    const t = Date.parse(String(b.data || "") + "T23:59:59-03:00");
    if (!isFinite(t)) return err(400, "data", "Data inválida.");
    await env.DB.prepare("UPDATE usuarios SET pago_ate = ? WHERE id = ?").bind(t, u.id).run();
  } else if (b.acao === "minutos"){
    await env.DB.prepare("UPDATE usuarios SET min_extra = MAX(0, min_extra + ?) WHERE id = ?").bind(num(b.minutos, 0), u.id).run();
  } else if (b.acao === "bloquear" || b.acao === "desbloquear"){
    await env.DB.prepare("UPDATE usuarios SET bloqueado = ? WHERE id = ?").bind(b.acao === "bloquear" ? 1 : 0, u.id).run();
  } else return err(400, "acao", "Ação desconhecida.");
  return json({ ok: true });
}

/* ---------- rotas ---------- */
export default {
  async fetch(req, env, ctx){
    const url = new URL(req.url);
    const path = url.pathname;
    const origin = url.origin;
    try {
      if (path.startsWith("/e/")){
        await ensureSchema(env);
        const m = path.match(/^\/e\/([a-z0-9-]{3,80})(\/?)(cadastro|ev)?$/);
        if (!m) return new Response("Não encontrado", { status: 404 });
        const id = m[1];
        if (m[3] === "cadastro" && req.method === "POST") return cadastrar(env, req, id, origin);
        if (m[3] === "ev" && req.method === "POST") return registrarLeitura(env, req, id);
        if (!m[2]) return Response.redirect(origin + "/e/" + id + "/", 301);
        return showDoc(env, req, id);
      }
      if (!path.startsWith("/api/")) return env.ASSETS.fetch(req);
      await ensureSchema(env);

      if (path === "/api/config") return json({ googleClientId: env.GOOGLE_CLIENT_ID || "", preco: num(env.PRECO, 39.9), minPlano: num(env.MIN_PLANO, 600), minTeste: num(env.MIN_TESTE, 30), dev: env.DEV_LOGIN === "1" });
      if (path === "/api/mp/aviso" && req.method === "POST") return avisoMP(env, req, url);

      if (path === "/api/entrar/google" && req.method === "POST"){
        let b = {}; try { b = await req.json(); } catch(e){}
        const c = await verifyGoogle(env, b.credential).catch(() => null);
        if (!c) return err(401, "login", "Não consegui confirmar sua conta Google. Tente de novo.");
        const id = await upsertUser(env, "g:" + c.sub, c.email, c.name, c.picture);
        return json({ ok: true }, 200, { "set-cookie": sessionCookie(await makeSession(env, id), 30 * 86400) });
      }
      if (path === "/api/entrar/teste" && req.method === "POST" && env.DEV_LOGIN === "1"){
        let b = {}; try { b = await req.json(); } catch(e){}
        const email = String(b.email || "teste@exemplo.com").toLowerCase();
        const id = await upsertUser(env, "d:" + email, email, b.nome || email.split("@")[0], "");
        return json({ ok: true }, 200, { "set-cookie": sessionCookie(await makeSession(env, id), 30 * 86400) });
      }
      if (path === "/api/sair") return json({ ok: true }, 200, { "set-cookie": sessionCookie("", 0) });

      const uid = await readSession(env, req);
      let u = await getUser(env, uid);
      if (path === "/api/assinatura/volta"){
        if (u){ const pid = url.searchParams.get("preapproval_id"); if (pid && pid !== u.mp_assinatura){ const r = await mp(env, "/preapproval/" + encodeURIComponent(pid)); if (r.ok && r.data && r.data.external_reference === u.id) await syncAssinatura(env, r.data); } else await conferirAssinatura(env, u, true); }
        return Response.redirect(origin + "/?assinatura=1", 302);
      }
      if (!u) return err(401, "login", "Entre com sua conta para continuar.");

      if (path === "/api/eu"){
        await conferirAssinatura(env, u, false);
        u = await getUser(env, u.id);
        if (Date.now() - (u.visto || 0) > 600e3) ctx.waitUntil(env.DB.prepare("UPDATE usuarios SET visto = ? WHERE id = ?").bind(Date.now(), u.id).run());
        return json({ usuario: { email: u.email, nome: u.nome, foto: u.foto }, saldo: await saldo(env, u), preco: num(env.PRECO, 39.9), minPlano: num(env.MIN_PLANO, 600) });
      }
      if (path === "/api/ia/texto" && req.method === "POST"){ const s = await saldo(env, u); if (!s.pode) return SEM_SALDO(s); return aiChat(env, req, u); }
      if (path === "/api/ia/audio" && req.method === "POST"){ const s = await saldo(env, u); if (!s.pode) return SEM_SALDO(s); return aiStt(env, req, u); }
      if (path === "/api/docs" && req.method === "POST") return saveDoc(env, req, u, origin);
      if (path === "/api/docs" && req.method === "GET") return listDocs(env, u, origin);
      const rel = path.match(/^\/api\/docs\/([a-z0-9-]{3,80})\/(relatorio|contatos\.csv)$/);
      if (rel) return relatorio(env, u, rel[1], rel[2] === "contatos.csv", origin);
      if (path === "/api/assinar" && req.method === "POST") return assinar(env, req, u, origin);
      if (path === "/api/cancelar" && req.method === "POST") return cancelar(env, u);

      if (path.startsWith("/api/admin/")){
        if (!isAdmin(env, u.email)) return err(403, "admin", "Só para administradores.");
        if (path === "/api/admin/resumo") return adminResumo(env);
        if (path === "/api/admin/acao" && req.method === "POST") return adminAcao(env, req);
      }
      return err(404, "rota", "Endereço desconhecido.");
    } catch(e){
      console.error("Stagebook:", e && e.stack || e);
      return err(500, "interno", "Algo deu errado no servidor. Tente de novo.");
    }
  }
};
