/* Palco Vivo: servidor na Cloudflare
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
    env.DB.prepare(`CREATE INDEX IF NOT EXISTS documentos_usuario ON documentos (usuario, criado)`)
  ]);
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
const SEM_SALDO = s => err(402, "sem_saldo", s.bloqueado ? "Esta conta foi pausada. Fale com o responsável pelo Palco Vivo." : s.ativo ? "Os minutos deste mês acabaram. Eles voltam no dia 1º." : "Os minutos de teste acabaram. Assine para continuar usando.");

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
  let id = String(b.id || "");
  if (id){
    const cur = await env.DB.prepare("SELECT usuario FROM documentos WHERE id = ?").bind(id).first();
    if (!cur || cur.usuario !== u.id) id = "";
  }
  if (id){
    await env.DB.prepare("UPDATE documentos SET html = ?, titulo = ?, evento = ?, atualizado = ? WHERE id = ?").bind(html, String(b.titulo || "").slice(0, 200), String(b.evento || "").slice(0, 200), now, id).run();
  } else {
    id = randId(7) + "-" + slugify(b.titulo);
    await env.DB.prepare("INSERT INTO documentos (id, usuario, titulo, evento, tipo, html, criado, atualizado) VALUES (?, ?, ?, ?, ?, ?, ?, ?)")
      .bind(id, u.id, String(b.titulo || "").slice(0, 200), String(b.evento || "").slice(0, 200), b.tipo === "ata" ? "ata" : "ebook", html, now, now).run();
  }
  return json({ id, url: origin + "/e/" + id + "/" });
}
async function listDocs(env, u, origin){
  const r = await env.DB.prepare("SELECT id, titulo, evento, tipo, criado FROM documentos WHERE usuario = ? ORDER BY criado DESC LIMIT 100").bind(u.id).all();
  return json({ docs: (r.results || []).map(d => Object.assign(d, { url: origin + "/e/" + d.id + "/" })) });
}
async function showDoc(env, id){
  const d = await env.DB.prepare("SELECT html FROM documentos WHERE id = ?").bind(id).first();
  if (!d) return new Response("<!doctype html><meta charset=utf-8><title>Não encontrado</title><p style='font-family:sans-serif;padding:24px'>Este documento não existe ou foi apagado.</p>", { status: 404, headers: { "content-type": "text/html; charset=utf-8" } });
  return new Response(d.html, { headers: { "content-type": "text/html; charset=utf-8", "cache-control": "public, max-age=60", "x-robots-tag": "noindex" } });
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
    reason: "Palco Vivo: assinatura mensal",
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
        const id = decodeURIComponent(path.slice(3).replace(/\/+$/, ""));
        if (!/^[a-z0-9-]{3,80}$/.test(id)) return new Response("Não encontrado", { status: 404 });
        if (!path.endsWith("/")) return Response.redirect(origin + "/e/" + id + "/", 301);
        return showDoc(env, id);
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
      if (path === "/api/assinar" && req.method === "POST") return assinar(env, req, u, origin);
      if (path === "/api/cancelar" && req.method === "POST") return cancelar(env, u);

      if (path.startsWith("/api/admin/")){
        if (!isAdmin(env, u.email)) return err(403, "admin", "Só para administradores.");
        if (path === "/api/admin/resumo") return adminResumo(env);
        if (path === "/api/admin/acao" && req.method === "POST") return adminAcao(env, req);
      }
      return err(404, "rota", "Endereço desconhecido.");
    } catch(e){
      console.error("Palco Vivo:", e && e.stack || e);
      return err(500, "interno", "Algo deu errado no servidor. Tente de novo.");
    }
  }
};
