// NFL Zone — Gardien de notifications (Cloudflare Worker)
// Rôle : toutes les minutes, regarde les scores ESPN et envoie une notification
// (Web Push) aux téléphones abonnés aux équipes favorites : rappel, coup d'envoi,
// points marqués, score final. Aucune donnée personnelle n'est stockée : seulement
// l'adresse technique d'abonnement du téléphone et la liste des équipes suivies.

const ESPN_SB = 'https://site.api.espn.com/apis/site/v2/sports/football/nfl/scoreboard';
const TEAMS = ['ARI','ATL','BAL','BUF','CAR','CHI','CIN','CLE','DAL','DEN','DET','GB','HOU','IND','JAX','KC','LAC','LAR','LV','MIA','MIN','NE','NO','NYG','NYJ','PHI','PIT','SF','SEA','TB','TEN','WAS'];
const AL = { WSH: 'WAS', LA: 'LAR', JAC: 'JAX', OAK: 'LV' };
const cn = a => { a = String(a || '').toUpperCase(); return AL[a] || a; };
const PUSH_HOSTS = ['fcm.googleapis.com', 'web.push.apple.com', 'updates.push.services.mozilla.com', 'notify.windows.com', 'push.services.mozilla.com'];
const MAX_PUSH_PER_TICK = 35; // limite Cloudflare (offre gratuite : 50 appels par exécution)

/* ---------- utilitaires base64url / octets ---------- */
const enc = s => new TextEncoder().encode(s);
export const b64u = b => { const u = b instanceof Uint8Array ? b : new Uint8Array(b); let s = ''; for (let i = 0; i < u.length; i++) s += String.fromCharCode(u[i]); return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, ''); };
export const unb64u = s => { s = String(s).replace(/-/g, '+').replace(/_/g, '/'); while (s.length % 4) s += '='; const r = atob(s), u = new Uint8Array(r.length); for (let i = 0; i < r.length; i++) u[i] = r.charCodeAt(i); return u; };
const cat = (...a) => { const n = a.reduce((x, y) => x + y.length, 0), o = new Uint8Array(n); let p = 0; for (const y of a) { o.set(y, p); p += y.length; } return o; };

async function hkdf(salt, ikm, info, len) {
  const k = await crypto.subtle.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  return new Uint8Array(await crypto.subtle.deriveBits({ name: 'HKDF', hash: 'SHA-256', salt, info }, k, len * 8));
}

/* ---------- chiffrement Web Push (RFC 8291, aes128gcm) ---------- */
export async function encryptPayload(sub, payload, opt = {}) {
  const ua = unb64u(sub.keys.p256dh), auth = unb64u(sub.keys.auth);
  const eph = opt.eph || await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
  const asPub = new Uint8Array(await crypto.subtle.exportKey('raw', eph.publicKey));
  const uaKey = await crypto.subtle.importKey('raw', ua, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  const secret = new Uint8Array(await crypto.subtle.deriveBits({ name: 'ECDH', public: uaKey }, eph.privateKey, 256));
  const salt = opt.salt || crypto.getRandomValues(new Uint8Array(16));
  const ikm = await hkdf(auth, secret, cat(enc('WebPush: info\0'), ua, asPub), 32);
  const cek = await hkdf(salt, ikm, enc('Content-Encoding: aes128gcm\0'), 16);
  const nonce = await hkdf(salt, ikm, enc('Content-Encoding: nonce\0'), 12);
  const key = await crypto.subtle.importKey('raw', cek, 'AES-GCM', false, ['encrypt']);
  const body = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, key, cat(payload, new Uint8Array([2]))));
  const rs = new Uint8Array([0, 0, 16, 0]); // 4096
  return cat(salt, rs, new Uint8Array([asPub.length]), asPub, body);
}

/* ---------- VAPID (RFC 8292) ---------- */
let vapidKey = null;
async function vapidJwt(env, audience) {
  if (!vapidKey) vapidKey = await crypto.subtle.importKey('jwk', JSON.parse(env.VAPID_PRIVATE), { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
  const h = b64u(enc(JSON.stringify({ typ: 'JWT', alg: 'ES256' })));
  const p = b64u(enc(JSON.stringify({ aud: audience, exp: Math.floor(Date.now() / 1000) + 12 * 3600, sub: env.VAPID_SUBJECT || 'mailto:admin@example.com' })));
  const sig = new Uint8Array(await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, vapidKey, enc(h + '.' + p)));
  return h + '.' + p + '.' + b64u(sig);
}

const jwtCache = new Map();
export async function sendPush(env, sub, message) {
  const u = new URL(sub.endpoint);
  let jwt = jwtCache.get(u.origin);
  if (!jwt) { jwt = await vapidJwt(env, u.origin); jwtCache.set(u.origin, jwt); }
  const body = await encryptPayload(sub, enc(JSON.stringify(message)));
  return fetch(sub.endpoint, {
    method: 'POST',
    headers: { Authorization: 'vapid t=' + jwt + ', k=' + env.VAPID_PUBLIC, 'Content-Encoding': 'aes128gcm', 'Content-Type': 'application/octet-stream', TTL: '3600', Urgency: 'high' },
    body,
  });
}

/* ---------- stockage (KV) ---------- */
const jget = async (env, k, d) => { const v = await env.KV.get(k); if (!v) return d; try { return JSON.parse(v); } catch (e) { return d; } };
const jput = (env, k, v) => env.KV.put(k, JSON.stringify(v));
const idOf = async ep => b64u(new Uint8Array(await crypto.subtle.digest('SHA-256', enc(ep)))).slice(0, 32);
const okHost = ep => { try { const u = new URL(ep); return u.protocol === 'https:' && PUSH_HOSTS.some(h => u.hostname === h || u.hostname.endsWith('.' + h)); } catch (e) { return false; } };

async function setSubscription(env, sub, teams, lang, rz) {
  const id = await idOf(sub.endpoint);
  const old = await jget(env, 'sub:' + id, { teams: [] });
  const keep = { e: sub.endpoint, k: { p256dh: sub.keys.p256dh, auth: sub.keys.auth }, l: lang === 'en' ? 'en' : 'fr', z: rz ? 1 : 0 };
  const touched = new Set([...(old.teams || []), ...teams]);
  for (const t of touched) {
    let arr = await jget(env, 'team:' + t, []);
    arr = arr.filter(x => x.e !== sub.endpoint);
    if (teams.includes(t)) arr.push(keep);
    if (arr.length) await jput(env, 'team:' + t, arr); else await env.KV.delete('team:' + t);
  }
  if (teams.length) await jput(env, 'sub:' + id, { teams }); else await env.KV.delete('sub:' + id);
  const active = new Set(await jget(env, 'active', []));
  for (const t of touched) { if (teams.includes(t)) active.add(t); else { const a = await jget(env, 'team:' + t, []); if (!a.length) active.delete(t); } }
  await jput(env, 'active', [...active]);
}

/* ---------- messages ---------- */
const PER = { fr: ['', '1er quart-temps', '2e quart-temps', '3e quart-temps', '4e quart-temps', 'prolongation'], en: ['', '1st quarter', '2nd quarter', '3rd quarter', '4th quarter', 'overtime'] };
function scoreLabel(d, l) { return d === 6 || d === 7 || d === 8 ? (l === 'en' ? 'Touchdown' : 'Touchdown') : d === 3 ? (l === 'en' ? 'Field goal' : 'Field goal') : d === 2 ? (l === 'en' ? 'Safety / 2-pt' : 'Safety / 2 pts') : (l === 'en' ? 'Score' : 'Score'); }
export function build(kind, g, l, extra) {
  const line = g.away + ' ' + g.as + ' – ' + g.hs + ' ' + g.home;
  const fr = l !== 'en', q = (PER[fr ? 'fr' : 'en'][Math.min(g.per, 5)] || '') + (g.clock ? ' ' + g.clock : '');
  if (kind === 'rem') return { title: (fr ? '⏰ Dans 30 min : ' : '⏰ In 30 min: ') + g.away + ' @ ' + g.home, body: fr ? 'Le match va bientôt commencer.' : 'The game starts soon.', tag: 'g' + g.id };
  if (kind === 'ko') return { title: (fr ? '🏈 C’est parti : ' : '🏈 Kickoff: ') + g.away + ' @ ' + g.home, body: fr ? 'Le match commence !' : 'The game is starting!', tag: 'g' + g.id };
  if (kind === 'rz') return { title: (fr ? '🔴 Red Zone : ' : '🔴 Red Zone: ') + extra.team + (fr ? ' attaque' : ' is driving'), body: line + (extra.pt ? ' · ' + extra.pt : '') + (q ? ' · ' + q : ''), tag: 'rz' + g.id };
  if (kind === 'sc') return { title: '🏈 ' + extra.team + ' — ' + scoreLabel(extra.d, l), body: line + (q ? ' · ' + q : ''), tag: 'g' + g.id };
  return { title: (fr ? '🏁 Terminé : ' : '🏁 Final: ') + line, body: fr ? 'Le match est terminé.' : 'The game is over.', tag: 'g' + g.id };
}

/* ---------- surveillance ESPN ---------- */
export function parse(sb) {
  return (sb.events || []).map(e => {
    const c = (e.competitions || [])[0] || {}, C = c.competitors || [];
    const A = C.find(x => x.homeAway === 'away') || {}, H = C.find(x => x.homeAway === 'home') || {};
    const st = c.status && c.status.type && c.status.type.state;
    const n = x => { const v = parseInt(x && x.score && (x.score.displayValue != null ? x.score.displayValue : x.score), 10); return isNaN(v) ? 0 : v; };
    const sc = x => { const v = parseInt(x && x.score, 10); return isNaN(v) ? 0 : v; };
    return { id: String(e.id), s: st || 'pre', away: cn(A.team && A.team.abbreviation), home: cn(H.team && H.team.abbreviation), as: sc(A), hs: sc(H), per: (c.status && c.status.period) || 0, clock: (c.status && c.status.displayClock) || '', ms: Date.parse(e.date), rz: !!(c.situation && c.situation.isRedZone), pos: String((c.situation && c.situation.possession) || ''), pt: (c.situation && c.situation.possessionText) || '', aid: String((A.team && A.team.id) || ''), hid: String((H.team && H.team.id) || '') };
  }).filter(g => g.id && g.away && g.home);
}

export async function tick(env, fetchFn = fetch, now = Date.now()) {
  const active = await jget(env, 'active', []);
  if (!active.length) return { sent: 0, note: 'aucun abonné' };
  const r = await fetchFn(ESPN_SB);
  if (!r.ok) return { sent: 0, note: 'ESPN ' + r.status };
  const games = parse(await r.json());
  const st = await jget(env, 'st', {}), ns = {};
  let sent = 0;
  const jobs = [];
  for (const g of games) {
    if (!active.includes(g.away) && !active.includes(g.home)) continue;
    const prev = st[g.id], zt = g.s === 'in' && g.rz ? (g.pos === g.aid ? g.away : g.pos === g.hid ? g.home : '') : '', cur = { s: g.s, a: g.as, h: g.hs, r: prev && prev.r ? 1 : 0, z: zt };
    if (prev) {
      if (prev.s === 'pre' && g.s === 'in') jobs.push(['ko', g]);
      if (g.s === 'in' || (g.s === 'post' && prev.s === 'in')) {
        if (g.as > prev.a) jobs.push(['sc', g, { team: g.away, d: g.as - prev.a }]);
        if (g.hs > prev.h) jobs.push(['sc', g, { team: g.home, d: g.hs - prev.h }]);
      }
      if (zt && prev.z !== zt) jobs.push(['rz', g, { team: zt, pt: g.pt }]);
      if (prev.s !== 'post' && g.s === 'post' && prev.s !== undefined) jobs.push(['fin', g]);
    }
    if (g.s === 'pre' && !cur.r && g.ms && g.ms - now <= 30 * 60e3 && g.ms - now > 0) { cur.r = 1; jobs.push(['rem', g]); }
    ns[g.id] = cur;
  }
  for (const [kind, g, extra] of jobs) {
    const subs = new Map();
    for (const t of [g.away, g.home]) for (const s of await jget(env, 'team:' + t, [])) subs.set(s.e, s);
    for (const s of subs.values()) {
      if (kind === 'rz' && !s.z) continue;
      if (sent >= MAX_PUSH_PER_TICK) break;
      sent++;
      try {
        const res = await sendPush(env, { endpoint: s.e, keys: s.k }, build(kind, g, s.l, extra));
        if (res.status === 404 || res.status === 410) await setSubscription(env, { endpoint: s.e, keys: s.k }, [], 'fr');
      } catch (e) { /* on réessaiera à la prochaine minute pour les événements suivants */ }
    }
  }
  if (JSON.stringify(ns) !== JSON.stringify(st)) await jput(env, 'st', ns);
  return { sent, jobs: jobs.length };
}

/* ---------- API publique ---------- */
function cors(env, req) {
  const o = env.ALLOWED_ORIGIN || '*';
  return { 'Access-Control-Allow-Origin': o, 'Access-Control-Allow-Methods': 'POST, GET, OPTIONS', 'Access-Control-Allow-Headers': 'Content-Type', 'Access-Control-Max-Age': '86400', Vary: 'Origin' };
}
const J = (env, req, d, s = 200) => new Response(JSON.stringify(d), { status: s, headers: { 'Content-Type': 'application/json', ...cors(env, req) } });

export async function handle(req, env) {
  if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors(env, req) });
  const u = new URL(req.url);
  if (req.method === 'GET') return J(env, req, { ok: true, service: 'nflzone-push' });
  let b; try { b = await req.json(); } catch (e) { return J(env, req, { ok: false, error: 'json' }, 400); }
  const sub = b && b.sub;
  if (!sub || !sub.endpoint || !sub.keys || !sub.keys.p256dh || !sub.keys.auth || !okHost(sub.endpoint)) return J(env, req, { ok: false, error: 'abonnement invalide' }, 400);
  if (u.pathname === '/subscribe') {
    const teams = [...new Set((b.teams || []).map(cn))].filter(t => TEAMS.includes(t)).slice(0, 8);
    await setSubscription(env, sub, teams, b.lang, !!b.rz);
    return J(env, req, { ok: true, teams });
  }
  if (u.pathname === '/unsubscribe') { await setSubscription(env, sub, [], 'fr'); return J(env, req, { ok: true }); }
  if (u.pathname === '/test') {
    const id = await idOf(sub.endpoint), known = await jget(env, 'sub:' + id, null);
    if (!known) return J(env, req, { ok: false, error: 'inconnu' }, 404);
    const l = b.lang === 'en' ? 'en' : 'fr';
    const r = await sendPush(env, sub, { title: l === 'en' ? '✅ Notifications enabled' : '✅ Notifications activées', body: l === 'en' ? 'You will be notified when your teams play.' : 'Tu seras prévenu quand tes équipes jouent.', tag: 'test' });
    return J(env, req, { ok: r.status < 300, status: r.status });
  }
  return J(env, req, { ok: false, error: 'route' }, 404);
}

export default {
  fetch: (req, env) => handle(req, env),
  scheduled: (ev, env, ctx) => { ctx.waitUntil(tick(env)); },
};
