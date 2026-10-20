// Godgram server — no npm install needed. Run: node server.js
const http = require('http'), fs = require('fs'), path = require('path'), crypto = require('crypto'), os = require('os');
const PORT = process.env.PORT || 3000, DB = path.join(__dirname, 'data.json');

let db = { users: {}, tokens: {}, msgs: [], groups: {} };
try { db = JSON.parse(fs.readFileSync(DB, 'utf8')); } catch (e) {}
db.groups = db.groups || {};
const save = () => fs.writeFile(DB, JSON.stringify(db), () => {});
const clients = {}; // username -> Set of SSE responses

const hash = (p, salt) => crypto.scryptSync(p, salt, 32).toString('hex');
const json = (res, code, obj) => { res.writeHead(code, { 'Content-Type': 'application/json' }); res.end(JSON.stringify(obj)); };
const readBody = req => new Promise(ok => {
  let b = '';
  req.on('data', c => { b += c; if (b.length > 1.5e6) req.destroy(); });
  req.on('end', () => { try { ok(JSON.parse(b || '{}')); } catch (e) { ok({}); } });
});
const push = (u, ev) => (clients[u] || new Set()).forEach(r => r.write('data: ' + JSON.stringify(ev) + '\n\n'));
const newToken = u => { const t = crypto.randomBytes(24).toString('hex'); db.tokens[t] = u; save(); return t; };

const ICON = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512"><rect width="512" height="512" rx="110" fill="#16213b"/><text x="256" y="350" font-size="300" font-weight="800" text-anchor="middle" fill="#f5b83d" font-family="sans-serif">گ</text></svg>';
const ASSETS = {
  '/manifest.json': ['application/manifest+json', JSON.stringify({ name: 'گودگرام', short_name: 'گودگرام', start_url: '/', display: 'standalone', dir: 'rtl', lang: 'fa', background_color: '#16213b', theme_color: '#16213b', icons: [{ src: '/icon.svg', sizes: 'any', type: 'image/svg+xml', purpose: 'any' }] })],
  '/sw.js': ['text/javascript', "self.addEventListener('install',()=>self.skipWaiting());self.addEventListener('activate',e=>e.waitUntil(clients.claim()));self.addEventListener('fetch',()=>{});"],
  '/icon.svg': ['image/svg+xml', ICON]
};

// very small rate limit for login/register (per IP)
const hits = {};
const limited = ip => { const n = Date.now(), a = (hits[ip] = (hits[ip] || []).filter(t => n - t < 60000)); a.push(n); return a.length > 15; };

http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://x'), p = url.pathname;

  if (ASSETS[p]) { res.writeHead(200, { 'Content-Type': ASSETS[p][0] + '; charset=utf-8' }); return res.end(ASSETS[p][1]); }
  if (!p.startsWith('/api/')) {
    return fs.readFile(path.join(__dirname, 'index.html'), (e, d) => {
      res.writeHead(e ? 500 : 200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(e ? 'index.html not found' : d);
    });
  }

  if (req.method === 'POST' && (p === '/api/register' || p === '/api/login')) {
    if (limited(req.socket.remoteAddress)) return json(res, 429, { error: 'تلاش زیاد؛ کمی بعد دوباره امتحان کن.' });
    const b = await readBody(req), u = String(b.u || '').toLowerCase(), pw = String(b.p || '');
    if (p === '/api/register') {
      if (!/^[a-z0-9_]{3,20}$/.test(u)) return json(res, 400, { error: 'نام کاربری باید ۳ تا ۲۰ حرف انگلیسی، عدد یا _ باشد.' });
      if (pw.length < 6) return json(res, 400, { error: 'رمز عبور حداقل ۶ کاراکتر باشد.' });
      if (db.users[u]) return json(res, 409, { error: 'این نام کاربری قبلاً گرفته شده.' });
      const salt = crypto.randomBytes(16).toString('hex');
      db.users[u] = { name: String(b.name || u).trim().slice(0, 30) || u, salt, hash: hash(pw, salt) };
      return json(res, 200, { token: newToken(u), u, name: db.users[u].name });
    }
    const user = db.users[u];
    if (!user || hash(pw, user.salt) !== user.hash) return json(res, 401, { error: 'نام کاربری یا رمز عبور اشتباه است.' });
    return json(res, 200, { token: newToken(u), u, name: user.name });
  }

  const token = (req.headers.authorization || '').slice(7) || url.searchParams.get('token');
  const me = db.tokens[token];
  if (!me || !db.users[me]) return json(res, 401, { error: 'auth' });

  if (p === '/api/me') return json(res, 200, { u: me, name: db.users[me].name });

  if (p === '/api/stream') {
    res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', Connection: 'keep-alive' });
    res.write(':ok\n\n');
    (clients[me] = clients[me] || new Set()).add(res);
    const announce = on => Object.keys(clients).forEach(x => push(x, { type: 'presence', u: me, online: on, t: Date.now() }));
    if (clients[me].size === 1) announce(true);
    const beat = setInterval(() => res.write(':hb\n\n'), 25000);
    return req.on('close', () => {
      clearInterval(beat); clients[me].delete(res);
      if (!clients[me].size) { db.users[me].lastSeen = Date.now(); save(); announce(false); }
    });
  }

  if (p === '/api/presence') {
    const u = url.searchParams.get('u');
    if (!db.users[u]) return json(res, 404, {});
    return json(res, 200, { online: !!(clients[u] && clients[u].size), lastSeen: db.users[u].lastSeen || 0 });
  }

  if (p === '/api/users') {
    const q = (url.searchParams.get('q') || '').toLowerCase().trim();
    return json(res, 200, Object.keys(db.users)
      .filter(u => u !== me && q && (u.includes(q) || db.users[u].name.toLowerCase().includes(q)))
      .slice(0, 20).map(u => ({ u, name: db.users[u].name })));
  }

  const isG = id => String(id).startsWith('g:');
  const inG = (id, u) => db.groups[id] && db.groups[id].members.includes(u);
  const seen = db.users[me].seen = db.users[me].seen || {};
  const visible = m => m.from === me || m.to === me || (isG(m.to) && inG(m.to, me));
  const keyOf = m => isG(m.to) ? m.to : (m.from === me ? m.to : m.from);
  const nameOf = k => isG(k) ? db.groups[k].name : (db.users[k] ? db.users[k].name : k);

  if (p === '/api/chats') {
    const map = {};
    Object.keys(db.groups).filter(g => inG(g, me)).forEach(g => { map[g] = { u: g, name: nameOf(g), unread: 0 }; });
    for (const m of db.msgs) {
      if (!visible(m)) continue;
      const k = keyOf(m);
      const c = map[k] = map[k] || { u: k, name: nameOf(k), unread: 0 };
      c.last = m;
      if (m.from !== me && (isG(k) ? m.t > (seen[k] || 0) : !m.read)) c.unread++;
    }
    const list = Object.values(map).sort((a, b) => (b.last ? b.last.t : 0) - (a.last ? a.last.t : 0));
    list.forEach(c => { if (c.last && c.last.img) c.last = { ...c.last, img: '1' }; });
    return json(res, 200, list);
  }

  if (p === '/api/messages') {
    const peer = url.searchParams.get('with');
    if (isG(peer) && !inG(peer, me)) return json(res, 403, { error: 'forbidden' });
    const list = db.msgs.filter(m => isG(peer) ? m.to === peer : (m.from === me && m.to === peer) || (m.from === peer && m.to === me));
    if (isG(peer)) { seen[peer] = Date.now(); save(); }
    else {
      let changed = false;
      list.forEach(m => { if (m.to === me && !m.read) { m.read = true; changed = true; } });
      if (changed) { save(); push(peer, { type: 'read', by: me }); }
    }
    return json(res, 200, list.slice(-100));
  }

  if (req.method === 'POST' && p === '/api/send') {
    const b = await readBody(req), text = String(b.text || '').trim().slice(0, 2000);
    const img = typeof b.img === 'string' && /^data:image\/jpeg;base64,/.test(b.img) && b.img.length < 900000 ? b.img : '';
    const ok = isG(b.to) ? inG(b.to, me) : (db.users[b.to] && b.to !== me);
    if ((!text && !img) || !ok) return json(res, 400, { error: 'پیام نامعتبر است.' });
    const msg = { id: crypto.randomUUID(), from: me, fn: db.users[me].name, to: b.to, text, img, t: Date.now(), read: false };
    db.msgs.push(msg); save();
    const targets = isG(b.to) ? db.groups[b.to].members : [b.to, me];
    targets.forEach(u => push(u, { type: 'msg', msg: { from: msg.from, to: msg.to } }));
    return json(res, 200, { ok: true });
  }

  if (req.method === 'POST' && p === '/api/group') {
    const b = await readBody(req), name = String(b.name || '').trim().slice(0, 40);
    const extra = (Array.isArray(b.members) ? b.members : []).map(x => String(x).toLowerCase()).filter(x => db.users[x]);
    const members = [...new Set([me, ...extra])];
    if (!name || members.length < 2) return json(res, 400, { error: 'نام گروه و حداقل یک عضو معتبر لازم است.' });
    const id = 'g:' + crypto.randomBytes(6).toString('hex');
    db.groups[id] = { name, members }; save();
    members.forEach(u => push(u, { type: 'group' }));
    return json(res, 200, { u: id, name });
  }

  json(res, 404, { error: 'not found' });
}).listen(PORT, '0.0.0.0', () => {
  console.log('Godgram is running ✔');
  console.log('  This computer:  http://localhost:' + PORT);
  Object.values(os.networkInterfaces()).flat().filter(i => i.family === 'IPv4' && !i.internal)
    .forEach(i => console.log('  Same Wi-Fi:     http://' + i.address + ':' + PORT));
});
