'use strict';
/* =====================================================================
   FGO 連線伺服器（單一檔案，只依賴 ws）
   功能：帳號（註冊／登入）、雲端存檔、對戰配對（快速配對／房間代碼）、
        對戰訊息轉送（兩端以同一個亂數種子各自模擬，伺服器負責轉送出招）、
        勝負紀錄與積分（Elo）、排行榜。
   啟動：npm install && npm start      （環境變數見 README.md）
   ===================================================================== */
const http = require('http'), fs = require('fs'), path = require('path'), crypto = require('crypto');
const { WebSocketServer } = require('ws');

/* ---------- 設定（可用環境變數覆蓋）---------- */
const PORT = +process.env.PORT || 3000;
const DATA_DIR = path.resolve(process.env.DATA_DIR || path.join(__dirname, 'data'));
const GAME_FILE = path.resolve(process.env.GAME_FILE || path.join(__dirname, 'public', 'gacha.html'));
const PVP_MUL = +process.env.PVP_MUL || 10;          // 雙方生命倍率（與單機練習的 PV_HP 對應；由伺服器統一下發，確保兩端一致）
const DRAFT_SEC = +process.env.DRAFT_SEC || 15;      // 選角每一輪秒數
const TURN_SEC = +process.env.TURN_SEC || 30;        // 每次出招的思考秒數
const TOKEN_DAYS = 30, MAX_SAVE_BYTES = 3 * 1024 * 1024, ELO_K = 32, ELO_START = 1000;
const CORS = process.env.CORS_ORIGIN || '*';
const HONOR_CAP = process.env.HONOR_CAP != null ? +process.env.HONOR_CAP : 500;   // 連線對戰每人每日榮譽上限（由伺服器統計，改裝客戶端也無法繞過）
const HONOR_PER_KILL = 8, HONOR_MATCH_MAX = 24;                                 // 與單機練習相同：每擊倒對方 1 體 +8，每場最多 24
const TZ_OFFSET = process.env.TZ_OFFSET_HOURS != null ? +process.env.TZ_OFFSET_HOURS : 8;   // 「每日」的換日時區（預設 UTC+8，台灣）
const CURRENCY_CAP = 999999;                          // 所有貨幣（魔法石／方塊／鑽石／榮譽／情書／皮膚券…）上限；伺服器收存檔時一律夾住，改裝客戶端也無法超過
const GM_USER = (process.env.GM_USER || 'GM').trim();   // GM 測試帳號（啟動時自動建立）；GM_PASS 沒設定時第一次啟動會產生隨機密碼並印在 log
const dayKey = () => new Date(Date.now() + TZ_OFFSET * 36e5).toISOString().slice(0, 10);

fs.mkdirSync(path.join(DATA_DIR, 'saves'), { recursive: true });

/* ---------- 簽章金鑰 ---------- */
const SECRET = (() => {
  if (process.env.SECRET) return process.env.SECRET;
  const f = path.join(DATA_DIR, 'secret.key');
  try { return fs.readFileSync(f, 'utf8').trim(); } catch (e) {}
  const s = crypto.randomBytes(32).toString('hex'); fs.writeFileSync(f, s, { mode: 0o600 }); return s;
})();

/* ---------- 簡易 JSON 儲存（原子寫入＋延遲合併）---------- */
const usersFile = path.join(DATA_DIR, 'users.json');
let users = {};
try { users = JSON.parse(fs.readFileSync(usersFile, 'utf8')); } catch (e) {}
const pending = new Map();
function atomicWrite(file, text) {
  const tmp = file + '.' + process.pid + '.tmp';
  fs.writeFileSync(tmp, text); fs.renameSync(tmp, file);
}
function scheduleWrite(file, getText) {
  if (pending.has(file)) return;
  pending.set(file, setTimeout(() => { pending.delete(file); try { atomicWrite(file, getText()); } catch (e) { console.error('write fail', file, e.message); } }, 400));
}
const saveUsers = () => scheduleWrite(usersFile, () => JSON.stringify(users));
const saveFile = u => path.join(DATA_DIR, 'saves', Buffer.from(u).toString('hex') + '.json');
const saveCache = new Map();
function loadSave(u) {
  if (saveCache.has(u)) return saveCache.get(u);
  let s = null; try { s = JSON.parse(fs.readFileSync(saveFile(u), 'utf8')); } catch (e) {}
  saveCache.set(u, s); return s;
}
function flushAll() { for (const [f, t] of pending) { clearTimeout(t); } pending.clear(); try { atomicWrite(usersFile, JSON.stringify(users)); for (const [u, s] of saveCache) if (s) atomicWrite(saveFile(u), JSON.stringify(s)); } catch (e) {} }
process.on('SIGINT', () => { flushAll(); process.exit(0); });
process.on('SIGTERM', () => { flushAll(); process.exit(0); });

/* ---------- 帳號 ---------- */
const NAME_RE = /^[A-Za-z0-9_\u4e00-\u9fff]{2,16}$/;
const norm = n => String(n || '').trim().toLowerCase();
const hashPw = (pw, salt) => crypto.scryptSync(pw, salt, 32).toString('hex');
function b64u(b) { return Buffer.from(b).toString('base64url'); }
function mkToken(u) {
  const body = b64u(JSON.stringify({ u, exp: Date.now() + TOKEN_DAYS * 864e5 }));
  return body + '.' + crypto.createHmac('sha256', SECRET).update(body).digest('base64url');
}
function readToken(t) {
  if (typeof t !== 'string') return null; const [body, sig] = t.split('.'); if (!body || !sig) return null;
  const ok = crypto.createHmac('sha256', SECRET).update(body).digest('base64url');
  if (sig.length !== ok.length || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(ok))) return null;
  try { const p = JSON.parse(Buffer.from(body, 'base64url').toString()); if (p.exp < Date.now() || !users[p.u]) return null; return p.u; } catch (e) { return null; }
}
const pub = u => ({ user: users[u].name, role: users[u].role || 'player', rating: users[u].rating, w: users[u].w, l: users[u].l, d: users[u].d });

/* ---------- GM 測試帳號 ----------
   role='gm' 的帳號登入後，遊戲端會發放全角色與 999999 貨幣（見 tpl.html 的 applyGM）。
   GM_PASS 有設定：每次啟動都以它為準（改環境變數即可改密碼）；沒設定：只在帳號不存在時產生隨機密碼並印出一次。 */
(function seedGM() {
  const k = norm(GM_USER); if (!NAME_RE.test(GM_USER)) { console.error('GM_USER 格式不合法，略過建立 GM 帳號'); return; }
  const pw = process.env.GM_PASS || '';
  if (users[k] && users[k].role !== 'gm') { console.error('已有同名的一般帳號「' + GM_USER + '」，請改 GM_USER；略過建立 GM 帳號'); return; }
  if (!users[k]) {
    const pass = pw || crypto.randomBytes(9).toString('base64url'), salt = crypto.randomBytes(16).toString('hex');
    users[k] = { name: GM_USER, salt, hash: hashPw(pass, salt), created: Date.now(), role: 'gm', rating: ELO_START, w: 0, l: 0, d: 0, owned: null };
    if (!pw) console.log('\n====== GM 帳號已建立 ======\n帳號：' + GM_USER + '\n密碼：' + pass + '\n（只會顯示這一次；之後要改密碼請設定環境變數 GM_PASS）\n===========================\n');
    saveUsers();
  } else if (pw && !crypto.timingSafeEqual(Buffer.from(hashPw(pw, users[k].salt)), Buffer.from(users[k].hash))) {
    const salt = crypto.randomBytes(16).toString('hex'); users[k].salt = salt; users[k].hash = hashPw(pw, salt); saveUsers();
  }
})();

/* ---------- 登入嘗試限流 ---------- */
const tries = new Map();
function limited(ip) {
  const now = Date.now(), a = (tries.get(ip) || []).filter(t => now - t < 60000);
  tries.set(ip, a); if (a.length >= 12) return true; a.push(now); return false;
}
setInterval(() => { const now = Date.now(); for (const [k, a] of tries) { const b = a.filter(t => now - t < 60000); if (b.length) tries.set(k, b); else tries.delete(k); } }, 60000);

/* ---------- HTTP ---------- */
function send(res, code, obj, type) {
  const body = type ? obj : JSON.stringify(obj);
  res.writeHead(code, { 'Content-Type': type || 'application/json; charset=utf-8', 'Access-Control-Allow-Origin': CORS, 'Access-Control-Allow-Headers': 'Content-Type, Authorization', 'Access-Control-Allow-Methods': 'GET,POST,PUT,OPTIONS', 'Cache-Control': 'no-store' });
  res.end(body);
}
function readBody(req, max) {
  return new Promise((ok, no) => {
    let n = 0; const c = [];
    req.on('data', d => { n += d.length; if (n > max) { no(new Error('too large')); req.destroy(); } else c.push(d); });
    req.on('end', () => { try { ok(JSON.parse(Buffer.concat(c).toString() || '{}')); } catch (e) { no(new Error('bad json')); } });
    req.on('error', no);
  });
}
const ipOf = req => (req.headers['x-forwarded-for'] || req.socket.remoteAddress || '').split(',')[0].trim();
const authOf = req => readToken((req.headers.authorization || '').replace(/^Bearer /, ''));

const server = http.createServer(async (req, res) => {
  try {
    const url = new URL(req.url, 'http://x'), p = url.pathname;
    if (req.method === 'OPTIONS') return send(res, 204, '', 'text/plain');
    if (req.method === 'GET' && (p === '/' || p === '/gacha.html')) {
      return fs.readFile(GAME_FILE, (e, d) => e ? send(res, 404, 'gacha.html not found: 請把遊戲檔放到 server/public/gacha.html', 'text/plain; charset=utf-8') : send(res, 200, d, 'text/html; charset=utf-8'));
    }
    if (p === '/api/health') return send(res, 200, { ok: true, online: wsCount(), time: Date.now() });
    if (p === '/api/config') return send(res, 200, { draftSec: DRAFT_SEC, turnSec: TURN_SEC, mul: PVP_MUL });
    if (req.method === 'POST' && (p === '/api/register' || p === '/api/login')) {
      if (limited(ipOf(req))) return send(res, 429, { error: '嘗試次數過多，請稍後再試' });
      const b = await readBody(req, 4096), name = String(b.user || '').trim(), pw = String(b.pass || ''), k = norm(name);
      if (p === '/api/register') {
        if (!NAME_RE.test(name)) return send(res, 400, { error: '帳號需為 2～16 個字（中英文、數字、底線）' });
        if (pw.length < 6 || pw.length > 64) return send(res, 400, { error: '密碼長度需為 6～64 字' });
        if (users[k]) return send(res, 409, { error: '這個帳號已被使用' });
        const salt = crypto.randomBytes(16).toString('hex');
        users[k] = { name, salt, hash: hashPw(pw, salt), created: Date.now(), role: 'player', rating: ELO_START, w: 0, l: 0, d: 0, owned: null };
        saveUsers();
      } else {
        const u = users[k];
        if (!u || !crypto.timingSafeEqual(Buffer.from(hashPw(pw, u.salt)), Buffer.from(u.hash))) return send(res, 401, { error: '帳號或密碼錯誤' });
      }
      return send(res, 200, { token: mkToken(k), ...pub(k) });
    }
    if (p.startsWith('/api/')) {
      if (p === '/api/leaderboard') {
        const a = Object.values(users).filter(u => u.role !== 'gm' && u.w + u.l + u.d > 0).sort((x, y) => y.rating - x.rating).slice(0, 20).map(u => ({ user: u.name, rating: u.rating, w: u.w, l: u.l, d: u.d }));
        return send(res, 200, a);
      }
      const u = authOf(req); if (!u) return send(res, 401, { error: '請重新登入' });
      if (p === '/api/me' && req.method === 'GET') return send(res, 200, pub(u));
      if (p === '/api/save' && req.method === 'GET') { const s = loadSave(u); return send(res, 200, s ? { rev: s.rev, updated: s.updated, save: s.blob } : { rev: 0, updated: 0, save: null }); }
      if (p === '/api/save' && req.method === 'PUT') {
        const b = await readBody(req, MAX_SAVE_BYTES + 1024);
        if (typeof b.save !== 'string' || b.save.length > MAX_SAVE_BYTES) return send(res, 413, { error: '存檔過大' });
        let parsed; try { parsed = JSON.parse(b.save); } catch (e) { return send(res, 400, { error: '存檔格式錯誤' }); }
        if (parsed && typeof parsed === 'object' && parsed.wallet && typeof parsed.wallet === 'object') {   // 貨幣上限鎖死：非數字→0，負數→0，超過上限→上限
          for (const k of Object.keys(parsed.wallet)) { const v = Math.floor(+parsed.wallet[k]); parsed.wallet[k] = Number.isFinite(v) ? Math.min(CURRENCY_CAP, Math.max(0, v)) : 0; }
          b.save = JSON.stringify(parsed);
        }
        const cur = loadSave(u), rev = cur ? cur.rev : 0;
        if (!b.force && (+b.baseRev || 0) !== rev) return send(res, 409, { error: '雲端存檔較新', rev, updated: cur.updated, save: cur.blob });
        const ns = { rev: rev + 1, updated: Date.now(), blob: b.save };
        saveCache.set(u, ns); scheduleWrite(saveFile(u), () => JSON.stringify(saveCache.get(u)));
        users[u].owned = parsed && typeof parsed.owned === 'object' ? parsed.owned : null; saveUsers();   // 選角驗證用：記下擁有的角色與等級
        return send(res, 200, { rev: ns.rev, updated: ns.updated });
      }
    }
    send(res, 404, { error: 'not found' });
  } catch (e) { send(res, 400, { error: e.message || 'bad request' }); }
});

/* =====================================================================
   WebSocket：配對、房間、對戰轉送
   ===================================================================== */
const wss = new WebSocketServer({ noServer: true, maxPayload: 64 * 1024 });
const conns = new Map();            // user -> ws
const wsCount = () => conns.size;
server.on('upgrade', (req, sock, head) => {
  const url = new URL(req.url, 'http://x');
  if (url.pathname !== '/ws') return sock.destroy();
  const u = readToken(url.searchParams.get('token'));
  if (!u) { sock.write('HTTP/1.1 401 Unauthorized\r\n\r\n'); return sock.destroy(); }
  wss.handleUpgrade(req, sock, head, ws => { ws.user = u; wss.emit('connection', ws, req); });
});

const tx = (ws, o) => { if (ws && ws.readyState === 1) ws.send(JSON.stringify(o)); };
const txu = (u, o) => tx(conns.get(u), o);
const queue = [];                   // { user, build, since }
const rooms = new Map();            // code -> { host, build, at }
const matches = new Map();          // id -> match
const inMatch = new Map();          // user -> match

const code4 = () => { const A = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; let s; do { s = Array.from({ length: 4 }, () => A[crypto.randomInt(A.length)]).join(''); } while (rooms.has(s)); return s; };
const dropFromLobby = u => { const i = queue.findIndex(q => q.user === u); if (i >= 0) queue.splice(i, 1); for (const [c, r] of rooms) if (r.host === u) rooms.delete(c); };

wss.on('connection', ws => {
  const u = ws.user, old = conns.get(u);
  if (old && old !== ws) { tx(old, { t: 'kicked', msg: '此帳號在其他地方登入' }); old.close(); }
  conns.set(u, ws); ws.alive = true;
  const m0 = inMatch.get(u);
  tx(ws, { t: 'hello', ...pub(u), inMatch: !!m0 });
  ws.on('pong', () => ws.alive = true);
  ws.on('message', data => { let m; try { m = JSON.parse(data); } catch (e) { return; } try { onMsg(ws, u, m); } catch (e) { console.error('msg err', e); } });
  ws.on('close', () => {
    if (conns.get(u) !== ws) return;
    conns.delete(u); dropFromLobby(u);
    const mt = inMatch.get(u); if (mt && !mt.done) finish(mt, 1 - mt.seats.indexOf(u), 'disconnect');
  });
});
setInterval(() => { for (const ws of wss.clients) { if (!ws.alive) { ws.terminate(); continue; } ws.alive = false; ws.ping(); } }, 25000);

const okBuild = b => typeof b === 'string' && b.length > 0 && b.length <= 64;

function onMsg(ws, u, m) {
  switch (m.t) {
    case 'ping': return tx(ws, { t: 'pong' });
    case 'queue': {
      if (inMatch.has(u)) return tx(ws, { t: 'err', msg: '你正在對戰中' });
      if (!okBuild(m.build)) return;
      dropFromLobby(u); queue.push({ user: u, build: m.build, since: Date.now() }); tx(ws, { t: 'queued' }); return pair();
    }
    case 'unqueue': dropFromLobby(u); return tx(ws, { t: 'idle' });
    case 'create': {
      if (inMatch.has(u) || !okBuild(m.build)) return; dropFromLobby(u);
      const c = code4(); rooms.set(c, { host: u, build: m.build, at: Date.now() }); return tx(ws, { t: 'room', code: c });
    }
    case 'join': {
      if (inMatch.has(u) || !okBuild(m.build)) return;
      const c = String(m.code || '').toUpperCase().trim(), r = rooms.get(c);
      if (!r || !conns.has(r.host)) return tx(ws, { t: 'err', msg: '找不到這個房間（代碼錯誤或房主已離開）' });
      if (r.host === u) return tx(ws, { t: 'err', msg: '不能加入自己建立的房間' });
      if (r.build !== m.build) return tx(ws, { t: 'err', msg: '遊戲版本與房主不同，請更新到相同版本（重新整理頁面）' });
      rooms.delete(c); dropFromLobby(u); return startMatch(r.host, u, r.build);
    }
    case 'leave': return dropFromLobby(u), tx(ws, { t: 'idle' });
  }
  const mt = inMatch.get(u); if (!mt || mt.done) return;
  const seat = mt.seats.indexOf(u);
  switch (m.t) {
    case 'lock': return onLock(mt, seat, m);
    case 'act': {   // 出招：原樣轉送給對手（兩端各自模擬）
      if (mt.stage < 3) return;
      mt.last = Date.now(); mt.seq++;
      return txu(mt.seats[1 - seat], { t: 'act', seq: mt.seq, act: String(m.act || '').slice(0, 8), ti: Number.isInteger(m.ti) ? m.ti : null, tgt: Number.isInteger(m.tgt) ? m.tgt : 0, h: m.h });
    }
    case 'forfeit': return finish(mt, 1 - seat, 'forfeit');
    case 'cheat': return finish(mt, seat, 'illegal');            // 對手送出不合法的操作（客戶端檢查後回報）
    case 'desync': return finish(mt, null, 'dispute');           // 兩端模擬結果不一致：本局不計分
    case 'result': return onResult(mt, seat, m.w, m.k);
  }
}

/* ---------- 配對 ---------- */
function pair() {
  for (let i = 0; i < queue.length; i++) {
    let best = -1, bd = 1e9;
    for (let j = i + 1; j < queue.length; j++) {
      if (queue[j].build !== queue[i].build) continue;
      const d = Math.abs(users[queue[i].user].rating - users[queue[j].user].rating), wait = (Date.now() - Math.min(queue[i].since, queue[j].since)) / 1000;
      if (d <= 150 + wait * 20 && d < bd) { bd = d; best = j; }
    }
    if (best >= 0) { const a = queue[i], b = queue[best]; queue.splice(best, 1); queue.splice(i, 1); startMatch(a.user, b.user, a.build); return pair(); }
  }
}
setInterval(pair, 3000);
setInterval(() => { const now = Date.now(); for (const [c, r] of rooms) if (now - r.at > 600000) { rooms.delete(c); txu(r.host, { t: 'idle', msg: '房間已逾時關閉' }); } }, 30000);

/* ---------- 對戰 ---------- */
function startMatch(a, b, build) {
  const seats = Math.random() < .5 ? [a, b] : [b, a];
  const mt = { id: crypto.randomBytes(6).toString('hex'), seats, build, seed: crypto.randomInt(1, 2 ** 31 - 1), stage: 0, locks: [null, null], picks: [[], []], los: [[], []], seq: 0, results: [null, null], ks: [null, null], done: false, at: Date.now(), last: Date.now(), timer: null };
  matches.set(mt.id, mt); seats.forEach(u => inMatch.set(u, mt));
  seats.forEach((u, s) => txu(u, { t: 'match', id: mt.id, seat: s, seed: mt.seed, mul: PVP_MUL, draftSec: DRAFT_SEC, turnSec: TURN_SEC, opp: { user: users[seats[1 - s]].name, rating: users[seats[1 - s]].rating } }));
  armDraft(mt);
}
function armDraft(mt) {
  clearTimeout(mt.timer);
  mt.timer = setTimeout(() => {   // 逾時未鎖定（客戶端正常會自動鎖定，只有斷線／異常才會走到這裡）
    if (mt.done || mt.stage >= 3) return;
    const l0 = !!mt.locks[0], l1 = !!mt.locks[1];
    if (!l0 && !l1) return finish(mt, -1, 'timeout'); finish(mt, l0 ? 0 : 1, 'timeout');
  }, (DRAFT_SEC + 6) * 1000);
}
function validLo(lo) {
  if (!lo || typeof lo !== 'object') return null; const n = (v, a, b) => { v = +v; return Number.isFinite(v) ? Math.min(b, Math.max(a, v)) : a; };
  const sf = lo.sf || {};
  return { lv: Math.round(n(lo.lv, 1, 5)), sp: n(lo.sp, 0, 400), sf: { spd: n(sf.spd, 0, 200), atk: n(sf.atk, 0, 2), hp: n(sf.hp, 0, 2), np: n(sf.np, 0, 100),
    sh: n(sf.sh, 0, 10000), iv: Math.round(n(sf.iv, 0, 3)), acr: n(sf.acr, 0, 0.5), dd: n(sf.dd, 0, 0.5) } };   // 刻印主動效果：護盾／無敵次數／全卡爆擊率／防禦下降（上限防竄改）
}
function onLock(mt, seat, m) {
  if (m.st !== mt.stage || mt.locks[seat]) return;
  const id = m.id, lo = validLo(m.lo), u = mt.seats[seat], ow = users[u].owned;
  if (!Number.isInteger(id) || id < 0 || id > 9999 || !lo) return;
  if (mt.picks[seat].includes(id)) return tx(conns.get(u), { t: 'err', msg: '角色重複' });
  if (ow) { const have = +ow[id] || 0; if (have <= 0) return finish(mt, 1 - seat, 'illegal'); lo.lv = Math.min(lo.lv, Math.min(5, have)); }   // 有雲端存檔：核對擁有與等級
  mt.locks[seat] = { id, lo }; txu(mt.seats[1 - seat], { t: 'oppLocked', st: mt.stage });
  if (mt.locks[0] && mt.locks[1]) {
    const st = mt.stage, p = mt.locks.map(x => ({ id: x.id, lo: x.lo }));
    mt.locks.forEach((x, s) => { mt.picks[s].push(x.id); mt.los[s].push(x.lo) });
    mt.stage++; mt.locks = [null, null]; mt.last = Date.now();
    mt.seats.forEach(uu => txu(uu, { t: 'reveal', st, p }));
    if (mt.stage < 3) armDraft(mt); else { clearTimeout(mt.timer); mt.timer = null; }
  }
}

/* ---------- 結算 ---------- */
function onResult(mt, seat, w, k) {
  if (mt.stage < 3 || ![0, 1, -1].includes(w)) return;
  mt.results[seat] = w; mt.ks[seat] = Math.min(3, Math.max(0, k | 0));   // k＝勝方擊倒對方的角色數（兩端模擬一致，取勝方自己的回報）
  if (mt.results[0] != null && mt.results[1] != null) { if (mt.results[0] === mt.results[1]) finish(mt, w, 'normal', true); else finish(mt, null, 'dispute'); return; }
  if (!mt.waitRes) mt.waitRes = setTimeout(() => { if (!mt.done) { const r = mt.results[0] != null ? mt.results[0] : mt.results[1]; if (r != null) finish(mt, r, 'normal', true); else finish(mt, null, 'dispute'); } }, 8000);   // 另一方沒回報：8 秒後採用單方回報
}
function finish(mt, w, reason, fromClients) {
  if (mt.done) return; mt.done = true; clearTimeout(mt.timer); clearTimeout(mt.waitRes);
  let delta = [0, 0];
  const played = mt.stage >= 3;   // 進入戰鬥才計入勝負與積分
  if (w != null && played && reason !== 'dispute') {
    const [a, b] = mt.seats.map(u => users[u]), ea = 1 / (1 + 10 ** ((b.rating - a.rating) / 400)), sa = w === -1 ? .5 : w === 0 ? 1 : 0;
    delta = [Math.round(ELO_K * (sa - ea)), Math.round(ELO_K * ((1 - sa) - (1 - ea)))];
    a.rating += delta[0]; b.rating += delta[1];
    if (w === -1) { a.d++; b.d++; } else { users[mt.seats[w]].w++; users[mt.seats[1 - w]].l++; }
    saveUsers();
  }
  // 榮譽獎勵：只有「雙方回報一致的正常結束」且勝方有擊倒對手才發；認輸／斷線不發（避免互刷）。每日上限由這裡統計
  const honor = [0, 0], today = dayKey();
  if (fromClients && (w === 0 || w === 1) && played) {
    const u = mt.seats[w], me = users[u], k = mt.ks[w] != null ? mt.ks[w] : (mt.ks[1 - w] != null ? mt.ks[1 - w] : 0);
    if (!me.hd || me.hd.d !== today) me.hd = { d: today, n: 0 };
    honor[w] = Math.max(0, Math.min(Math.min(HONOR_MATCH_MAX, k * HONOR_PER_KILL), HONOR_CAP - me.hd.n));
    me.hd.n += honor[w]; if (honor[w]) saveUsers();
  }
  const hToday = u => { const h = users[u].hd; return h && h.d === today ? h.n : 0 };
  mt.seats.forEach((u, s) => { if (inMatch.get(u) === mt) inMatch.delete(u); txu(u, { t: 'end', reason, w: w == null ? -2 : w, delta: delta[s], rating: users[u].rating, honor: honor[s], honorToday: hToday(u), honorCap: HONOR_CAP, fromClients: !!fromClients }); });
  setTimeout(() => matches.delete(mt.id), 5000);
}
setInterval(() => {   // 清理閒置過久的對局（雙方都沒有動靜）
  const now = Date.now(); for (const mt of matches.values()) if (!mt.done && now - mt.last > 10 * 60000) finish(mt, null, 'idle');
}, 30000);

server.listen(PORT, () => console.log(`FGO server listening on :${PORT}  (data: ${DATA_DIR})`));
