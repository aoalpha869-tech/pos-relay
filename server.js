/**
 * POS Relay + License API Server  (نسخة آمنة + لا تنام)
 * =====================================================
 *  - Relay Server  : ربط الهاتف (scanner) بالـ POS عبر WebSocket
 *  - License API   : إدارة مفاتيح التفعيل السحابية
 *  - Dashboard     : محمية بتوكن سري (dash token) لكل محل
 *  - Keep-Alive    : self-ping يمنع نوم السيرفر على Render المجاني
 *
 * متغيرات البيئة على Render:
 *   DATABASE_URL          — رابط PostgreSQL (يُضاف تلقائياً عند ربط القاعدة)
 *   ADMIN_SECRET          — كلمة مرور السوبر أدمن (إجبارية — لا قيمة افتراضية)
 *   ALLOWED_ORIGINS       — (اختياري) نطاقات مسموح بها مفصولة بفواصل، مثال:
 *                           https://tauri.localhost,tauri://localhost
 *                           إن لم تُضبط يُسمح للجميع (الحماية تتم بالتوكن/كلمة السر).
 *   RENDER_EXTERNAL_URL   — يضبطه Render تلقائياً، يُستخدم للـ keep-alive
 */

const express   = require('express');
const { WebSocketServer } = require('ws');
const http      = require('http');
const path      = require('path');
const fs        = require('fs');
const { Pool }  = require('pg');
const crypto    = require('crypto');

// ─────────────────────────────────────────────
//  تحقق إجباري من ADMIN_SECRET عند الإقلاع
// ─────────────────────────────────────────────
const ADMIN_SECRET = process.env.ADMIN_SECRET;
if (!ADMIN_SECRET || ADMIN_SECRET.length < 8) {
  console.error('[FATAL] متغير البيئة ADMIN_SECRET غير مضبوط أو قصير جداً (8 أحرف على الأقل).');
  console.error('        اضبطه في إعدادات Render > Environment ثم أعد النشر.');
  process.exit(1);
}

const app    = express();
const server = http.createServer(app);
const wss    = new WebSocketServer({ server });

// ─────────────────────────────────────────────
//  CORS — مفتوح بالكامل، ومُطبَّق قبل أي شيء آخر (حتى قبل express.json())
//  باش هيدرز الـ CORS تتبعث حتى مع أخطاء زي 413 (حمولة كبيرة) وماشي غير عند النجاح
//  (التحقق الحقيقي يتم عبر التوكن فكل طلب، ماشي عبر الـ Origin)
// ─────────────────────────────────────────────
app.use((req, res, next) => {
  const origin = req.headers.origin;
  res.header('Access-Control-Allow-Origin', origin || '*');
  res.header('Vary', 'Origin');
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, x-admin-password');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});

// حد أقصى أكبر لحجم الـ JSON (كاتالوغات كبيرة: آلاف المنتجات/المبيعات فطلب واحد،
// وأحياناً تتجاوز 100 ميغا بسبب صور المنتجات المُخزَّنة base64 — انظر stripHeavyImages تحت)
app.use(express.json({ limit: '250mb' }));

// ─────────────────────────────────────────────
//  تنظيف الصور الثقيلة (base64) من بيانات POS الضخمة
//  قبل تخزينها فـ Postgres أو تمريرها للهاتف/اللوحة —
//  الصور غير ضرورية لا للوحة المتابعة ولا لعمليات البيع عن بُعد،
//  وهي المسؤولة عادة عن أغلب حجم البيانات (عشرات/مئات الميغا لآلاف المنتجات)
// ─────────────────────────────────────────────
function stripHeavyImages(node, depth) {
  depth = depth || 0;
  if (depth > 12 || node == null) return node;
  if (typeof node === 'string') {
    // أي سلسلة base64 لصورة أطول من 500 حرف تُحذف (تُستبدل بـ null)
    if (node.length > 500 && node.slice(0, 11) === 'data:image/') return null;
    return node;
  }
  if (Array.isArray(node)) {
    for (let i = 0; i < node.length; i++) node[i] = stripHeavyImages(node[i], depth + 1);
    return node;
  }
  if (typeof node === 'object') {
    for (const k in node) node[k] = stripHeavyImages(node[k], depth + 1);
    return node;
  }
  return node;
}

// يطبّق التنظيف على بيانات POS الواردة، سواء كانت كائن مباشر (لقطة اللوحة)
// أو نص JSON مُغلَّف داخل {status, body} (رد api_request لتطبيق الهاتف)
function sanitizePosData(data) {
  try {
    if (data && typeof data.body === 'string') {
      const parsed = JSON.parse(data.body);
      data.body = JSON.stringify(stripHeavyImages(parsed));
      return data;
    }
    return stripHeavyImages(data);
  } catch (e) {
    return data; // إن فشل التحليل (بيانات غير JSON)، مرّرها كما هي بدل ما نكسر التدفق
  }
}

// ─────────────────────────────────────────────
//  قاعدة البيانات PostgreSQL
// ─────────────────────────────────────────────
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS licenses (
      key          TEXT PRIMARY KEY,
      type         TEXT NOT NULL,
      duration     INTEGER NOT NULL,
      created_at   DATE NOT NULL DEFAULT CURRENT_DATE,
      activated_at DATE DEFAULT NULL,
      expires_at   DATE DEFAULT NULL,
      instance_id  TEXT DEFAULT NULL,
      note         TEXT DEFAULT '',
      revoked      INTEGER NOT NULL DEFAULT 0
    )
  `);
  await pool.query(`
    ALTER TABLE licenses ADD COLUMN IF NOT EXISTS revoked INTEGER NOT NULL DEFAULT 0
  `).catch(() => {});
  await pool.query(`
    CREATE TABLE IF NOT EXISTS client_snapshots (
      license_key   TEXT PRIMARY KEY REFERENCES licenses(key) ON DELETE CASCADE,
      last_seen     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      is_online     BOOLEAN NOT NULL DEFAULT FALSE,
      room_id       TEXT DEFAULT NULL,
      token         TEXT DEFAULT NULL,
      snapshot      JSONB DEFAULT NULL
    )
  `);
  await pool.query(`
    ALTER TABLE client_snapshots ADD COLUMN IF NOT EXISTS token TEXT DEFAULT NULL
  `).catch(() => {});
  console.log('[DB] جداول قاعدة البيانات جاهزة');
}
initDB().catch(err => console.error('[DB] فشل إنشاء الجداول:', err.message));

// ─────────────────────────────────────────────
//  أدوات مساعدة
// ─────────────────────────────────────────────

/** مقارنة آمنة ضد timing attacks */
function safeEqual(a, b) {
  const ba = Buffer.from(String(a || ''));
  const bb = Buffer.from(String(b || ''));
  if (ba.length !== bb.length) return false;
  return crypto.timingSafeEqual(ba, bb);
}

function checkAdmin(password) {
  return safeEqual(password, ADMIN_SECRET);
}

function generateKey() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const part  = () => Array.from({ length: 4 }, () =>
    chars[crypto.randomInt(0, chars.length)]
  ).join('');
  return `${part()}-${part()}-${part()}-${part()}`;
}

// توقيت الجزائر UTC+1 — نحسب التاريخ محلياً لا بتوقيت UTC حتى تتطابق الأيام مع ساعة المستخدم
const TZ_OFFSET_MS = 60 * 60 * 1000; // +1 ساعة
function today()      { return new Date(Date.now() + TZ_OFFSET_MS).toISOString().slice(0, 10); }
function addDays(d)   { const x = new Date(Date.now() + TZ_OFFSET_MS); x.setUTCDate(x.getUTCDate() + d); return x.toISOString().slice(0, 10); }
// يحوّل أي قيمة تاريخ (Date من PostgreSQL أو نص) إلى صيغة موحّدة YYYY-MM-DD
// مهم جداً: بدونه تُقارَن كائنات Date بنصوص فتفشل المقارنة وتبقى التراخيص المنتهية "صالحة"
function toDateStr(d) {
  if (!d) return null;
  if (typeof d === 'string') return d.slice(0, 10);
  try { return new Date(d).toISOString().slice(0, 10); } catch (_) { return null; }
}

// ─────────────────────────────────────────────
//  Rate limiting بسيط في الذاكرة (ضد brute-force)
// ─────────────────────────────────────────────
const hits = new Map(); // ip -> { count, ts }
function rateLimit(maxPerMin) {
  return (req, res, next) => {
    const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || req.socket.remoteAddress || 'unknown';
    const now = Date.now();
    const rec = hits.get(ip) || { count: 0, ts: now };
    if (now - rec.ts > 60000) { rec.count = 0; rec.ts = now; }
    rec.count++;
    hits.set(ip, rec);
    if (rec.count > maxPerMin) {
      return res.status(429).json({ error: 'طلبات كثيرة جداً — حاول بعد دقيقة' });
    }
    next();
  };
}
// تنظيف دوري للذاكرة
setInterval(() => {
  const now = Date.now();
  for (const [ip, rec] of hits) if (now - rec.ts > 120000) hits.delete(ip);
}, 120000);

function requireAdmin(req, res, next) {
  const pass = req.body?.admin_password || req.headers['x-admin-password'];
  if (!checkAdmin(pass)) {
    return res.status(401).json({ error: 'كلمة مرور غير صحيحة' });
  }
  next();
}

// ═════════════════════════════════════════════
//  LICENSE API
// ═════════════════════════════════════════════
app.post('/api/license/activate', rateLimit(20), async (req, res) => {
  const { key, instance_id } = req.body || {};
  if (!key || !instance_id) return res.status(400).json({ error: 'key و instance_id مطلوبان' });
  try {
    const result = await pool.query('SELECT * FROM licenses WHERE key = $1', [key.toUpperCase().trim()]);
    if (result.rows.length === 0) return res.json({ ok: false, error: 'المفتاح غير صحيح أو غير موجود' });
    const lic = result.rows[0];
    if (lic.instance_id && lic.instance_id !== instance_id)
      return res.json({ ok: false, error: 'هذا المفتاح مُستخدم بالفعل على نسخة أخرى' });
    if (lic.revoked) return res.json({ ok: false, error: 'تم إلغاء هذا الترخيص', revoked: true });

    const isFirstActivation = !lic.activated_at;
    let expires_at = lic.expires_at;
    if (isFirstActivation) {
      expires_at = lic.duration === 0 ? null : addDays(lic.duration);
      await pool.query(
        `UPDATE licenses SET activated_at = $1, expires_at = $2, instance_id = $3 WHERE key = $4`,
        [today(), expires_at, instance_id, lic.key]
      );
      await pool.query(
        `INSERT INTO client_snapshots (license_key, last_seen, is_online, room_id)
         VALUES ($1, NOW(), FALSE, $2) ON CONFLICT (license_key) DO NOTHING`,
        [lic.key, instance_id]
      ).catch(() => {});
    }
    // توحيد صيغة التاريخ قبل المقارنة (إصلاح الخلل: Date مقابل نص كان يفشل دائماً)
    const exp = toDateStr(expires_at);
    if (exp && exp <= today())
      return res.json({ ok: false, error: 'انتهت صلاحية هذا المفتاح', expired: true });

    let days_left = -1;
    if (exp) days_left = Math.max(0, Math.ceil((new Date(exp) - new Date(today())) / 86400000));
    res.json({ ok: true, type: lic.type, expires_at: exp || null, days_left,
      activated_at: isFirstActivation ? today() : toDateStr(lic.activated_at) });
  } catch (err) {
    console.error('[license/activate]', err.message);
    res.status(500).json({ error: 'خطأ في الخاد��' });
  }
});

app.post('/api/license/verify', rateLimit(40), async (req, res) => {
  const { key, instance_id, room_id } = req.body || {};
  if (!key || !instance_id) return res.status(400).json({ ok: false, error: 'key و instance_id مطلوبان' });
  try {
    const result = await pool.query(
      'SELECT * FROM licenses WHERE key = $1 AND instance_id = $2',
      [key.toUpperCase().trim(), instance_id]
    );
    if (result.rows.length === 0) return res.json({ ok: false, error: 'الترخيص غير موجود' });
    const lic = result.rows[0];
    if (lic.revoked) return res.json({ ok: false, error: 'تم إلغاء هذا الترخيص', revoked: true });
    // توحيد صيغة التاريخ قبل المقارنة (إصلاح الخلل: Date مقابل نص كان يفشل دائماً)
    const exp = toDateStr(lic.expires_at);
    if (exp && exp <= today())
      return res.json({ ok: false, error: 'انتهت صلاحية الترخيص', expired: true });

    let days_left = -1;
    if (exp) days_left = Math.max(0, Math.ceil((new Date(exp) - new Date(today())) / 86400000));
    if (room_id && room_id.trim()) {
      pool.query(
        `INSERT INTO client_snapshots (license_key, last_seen, is_online, room_id)
         VALUES ($1, NOW(), FALSE, $2)
         ON CONFLICT (license_key) DO UPDATE SET room_id = $2, last_seen = NOW()`,
        [lic.key, room_id.trim()]
      ).catch(() => {});
    }
    res.json({ ok: true, type: lic.type, expires_at: exp || null, days_left });
  } catch (err) {
    console.error('[license/verify]', err.message);
    res.status(500).json({ ok: false, error: 'خطأ في الخادم' });
  }
});

app.post('/api/license/register-room', rateLimit(40), async (req, res) => {
  const { key, instance_id, room_id } = req.body || {};
  if (!key || !instance_id || !room_id)
    return res.status(400).json({ ok: false, error: 'key و instance_id و room_id مطلوبة' });
  try {
    const result = await pool.query(
      'SELECT key FROM licenses WHERE key = $1 AND instance_id = $2 AND revoked = 0',
      [key.toUpperCase().trim(), instance_id]
    );
    if (result.rows.length === 0) return res.json({ ok: false, error: 'الترخيص غير صالح' });
    const licKey = result.rows[0].key;
    await pool.query(
      `INSERT INTO client_snapshots (license_key, last_seen, is_online, room_id)
       VALUES ($1, NOW(), FALSE, $2)
       ON CONFLICT (license_key) DO UPDATE SET room_id = $2, last_seen = NOW()`,
      [licKey, room_id]
    );
    res.json({ ok: true });
  } catch (err) {
    console.error('[register-room]', err.message);
    res.status(500).json({ ok: false, error: 'خطأ في السيرفر' });
  }
});

// ═════════════════════════════════════════════
//  ADMIN API  (محمية بـ ADMIN_SECRET + rate limit)
// ═════════════════════════════════════════════
app.post('/api/admin/create', rateLimit(30), requireAdmin, async (req, res) => {
  const { type = 'trial', note = '' } = req.body;
  const duration = { trial: 7, trial_day: 1, annual: 365, lifetime: 0 }[type] ?? 7;
  let key, tries = 0;
  do {
    key = generateKey();
    const exists = await pool.query('SELECT 1 FROM licenses WHERE key = $1', [key]);
    if (exists.rows.length === 0) break;
    tries++;
  } while (tries < 10);
  try {
    await pool.query(
      `INSERT INTO licenses (key, type, duration, created_at, note) VALUES ($1, $2, $3, $4, $5)`,
      [key, type, duration, today(), note]
    );
    res.json({ ok: true, key });
  } catch (err) {
    console.error('[admin/create]', err.message);
    res.status(500).json({ error: 'فشل إنشاء المفتاح' });
  }
});

app.get('/api/admin/rooms', rateLimit(30), requireAdmin, async (req, res) => {
  try {
    // السجل الدائم: كل غرفة سجّلت روحها مرة، حتى لو غير متصلة حاليًا
    const result = await pool.query(`
      SELECT cs.room_id, cs.is_online AS db_online, cs.last_seen, cs.token AS db_token,
             l.key AS license_key, l.note
      FROM client_snapshots cs
      LEFT JOIN licenses l ON l.key = cs.license_key
      WHERE cs.room_id IS NOT NULL
      ORDER BY cs.last_seen DESC
    `);

    const list = result.rows.map(row => {
      const live = rooms.get(row.room_id); // الحالة الحية إذا كانت متوفرة فالذاكرة الآن
      const posLive = !!(live && posConnected(live));
      return {
        room_id: row.room_id,
        // نفضّل التوكن الحي، وإلا نرجع لآخر توكن محفوظ فالقاعدة
        token: (live ? live.token : null) || row.db_token || null,
        license_key: row.license_key,
        note: row.note || '',
        // نعتمد الحالة الحية إذا كان السيرفر عارفها الآن، وإلا نرجع لآخر حالة مسجلة فالقاعدة
        pos_connected: live ? posLive : !!row.db_online,
        phones_connected: live ? live.phones.filter(p => p.readyState === 1).length : 0,
        pending_requests: live ? live.pendingReqs.size : 0,
        last_seen: row.last_seen,
      };
    });

    // أضف أي غرفة حية فالذاكرة الآن وماكانتش بعد فالقاعدة (نادر، لكن للاحتياط)
    for (const [id, r] of rooms.entries()) {
      if (!list.find(x => x.room_id === id)) {
        list.push({
          room_id: id,
          token: r.token,
          license_key: null,
          note: '',
          pos_connected: posConnected(r),
          phones_connected: r.phones.filter(p => p.readyState === 1).length,
          pending_requests: r.pendingReqs.size,
          last_seen: null,
        });
      }
    }

    res.json({ ok: true, count: list.length, rooms: list });
  } catch (err) {
    console.error('[admin/rooms]', err.message);
    res.status(500).json({ ok: false, error: 'فشل جلب قائمة الغرف' });
  }
});

app.post('/api/admin/list', rateLimit(30), requireAdmin, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM licenses ORDER BY created_at DESC');
    res.json({ ok: true, licenses: result.rows });
  } catch (err) { res.status(500).json({ error: 'فشل جلب القائمة' }); }
});

app.post('/api/admin/delete', rateLimit(30), requireAdmin, async (req, res) => {
  const { key } = req.body;
  if (!key) return res.status(400).json({ error: 'key مطلوب' });
  try {
    await pool.query('DELETE FROM licenses WHERE key = $1', [key.toUpperCase().trim()]);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: 'فشل الحذف' }); }
});

app.post('/api/admin/revoke', rateLimit(30), requireAdmin, async (req, res) => {
  const { key } = req.body;
  if (!key) return res.status(400).json({ error: 'key مطلوب' });
  try {
    const result = await pool.query(
      'UPDATE licenses SET revoked = 1 WHERE key = $1 RETURNING key', [key.toUpperCase().trim()]
    );
    if (result.rowCount === 0) return res.json({ ok: false, error: 'المفتاح غير موجود' });
    res.json({ ok: true, message: 'تم قطع الترخيص — سيُوقف البرنامج عند الاتصال بالإنترنت' });
  } catch (err) { res.status(500).json({ error: 'فشل قطع الترخيص' }); }
});

app.post('/api/admin/unrevoke', rateLimit(30), requireAdmin, async (req, res) => {
  const { key } = req.body;
  if (!key) return res.status(400).json({ error: 'key مطلوب' });
  try {
    const result = await pool.query(
      'UPDATE licenses SET revoked = 0 WHERE key = $1 RETURNING key', [key.toUpperCase().trim()]
    );
    if (result.rowCount === 0) return res.json({ ok: false, error: 'المفتاح غير موجود' });
    res.json({ ok: true, message: 'تم استعادة الترخيص' });
  } catch (err) { res.status(500).json({ error: 'فشل استعادة الترخيص' }); }
});

app.post('/api/admin/reset-instance', rateLimit(30), requireAdmin, async (req, res) => {
  const { key } = req.body;
  if (!key) return res.status(400).json({ error: 'key مطلوب' });
  try {
    await pool.query(
      `UPDATE licenses SET instance_id = NULL, activated_at = NULL, expires_at = NULL WHERE key = $1`,
      [key.toUpperCase().trim()]
    );
    res.json({ ok: true, message: 'تم إعادة تعيين المفتاح — يمكن تفعيله على جهاز جديد' });
  } catch (err) { res.status(500).json({ error: 'فشل إعادة التعيين' }); }
});

app.post('/api/admin/link-room', rateLimit(30), requireAdmin, async (req, res) => {
  const { key, room_id } = req.body || {};
  if (!key || !room_id) return res.status(400).json({ error: 'key و room_id مطلوبان' });
  try {
    const lic = await pool.query('SELECT key FROM licenses WHERE key = $1', [key.toUpperCase().trim()]);
    if (lic.rows.length === 0) return res.json({ ok: false, error: 'المفتاح غير موجود' });
    await pool.query(
      `INSERT INTO client_snapshots (license_key, last_seen, is_online, room_id)
       VALUES ($1, NOW(), FALSE, $2)
       ON CONFLICT (license_key) DO UPDATE SET room_id = $2, last_seen = NOW()`,
      [lic.rows[0].key, room_id.trim()]
    );
    const room = rooms.get(room_id.trim());
    if (room?.pos?.readyState === 1) {
      await pool.query('UPDATE client_snapshots SET is_online = TRUE WHERE license_key = $1', [lic.rows[0].key]);
    }
    res.json({ ok: true });
  } catch (err) {
    console.error('[link-room]', err.message);
    res.status(500).json({ error: 'فشل الربط' });
  }
});

app.post('/api/admin/client-snapshot', rateLimit(30), requireAdmin, async (req, res) => {
  const { key } = req.body;
  if (!key) return res.status(400).json({ error: 'key مطلوب' });
  try {
    const result = await pool.query('SELECT * FROM client_snapshots WHERE license_key = $1', [key.toUpperCase().trim()]);
    res.json({ ok: true, snapshot: result.rows[0] || null });
  } catch (err) { res.status(500).json({ error: 'فشل جلب البيانات' }); }
});

app.get('/api/admin/client-live/:key', rateLimit(30), async (req, res) => {
  const pass = req.headers['x-admin-password'];
  if (!checkAdmin(pass)) return res.status(401).json({ error: 'غير مصرح' });
  const key = req.params.key.toUpperCase().trim();
  const snap = await pool.query(
    'SELECT room_id, is_online FROM client_snapshots WHERE license_key = $1', [key]
  ).catch(() => ({ rows: [] }));
  const row = snap.rows[0];
  if (!row || !row.room_id || !row.is_online)
    return res.status(503).json({ error: 'الجهاز غير متصل حالياً', offline: true });
  const room = getRoom(row.room_id);
  if (!posConnected(room)) {
    await pool.query('UPDATE client_snapshots SET is_online = FALSE WHERE license_key = $1', [key]).catch(() => {});
    return res.status(503).json({ error: 'الجهاز غير متصل حالياً', offline: true });
  }
  const reqId = crypto.randomBytes(8).toString('hex');
  try {
    const data = await posRequest(room, 'dashboard_full_request', reqId, 45000);
    await pool.query(
      `INSERT INTO client_snapshots (license_key, last_seen, is_online, room_id, snapshot)
       VALUES ($1, NOW(), TRUE, $2, $3)
       ON CONFLICT (license_key) DO UPDATE
         SET last_seen = NOW(), is_online = TRUE, room_id = $2, snapshot = $3`,
      [key, row.room_id, JSON.stringify(data)]
    ).catch(() => {});
    res.json({ ok: true, live: true, data });
  } catch (e) {
    res.status(504).json({ error: 'انتهى وقت الانتظار' });
  }
});

// ═════════════════════════════════════════════
//  Static Pages
// ═════════════════════════════════════════════
function sendFile(res, name) {
  const p = path.join(__dirname, name);
  if (!fs.existsSync(p)) return res.status(404).send(name + ' not found');
  // منع التخزين المؤقت حتى تظهر آخر نسخة دائماً (لا نسخة قديمة مخزّنة)
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.set('Pragma', 'no-cache');
  res.set('Expires', '0');
  res.sendFile(p);
}
app.get('/scanner/:roomId',   (req, res) => sendFile(res, 'scanner.html'));
app.get('/dashboard/:roomId', (req, res) => sendFile(res, 'dashboard.html'));
app.get('/health', (_, res) => res.json({ ok: true, rooms: rooms.size, time: new Date() }));
app.get('/admin',  (_, res) => sendFile(res, 'admin.html'));
app.get('/',       (_, res) => sendFile(res, 'download.html'));

// ═════════════════════════════════════════════
//  Relay WebSocket (scanner ↔ POS) + Dashboard token
// ═════════════════════════════════════════════
const rooms = new Map();
function getRoom(id) {
  if (!rooms.has(id))
    rooms.set(id, {
      pos: null, phones: [], pendingReqs: new Map(), token: null,
      pollQueue: [], pollWaiters: [], lastPollAt: 0, // ── وضع الـ HTTP Long-Polling (POS بدون WebSocket)
    });
  return rooms.get(id);
}

const POLL_ALIVE_MS = 40000; // إذا ما توصلش طلب poll جديد خلال هاذ المدة، نعتبروه منقطع (أطول من مدة الـ long-poll: 25 ثانية + هامش أمان)

/** واش الـ POS متصل الآن، سواء عبر WebSocket أو عبر Long-Polling */
function posConnected(room) {
  if (room.pos && room.pos.readyState === 1) return true;
  return (Date.now() - room.lastPollAt) < POLL_ALIVE_MS;
}

/** يرسل رسالة للـ POS: مباشرة عبر WebSocket إذا كان متصل بيه، وإلا يحطها فطابور الـ polling */
function sendToPos(room, obj) {
  if (room.pos && room.pos.readyState === 1) {
    room.pos.send(JSON.stringify(obj));
    return;
  }
  room.pollQueue.push(obj);
  if (room.pollWaiters.length) {
    const waiter = room.pollWaiters.shift();
    const msgs = room.pollQueue.splice(0, room.pollQueue.length);
    waiter(msgs);
  }
}

async function posRequest(room, type, reqId, timeout = 12000) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => { room.pendingReqs.delete(reqId); reject(new Error('timeout')); }, timeout);
    room.pendingReqs.set(reqId, { resolve, reject, timer });
    sendToPos(room, { type, reqId });
  });
}

/** التحقق من توكن لوحة المتابعة لغرفة معينة */
function checkDashToken(room, token) {
  // إن لم يكن للغرفة توكن (POS قديم لم يُحدّث) نرفض افتراضياً للأمان
  if (!room || !room.token) return false;
  return safeEqual(token, room.token);
}

app.get('/api/dashboard/:roomId', async (req, res) => {
  const room = getRoom(req.params.roomId);
  if (!posConnected(room))
    return res.status(503).json({ error: 'POS غير متصل حالياً' });
  if (!checkDashToken(room, req.query.token))
    return res.status(401).json({ error: 'توكن غير صالح' });
  const reqId = crypto.randomBytes(8).toString('hex');
  try {
    const data = await posRequest(room, 'dashboard_request', reqId);
    res.json(data);
  } catch (e) {
    res.status(504).json({ error: e.message === 'timeout' ? 'انتهى وقت الانتظار' : e.message });
  }
});

app.get('/api/dashboard-full/:roomId', async (req, res) => {
  const roomId = req.params.roomId;
  const room = getRoom(roomId);
  if (!posConnected(room))
    return res.status(503).json({ error: 'POS غير متصل حالياً' });
  if (!checkDashToken(room, req.query.token))
    return res.status(401).json({ error: 'توكن غير صالح' });

  // ── نجرّب أولاً نرجّع آخر نسخة محفوظة فورياً (بلا انتظار) ──────────────
  // ونطلق تحديث فالخلفية (بمهلة طويلة) بلا ما نخلّي المستخدم ينتظرها
  let cached = null;
  try {
    const snap = await pool.query('SELECT snapshot, last_seen FROM client_snapshots WHERE room_id = $1', [roomId]);
    if (snap.rows[0]?.snapshot) cached = snap.rows[0].snapshot;
  } catch (e) {}

  scheduleBackgroundRefresh(room, roomId); // fire-and-forget، لا ننتظرها

  if (cached) {
    res.json(cached);
    return;
  }

  // ما كاين حتى نسخة محفوظة (أول مرة) — هنا فقط ننتظر الحساب الحي
  const reqId = crypto.randomBytes(8).toString('hex');
  try {
    const data = await posRequest(room, 'dashboard_full_request', reqId, 90000);
    await pool.query(
      `UPDATE client_snapshots SET snapshot = $1, last_seen = NOW() WHERE room_id = $2`,
      [JSON.stringify(data), roomId]
    ).catch(() => {});
    res.json(data);
  } catch (e) {
    res.status(504).json({ error: e.message === 'timeout' ? 'انتهى وقت الانتظار — أول تحميل قد يطول، أعد المحاولة بعد قليل' : e.message });
  }
});

// ── يطلب نسخة محدّثة فالخلفية بلا حجب أي طلب HTTP، بمهلة معقولة (Rate-limited) ──
function scheduleBackgroundRefresh(room, roomId) {
  const now = Date.now();
  if (room._bgRefreshInFlight) return;                    // كاين طلب شغّال بالفعل
  if (room._lastBgRefreshAt && now - room._lastBgRefreshAt < 60000) return; // لا تعيد قبل 60 ثانية
  room._bgRefreshInFlight = true;
  room._lastBgRefreshAt = now;
  const reqId = 'bg_' + crypto.randomBytes(6).toString('hex');
  posRequest(room, 'dashboard_full_request', reqId, 120000)
    .then(data => {
      return pool.query(
        `UPDATE client_snapshots SET snapshot = $1, last_seen = NOW() WHERE room_id = $2`,
        [JSON.stringify(data), roomId]
      );
    })
    .catch(e => console.error('[bg-refresh]', roomId, e.message))
    .finally(() => { room._bgRefreshInFlight = false; });
}

// ── جسر تشغيل نقطة البيع عن بُعد (الهاتف السحابي) — يمرّر طلب REST إلى الحاسوب عبر الغرفة
app.post('/api/relay/:roomId', rateLimit(120), async (req, res) => {
  const room = getRoom(req.params.roomId);
  if (!posConnected(room))
    return res.status(503).json({ error: 'POS غير متصل حالياً' });
  const token = req.query.token || req.headers['x-dash-token'];
  if (!checkDashToken(room, token))
    return res.status(401).json({ error: 'توكن غير صالح' });
  const { method, path, body } = req.body || {};
  if (!path) return res.status(400).json({ error: 'path مطلوب' });
  const reqId = crypto.randomBytes(8).toString('hex');
  try {
    const result = await new Promise((resolve, reject) => {
      // مهلة أطول (120 ثانية) لتحمّل نقل بيانات ضخمة (كاتالوغ كبير) عبر اتصال
      // إنترنت عادي بين الحاسوب والـrelay، بدل 15 ثانية غير كافية لأي حجم كبير
      const timer = setTimeout(() => { room.pendingReqs.delete(reqId); reject(new Error('timeout')); }, 120000);
      room.pendingReqs.set(reqId, { resolve, reject, timer });
      sendToPos(room, { type: 'api_request', reqId, method: method || 'GET', path, body: body || '' });
    });
    const status = (result && result.status) || 200;
    res.status(status).type('application/json').send((result && result.body) || '{}');
  } catch (e) {
    res.status(504).json({ error: e.message === 'timeout' ? 'انتهى وقت الانتظار' : e.message });
  }
});

wss.on('connection', (ws, req) => {
  const url    = new URL(req.url, 'http://localhost');
  const role   = url.searchParams.get('role');
  const roomId = url.searchParams.get('room');
  const token  = url.searchParams.get('token');
  if (!role || !roomId) { ws.close(4000, 'missing role or room'); return; }

  ws.isAlive = true;
  ws.on('pong', () => { ws.isAlive = true; });
  const room = getRoom(roomId);

  if (role === 'pos') {
    // POS لازم يقدّم التوكن — هو من يحدّد سر الغرفة
    if (!token || token.length < 16) { ws.close(4001, 'missing token'); return; }
    room.token = token;          // سر لوحة المتابعة لهذه الغرفة
    room.pos = ws;
    console.log(`[POS] connected room=${roomId}`);
    ws.send(JSON.stringify({ type: 'status', msg: 'connected' }));
    pool.query(
      `UPDATE client_snapshots SET is_online = TRUE, last_seen = NOW(), token = $2 WHERE room_id = $1`, [roomId, token]
    ).catch(() => {});

    const autoReqId = 'auto_' + crypto.randomBytes(6).toString('hex');
    setTimeout(() => {
      if (ws.readyState !== 1) return;
      const timer = setTimeout(() => room.pendingReqs.delete(autoReqId), 120000);
      room.pendingReqs.set(autoReqId, {
        timer,
        resolve: async (data) => {
          try {
            await pool.query(
              `UPDATE client_snapshots SET snapshot = $1, last_seen = NOW(), is_online = TRUE WHERE room_id = $2`,
              [JSON.stringify(data), roomId]
            );
          } catch (e) { console.error('[snapshot] فشل حفظ البيانات:', e.message); }
        },
        reject: () => {}
      });
      ws.send(JSON.stringify({ type: 'dashboard_full_request', reqId: autoReqId }));
    }, 3000);

    ws.on('message', raw => {
      const txt = raw.toString().trim();
      try {
        const msg = JSON.parse(txt);
        if (msg.type === 'ping') { ws.send(JSON.stringify({ type: 'pong' })); return; }
        if ((msg.type === 'dashboard_response' || msg.type === 'dashboard_full_response' || msg.type === 'api_response') && msg.reqId) {
          const pending = room.pendingReqs.get(msg.reqId);
          if (pending) {
            clearTimeout(pending.timer);
            room.pendingReqs.delete(msg.reqId);
            pending.resolve(msg.data);
            return;
          }
        }
      } catch (e) {}
      room.phones.forEach(p => { if (p.readyState === 1) p.send(txt); });
    });

    ws.on('close', () => {
      room.pos = null;
      pool.query(
        `UPDATE client_snapshots SET is_online = FALSE, last_seen = NOW() WHERE room_id = $1`, [roomId]
      ).catch(() => {});
      for (const [, pending] of room.pendingReqs) { clearTimeout(pending.timer); pending.reject(new Error('POS انقطع')); }
      room.pendingReqs.clear();
      console.log(`[POS] disconnected room=${roomId}`);
    });

  } else if (role === 'phone') {
    room.phones.push(ws);
    console.log(`[Phone] connected room=${roomId} total=${room.phones.length}`);
    sendToPos(room, { type: 'phone_connected', count: room.phones.length });
    ws.on('message', raw => {
      const txt = raw.toString().trim();
      if (!txt) return;
      try {
        const msg = JSON.parse(txt);
        if (msg.type === 'ping') { ws.send(JSON.stringify({ type: 'pong' })); return; }
      } catch (e) {}
      sendToPos(room, { type: 'barcode', value: txt });
    });
    ws.on('close', () => {
      room.phones = room.phones.filter(p => p !== ws);
      sendToPos(room, { type: 'phone_disconnected', count: room.phones.length });
    });
  }
});

// ═════════════════════════════════════════════
//  POS عبر HTTP Long-Polling — بديل مستقر عن WebSocket
//  (يستعملها تطبيق Vendix الحالي بدل الاتصال المباشر بالـ WS)
// ═════════════════════════════════════════════
app.get('/api/pos-poll/:roomId', rateLimit(600), async (req, res) => {
  const roomId = req.params.roomId;
  const token  = req.query.token;
  if (!token || token.length < 16) return res.status(400).json({ error: 'token مطلوب' });

  const room = getRoom(roomId);
  // أول طلب poll من هاذ الجهاز هو من يحدّد سر الغرفة (كيفما فـ WebSocket).
  // لو الغرفة خاملة (بلا poll ناجح من مدة POLL_ALIVE_MS) نعتبر الجهاز القديم
  // منقطعاً ونتبنّى التوكن الجديد تلقائياً — هذا يحل مشكلة توكن قديم عالق
  // في الذاكرة (مثلاً من جلسة "npx tauri dev" سابقة) يمنع النسخة المبنية
  // (exe) من الاتصال بنفس الغرفة لاحقاً.
  const roomIdle = (Date.now() - room.lastPollAt) >= POLL_ALIVE_MS;
  if (!room.token || roomIdle) {
    room.token = token;
  } else if (!safeEqual(token, room.token)) {
    return res.status(401).json({ error: 'توكن غير صالح' });
  }

  room.lastPollAt = Date.now();
  pool.query(
    `UPDATE client_snapshots SET is_online = TRUE, last_seen = NOW(), token = $2 WHERE room_id = $1`,
    [roomId, token]
  ).catch(() => {});

  // أول اتصال poll لهاذ الغرفة: نطلب لقطة كاملة للوحة المتابعة باش تتحفظ فالقاعدة (كيفما WS)
  if (!room._autoSnapshotDone) {
    room._autoSnapshotDone = true;
    const autoReqId = 'auto_' + crypto.randomBytes(6).toString('hex');
    const timer = setTimeout(() => room.pendingReqs.delete(autoReqId), 120000);
    room.pendingReqs.set(autoReqId, {
      timer,
      resolve: async (data) => {
        try {
          await pool.query(
            `UPDATE client_snapshots SET snapshot = $1, last_seen = NOW(), is_online = TRUE WHERE room_id = $2`,
            [JSON.stringify(data), roomId]
          );
        } catch (e) { console.error('[snapshot] فشل حفظ البيانات:', e.message); }
      },
      reject: () => {}
    });
    room.pollQueue.push({ type: 'dashboard_full_request', reqId: autoReqId });
  }

  // لو كاين رسائل بالانتظار، رجّعها فوراً بلا ما نستنى
  if (room.pollQueue.length) {
    return res.json({ messages: room.pollQueue.splice(0, room.pollQueue.length) });
  }

  // وإلا، Long-poll: نستنى حتى 25 ثانية لأي رسالة جديدة قبل ما نرجّع قائمة فارغة
  const messages = await new Promise(resolve => {
    const timer = setTimeout(() => {
      const idx = room.pollWaiters.indexOf(waiter);
      if (idx !== -1) room.pollWaiters.splice(idx, 1);
      resolve([]);
    }, 25000);
    const waiter = (msgs) => { clearTimeout(timer); resolve(msgs); };
    room.pollWaiters.push(waiter);
  });
  res.json({ messages });
});

app.post('/api/pos-respond/:roomId', rateLimit(600), (req, res) => {
  const roomId = req.params.roomId;
  const room = getRoom(roomId);
  const token = req.query.token;
  if (!checkDashToken(room, token)) return res.status(401).json({ error: 'توكن غير صالح' });

  room.lastPollAt = Date.now(); // أي رد يعتبر أيضاً دليل حياة
  const { reqId, data } = req.body || {};
  const cleanData = sanitizePosData(data); // احذف الصور الثقيلة قبل أي تخزين أو تمرير
  if (reqId) {
    const pending = room.pendingReqs.get(reqId);
    if (pending) {
      clearTimeout(pending.timer);
      room.pendingReqs.delete(reqId);
      pending.resolve(cleanData);
    }
  }
  res.json({ ok: true });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`[Server] port=${PORT} — Relay + License API ✅ (secured)`));

// ─────────────────────────────────────────────
//  Heartbeat WebSocket — يكتشف الاتصالات الميتة
// ─────────────────────────────────────────────
const HEARTBEAT_INTERVAL = 30000;
setInterval(() => {
  wss.clients.forEach(ws => {
    if (ws.isAlive === false) return ws.terminate();
    ws.isAlive = false;
    ws.ping();
  });
}, HEARTBEAT_INTERVAL);

// ─────────────────────────────────────────────
//  KEEP-ALIVE — يمنع نوم السيرفر على Render المجاني
//  يرسل طلباً لنفسه كل 10 دقائق (< 15 دقيقة حد الخمول)
// ─────────────────────────────────────────────
const SELF_URL = process.env.RENDER_EXTERNAL_URL; // يضبطه Render تلقائياً
if (SELF_URL && typeof fetch === 'function') {
  const KEEP_ALIVE = 10 * 60 * 1000; // 10 دقائق
  setInterval(() => {
    fetch(SELF_URL + '/health')
      .then(() => console.log('[keep-alive] ping ✅', new Date().toISOString()))
      .catch(err => console.warn('[keep-alive] فشل:', err.message));
  }, KEEP_ALIVE);
  console.log('[keep-alive] مُفعّل — ping ذاتي كل 10 دقائق إلى', SELF_URL);
} else {
  console.warn('[keep-alive] RENDER_EXTERNAL_URL غير مضبوط — استخدم UptimeRobot كحل بديل.');
}
