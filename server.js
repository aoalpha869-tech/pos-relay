/**
 * POS Relay + License API Server
 * ================================
 * يجمع بين:
 *  - Relay Server  : ربط الهاتف (scanner) بالـ POS عبر WebSocket
 *  - License API   : إدارة مفاتيح التفعيل السحابية
 *
 * متغيرات البيئة المطلوبة على Render:
 *   DATABASE_URL   — رابط PostgreSQL (يُضاف تلقائياً عند ربط قاعدة البيانات)
 *   ADMIN_SECRET   — كلمة مرور السوبر أدمن (مثال: MySuperPass2026)
 */

const express   = require('express');
const { WebSocketServer } = require('ws');
const http      = require('http');
const path      = require('path');
const fs        = require('fs');
const { Pool }  = require('pg');
const crypto    = require('crypto');

const app    = express();
const server = http.createServer(app);
const wss    = new WebSocketServer({ server });

app.use(express.json());

// ─────────────────────────────────────────────
//  قاعدة البيانات PostgreSQL
// ─────────────────────────────────────────────
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }   // مطلوب على Render
});

// إنشاء الجدول إن لم يكن موجوداً
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
  console.log('[DB] جداول قاعدة البيانات جاهزة');

  // migration: أضف عمود revoked إذا لم يكن موجوداً
  await pool.query(`
    ALTER TABLE licenses ADD COLUMN IF NOT EXISTS revoked INTEGER NOT NULL DEFAULT 0
  `).catch(() => {}); // تجاهل الخطأ لو العمود موجود مسبقاً
}
initDB().catch(err => console.error('[DB] فشل إنشاء الجداول:', err.message));

// ─────────────────────────────────────────────
//  أدوات مساعدة
// ─────────────────────────────────────────────

/** التحقق من كلمة مرور الأدمن */
function checkAdmin(password) {
  const secret = process.env.ADMIN_SECRET || 'SUPER2026';
  return password === secret;
}

/** توليد مفتاح XXXX-XXXX-XXXX-XXXX */
function generateKey() {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789'; // بدون O,0,I,1
  const part  = () => Array.from({ length: 4 }, () =>
    chars[crypto.randomInt(0, chars.length)]
  ).join('');
  return `${part()}-${part()}-${part()}-${part()}`;
}

/** تاريخ اليوم بصيغة YYYY-MM-DD */
function today() {
  return new Date().toISOString().slice(0, 10);
}

/** إضافة أيام لتاريخ اليوم */
function addDays(days) {
  const d = new Date();
  d.setDate(d.getDate() + days);
  return d.toISOString().slice(0, 10);
}

// ─────────────────────────────────────────────
//  Middleware: التحقق من الأدمن
// ─────────────────────────────────────────────
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

/**
 * POST /api/license/activate
 * يُستدعى من تطبيق Tauri عند إدخال مفتاح التفعيل
 * Body: { key, instance_id }
 */
app.post('/api/license/activate', async (req, res) => {
  const { key, instance_id } = req.body || {};

  if (!key || !instance_id) {
    return res.status(400).json({ error: 'key و instance_id مطلوبان' });
  }

  try {
    const result = await pool.query(
      'SELECT * FROM licenses WHERE key = $1',
      [key.toUpperCase().trim()]
    );

    if (result.rows.length === 0) {
      return res.json({ ok: false, error: 'المفتاح غير صحيح أو غير موجود' });
    }

    const lic = result.rows[0];

    // مفعَّل على نسخة مختلفة → رفض
    if (lic.instance_id && lic.instance_id !== instance_id) {
      return res.json({ ok: false, error: 'هذا المفتاح مُستخدم بالفعل على نسخة أخرى' });
    }

    // مفتاح مقطوع → رفض
    if (lic.revoked) {
      return res.json({ ok: false, error: 'تم إلغاء هذا الترخيص', revoked: true });
    }

    // أول تفعيل
    const isFirstActivation = !lic.activated_at;
    let expires_at = lic.expires_at;

    if (isFirstActivation) {
      expires_at = lic.duration === 0 ? null : addDays(lic.duration);
      await pool.query(
        `UPDATE licenses
         SET activated_at = $1, expires_at = $2, instance_id = $3
         WHERE key = $4`,
        [today(), expires_at, instance_id, lic.key]
      );
    }

    // تحقق من الانتهاء
    if (expires_at && expires_at < today()) {
      return res.json({ ok: false, error: 'انتهت صلاحية هذا المفتاح' });
    }

    // حساب الأيام المتبقية
    let days_left = -1; // lifetime
    if (expires_at) {
      const diff = new Date(expires_at) - new Date(today());
      days_left = Math.max(0, Math.ceil(diff / 86400000));
    }

    res.json({
      ok:           true,
      type:         lic.type,
      expires_at:   expires_at || null,
      days_left,
      activated_at: isFirstActivation ? today() : lic.activated_at
    });

  } catch (err) {
    console.error('[license/activate]', err.message);
    res.status(500).json({ error: 'خطأ في الخادم' });
  }
});

/**
 * POST /api/license/verify
 * يُستدعى دورياً من التطبيق للتحقق من صلاحية الترخيص
 * Body: { key, instance_id }
 */
app.post('/api/license/verify', async (req, res) => {
  const { key, instance_id } = req.body || {};

  if (!key || !instance_id) {
    return res.status(400).json({ ok: false, error: 'key و instance_id مطلوبان' });
  }

  try {
    const result = await pool.query(
      'SELECT * FROM licenses WHERE key = $1 AND instance_id = $2',
      [key.toUpperCase().trim(), instance_id]
    );

    if (result.rows.length === 0) {
      return res.json({ ok: false, error: 'الترخيص غير موجود' });
    }

    const lic = result.rows[0];

    // مفتاح مقطوع → رفض فوري
    if (lic.revoked) {
      return res.json({ ok: false, error: 'تم إلغاء هذا الترخيص', revoked: true });
    }

    if (lic.expires_at && lic.expires_at < today()) {
      return res.json({ ok: false, error: 'انتهت صلاحية الترخيص', expired: true });
    }

    let days_left = -1;
    if (lic.expires_at) {
      const diff = new Date(lic.expires_at) - new Date(today());
      days_left = Math.max(0, Math.ceil(diff / 86400000));
    }

    res.json({
      ok:         true,
      type:       lic.type,
      expires_at: lic.expires_at || null,
      days_left
    });

  } catch (err) {
    console.error('[license/verify]', err.message);
    res.status(500).json({ ok: false, error: 'خطأ في الخادم' });
  }
});

// ═════════════════════════════════════════════
//  ADMIN API  (محمية بـ ADMIN_SECRET)
// ═════════════════════════════════════════════

/**
 * POST /api/admin/create
 * Body: { admin_password, type: "trial"|"annual"|"lifetime", note }
 */
app.post('/api/admin/create', requireAdmin, async (req, res) => {
  const { type = 'trial', note = '' } = req.body;

  const duration = { trial: 7, annual: 365, lifetime: 0 }[type] ?? 7;

  // توليد مفتاح فريد
  let key;
  let tries = 0;
  do {
    key = generateKey();
    const exists = await pool.query('SELECT 1 FROM licenses WHERE key = $1', [key]);
    if (exists.rows.length === 0) break;
    tries++;
  } while (tries < 10);

  try {
    await pool.query(
      `INSERT INTO licenses (key, type, duration, created_at, note)
       VALUES ($1, $2, $3, $4, $5)`,
      [key, type, duration, today(), note]
    );
    res.json({ ok: true, key });
  } catch (err) {
    console.error('[admin/create]', err.message);
    res.status(500).json({ error: 'فشل إنشاء المفتاح' });
  }
});

/**
 * POST /api/admin/list
 * Body: { admin_password }
 */
app.post('/api/admin/list', requireAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT * FROM licenses ORDER BY created_at DESC'
    );
    res.json({ ok: true, licenses: result.rows });
  } catch (err) {
    res.status(500).json({ error: 'فشل جلب القائمة' });
  }
});

/**
 * POST /api/admin/delete
 * Body: { admin_password, key }
 */
app.post('/api/admin/delete', requireAdmin, async (req, res) => {
  const { key } = req.body;
  if (!key) return res.status(400).json({ error: 'key مطلوب' });

  try {
    await pool.query('DELETE FROM licenses WHERE key = $1', [key.toUpperCase().trim()]);
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: 'فشل الحذف' });
  }
});

/**
 * POST /api/admin/revoke
 * قطع الترخيص — يبقى في القاعدة لكن يُرفض عند الاتصال
 * Body: { admin_password, key }
 */
app.post('/api/admin/revoke', requireAdmin, async (req, res) => {
  const { key } = req.body;
  if (!key) return res.status(400).json({ error: 'key مطلوب' });

  try {
    const result = await pool.query(
      'UPDATE licenses SET revoked = 1 WHERE key = $1 RETURNING key, type, note',
      [key.toUpperCase().trim()]
    );
    if (result.rowCount === 0) return res.json({ ok: false, error: 'المفتاح غير موجود' });
    res.json({ ok: true, message: 'تم قطع الترخيص — سيُوقف البرنامج عند الاتصال بالإنترنت' });
  } catch (err) {
    res.status(500).json({ error: 'فشل قطع الترخيص' });
  }
});

/**
 * POST /api/admin/unrevoke
 * استعادة ترخيص مقطوع
 * Body: { admin_password, key }
 */
app.post('/api/admin/unrevoke', requireAdmin, async (req, res) => {
  const { key } = req.body;
  if (!key) return res.status(400).json({ error: 'key مطلوب' });

  try {
    const result = await pool.query(
      'UPDATE licenses SET revoked = 0 WHERE key = $1 RETURNING key',
      [key.toUpperCase().trim()]
    );
    if (result.rowCount === 0) return res.json({ ok: false, error: 'المفتاح غير موجود' });
    res.json({ ok: true, message: 'تم استعادة الترخيص' });
  } catch (err) {
    res.status(500).json({ error: 'فشل استعادة الترخيص' });
  }
});

/**
 * POST /api/admin/reset-instance
 * إعادة تعيين instance_id (تسمح لنفس المفتاح بالتفعيل على جهاز جديد)
 * Body: { admin_password, key }
 */
app.post('/api/admin/reset-instance', requireAdmin, async (req, res) => {
  const { key } = req.body;
  if (!key) return res.status(400).json({ error: 'key مطلوب' });

  try {
    await pool.query(
      `UPDATE licenses SET instance_id = NULL, activated_at = NULL, expires_at = NULL
       WHERE key = $1`,
      [key.toUpperCase().trim()]
    );
    res.json({ ok: true, message: 'تم إعادة تعيين المفتاح — يمكن تفعيله على جهاز جديد' });
  } catch (err) {
    res.status(500).json({ error: 'فشل إعادة التعيين' });
  }
});

// ═════════════════════════════════════════════
//  Static Pages (scanner + dashboard)
// ═════════════════════════════════════════════
function sendFile(res, name) {
  const p = path.join(__dirname, name);
  if (!fs.existsSync(p)) return res.status(404).send(name + ' not found');
  res.sendFile(p);
}

app.get('/scanner/:roomId',   (req, res) => sendFile(res, 'scanner.html'));
app.get('/dashboard/:roomId', (req, res) => sendFile(res, 'dashboard.html'));
app.get('/health', (_, res) => res.json({ ok: true, rooms: rooms.size, time: new Date() }));
app.get('/admin',  (_, res) => sendFile(res, 'admin.html'));
app.get('/',       (_, res) => res.send('POS Server ✅ — Relay + License API'));

// ═════════════════════════════════════════════
//  Relay WebSocket (scanner ↔ POS)
// ═════════════════════════════════════════════
const rooms = new Map();
function getRoom(id) {
  if (!rooms.has(id))
    rooms.set(id, { pos: null, phones: [], pendingReqs: new Map() });
  return rooms.get(id);
}

async function posRequest(room, type, reqId, timeout = 12000) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      room.pendingReqs.delete(reqId);
      reject(new Error('timeout'));
    }, timeout);
    room.pendingReqs.set(reqId, { resolve, reject, timer });
    room.pos.send(JSON.stringify({ type, reqId }));
  });
}

app.get('/api/dashboard/:roomId', async (req, res) => {
  const room = getRoom(req.params.roomId);
  if (!room.pos || room.pos.readyState !== 1)
    return res.status(503).json({ error: 'POS غير متصل حالياً' });
  const reqId = Math.random().toString(36).slice(2);
  try {
    const data = await posRequest(room, 'dashboard_request', reqId);
    res.json(data);
  } catch (e) {
    res.status(504).json({ error: e.message === 'timeout' ? 'انتهى وقت الانتظار' : e.message });
  }
});

app.get('/api/dashboard-full/:roomId', async (req, res) => {
  const room = getRoom(req.params.roomId);
  if (!room.pos || room.pos.readyState !== 1)
    return res.status(503).json({ error: 'POS غير متصل حالياً' });
  const reqId = Math.random().toString(36).slice(2);
  try {
    const data = await posRequest(room, 'dashboard_full_request', reqId, 14000);
    res.json(data);
  } catch (e) {
    res.status(504).json({ error: e.message === 'timeout' ? 'انتهى وقت الانتظار' : e.message });
  }
});

wss.on('connection', (ws, req) => {
  const url    = new URL(req.url, 'http://localhost');
  const role   = url.searchParams.get('role');
  const roomId = url.searchParams.get('room');

  if (!role || !roomId) { ws.close(4000, 'missing role or room'); return; }

  const room = getRoom(roomId);

  if (role === 'pos') {
    room.pos = ws;
    console.log(`[POS] connected room=${roomId}`);
    ws.send(JSON.stringify({ type: 'status', msg: 'connected' }));

    ws.on('message', raw => {
      const txt = raw.toString().trim();
      try {
        const msg = JSON.parse(txt);
        if ((msg.type === 'dashboard_response' || msg.type === 'dashboard_full_response') && msg.reqId) {
          const pending = room.pendingReqs.get(msg.reqId);
          if (pending) {
            clearTimeout(pending.timer);
            room.pendingReqs.delete(msg.reqId);
            pending.resolve(msg.data);
            return;
          }
        }
      } catch(e) {}
      room.phones.forEach(p => { if (p.readyState === 1) p.send(txt); });
    });

    ws.on('close', () => {
      room.pos = null;
      for (const [, pending] of room.pendingReqs) {
        clearTimeout(pending.timer);
        pending.reject(new Error('POS انقطع'));
      }
      room.pendingReqs.clear();
      console.log(`[POS] disconnected room=${roomId}`);
    });

  } else if (role === 'phone') {
    room.phones.push(ws);
    console.log(`[Phone] connected room=${roomId} total=${room.phones.length}`);
    if (room.pos?.readyState === 1)
      room.pos.send(JSON.stringify({ type: 'phone_connected', count: room.phones.length }));

    ws.on('message', raw => {
      const txt = raw.toString().trim();
      if (!txt) return;
      if (room.pos?.readyState === 1)
        room.pos.send(JSON.stringify({ type: 'barcode', value: txt }));
    });

    ws.on('close', () => {
      room.phones = room.phones.filter(p => p !== ws);
      if (room.pos?.readyState === 1)
        room.pos.send(JSON.stringify({ type: 'phone_disconnected', count: room.phones.length }));
    });
  }
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`[Server] port=${PORT} — Relay + License API ✅`));
