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

// CORS
app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", "*");
  res.header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
  res.header("Access-Control-Allow-Headers", "Content-Type, Authorization");
  if (req.method === "OPTIONS") return res.sendStatus(200);
  next();
});

// ─────────────────────────────────────────────
//  قاعدة البيانات PostgreSQL
// ─────────────────────────────────────────────
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }   // مطلوب على Render
});

// إنشاء الجداول إن لم تكن موجودة
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

  // migration: أضف عمود revoked إذا لم يكن موجوداً
  await pool.query(`
    ALTER TABLE licenses ADD COLUMN IF NOT EXISTS revoked INTEGER NOT NULL DEFAULT 0
  `).catch(() => {});

  // جدول snapshots: آخر بيانات كل عميل
  await pool.query(`
    CREATE TABLE IF NOT EXISTS client_snapshots (
      license_key   TEXT PRIMARY KEY REFERENCES licenses(key) ON DELETE CASCADE,
      last_seen     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      is_online     BOOLEAN NOT NULL DEFAULT FALSE,
      room_id       TEXT DEFAULT NULL,
      snapshot      JSONB DEFAULT NULL
    )
  `);

  console.log('[DB] جداول قاعدة البيانات جاهزة');
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
      // إنشاء سجل snapshot للعميل الجديد
      await pool.query(
        `INSERT INTO client_snapshots (license_key, last_seen, is_online, room_id)
         VALUES ($1, NOW(), FALSE, $2)
         ON CONFLICT (license_key) DO NOTHING`,
        [lic.key, instance_id]
      ).catch(() => {});
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
  const { key, instance_id, room_id } = req.body || {};

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

    // ── حفظ room_id إذا أُرسل ─────────────────────────────────────────
    if (room_id && room_id.trim()) {
      pool.query(
        `INSERT INTO client_snapshots (license_key, last_seen, is_online, room_id)
         VALUES ($1, NOW(), FALSE, $2)
         ON CONFLICT (license_key) DO UPDATE
           SET room_id = $2, last_seen = NOW()`,
        [lic.key, room_id.trim()]
      ).catch(() => {});
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

/**
 * POST /api/license/register-room
 * يُستدعى من الـ POS عند بدء تشغيل الـ scanner لربط room_id بالمفتاح
 * Body: { key, instance_id, room_id }
 */
app.post('/api/license/register-room', async (req, res) => {
  const { key, instance_id, room_id } = req.body || {};
  if (!key || !instance_id || !room_id) {
    return res.status(400).json({ ok: false, error: 'key و instance_id و room_id مطلوبة' });
  }

  try {
    // تحقق أن المفتاح صحيح وينتمي لهذا الجهاز
    const result = await pool.query(
      'SELECT key FROM licenses WHERE key = $1 AND instance_id = $2 AND revoked = 0',
      [key.toUpperCase().trim(), instance_id]
    );
    if (result.rows.length === 0) {
      return res.json({ ok: false, error: 'الترخيص غير صالح' });
    }

    const licKey = result.rows[0].key;

    // نحدّث أو ننشئ سجل الـ snapshot بـ room_id
    await pool.query(
      `INSERT INTO client_snapshots (license_key, last_seen, is_online, room_id)
       VALUES ($1, NOW(), FALSE, $2)
       ON CONFLICT (license_key) DO UPDATE
         SET room_id = $2, last_seen = NOW()`,
      [licKey, room_id]
    );

    res.json({ ok: true });
  } catch (err) {
    console.error('[register-room]', err.message);
    res.status(500).json({ ok: false, error: 'خطأ في السيرفر' });
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

/**
 * POST /api/admin/link-room
 * ربط room_id بمفتاح عميل يدوياً من صفحة الأدمن
 * Body: { key, room_id }  — محمي بـ x-admin-password header
 */
app.post('/api/admin/link-room', requireAdmin, async (req, res) => {
  const { key, room_id } = req.body || {};
  if (!key || !room_id) return res.status(400).json({ error: 'key و room_id مطلوبان' });

  try {
    // نتحقق أن المفتاح موجود
    const lic = await pool.query('SELECT key FROM licenses WHERE key = $1', [key.toUpperCase().trim()]);
    if (lic.rows.length === 0) return res.json({ ok: false, error: 'المفتاح غير موجود' });

    // نحدّث أو ننشئ سجل snapshot بـ room_id
    await pool.query(
      `INSERT INTO client_snapshots (license_key, last_seen, is_online, room_id)
       VALUES ($1, NOW(), FALSE, $2)
       ON CONFLICT (license_key) DO UPDATE
         SET room_id = $2, last_seen = NOW()`,
      [lic.rows[0].key, room_id.trim()]
    );

    // نحدّث is_online إذا الـ room متصل فعلاً
    const room = rooms.get(room_id.trim());
    if (room?.pos?.readyState === 1) {
      await pool.query(
        'UPDATE client_snapshots SET is_online = TRUE WHERE license_key = $1',
        [lic.rows[0].key]
      );
    }

    res.json({ ok: true });
  } catch (err) {
    console.error('[link-room]', err.message);
    res.status(500).json({ error: 'فشل الربط' });
  }
});

/**
 * POST /api/admin/client-snapshot
 * جلب آخر snapshot محفوظ لعميل معين
 * Body: { admin_password, key }
 */
app.post('/api/admin/client-snapshot', requireAdmin, async (req, res) => {
  const { key } = req.body;
  if (!key) return res.status(400).json({ error: 'key مطلوب' });

  try {
    const result = await pool.query(
      'SELECT * FROM client_snapshots WHERE license_key = $1',
      [key.toUpperCase().trim()]
    );
    res.json({ ok: true, snapshot: result.rows[0] || null });
  } catch (err) {
    res.status(500).json({ error: 'فشل جلب البيانات' });
  }
});

/**
 * GET /api/admin/client-live/:key
 * جلب بيانات مباشرة من الجهاز إذا كان متصلاً
 */
app.get('/api/admin/client-live/:key', async (req, res) => {
  const pass = req.headers['x-admin-password'];
  if (!checkAdmin(pass)) return res.status(401).json({ error: 'غير مصرح' });

  const key = req.params.key.toUpperCase().trim();

  // نبحث عن roomId الخاص بهذا المفتاح
  const snap = await pool.query(
    'SELECT room_id, is_online FROM client_snapshots WHERE license_key = $1',
    [key]
  ).catch(() => ({ rows: [] }));

  const row = snap.rows[0];
  if (!row || !row.room_id || !row.is_online) {
    return res.status(503).json({ error: 'الجهاز غير متصل حالياً', offline: true });
  }

  const room = getRoom(row.room_id);
  if (!room.pos || room.pos.readyState !== 1) {
    // تحديث حالة الاتصال
    await pool.query(
      'UPDATE client_snapshots SET is_online = FALSE WHERE license_key = $1', [key]
    ).catch(() => {});
    return res.status(503).json({ error: 'الجهاز غير متصل حالياً', offline: true });
  }

  const reqId = Math.random().toString(36).slice(2);
  try {
    const data = await posRequest(room, 'dashboard_full_request', reqId, 14000);
    // نحفظ snapshot تلقائياً
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
app.get('/',       (_, res) => sendFile(res, 'download.html'));

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

  // ── Heartbeat: نعلّم الاتصال أنه حي عند كل pong ──────────────────────────
  ws.isAlive = true;
  ws.on('pong', () => { ws.isAlive = true; });

  const room = getRoom(roomId);

  if (role === 'pos') {
    room.pos = ws;
    console.log(`[POS] connected room=${roomId}`);
    ws.send(JSON.stringify({ type: 'status', msg: 'connected' }));

    // تحديث حالة الاتصال في قاعدة البيانات
    pool.query(
      `UPDATE client_snapshots SET is_online = TRUE, last_seen = NOW()
       WHERE room_id = $1`,
      [roomId]
    ).catch(() => {});

    // جلب snapshot تلقائي بعد 3 ثواني من الاتصال
    const autoReqId = 'auto_' + Math.random().toString(36).slice(2);
    setTimeout(() => {
      if (ws.readyState !== 1) return;
      const timer = setTimeout(() => room.pendingReqs.delete(autoReqId), 15000);
      room.pendingReqs.set(autoReqId, {
        timer,
        resolve: async (data) => {
          try {
            // نبحث بـ room_id مباشرة في client_snapshots (تم ربطه مسبقاً عبر register-room)
            await pool.query(
              `UPDATE client_snapshots
               SET snapshot = $1, last_seen = NOW(), is_online = TRUE
               WHERE room_id = $2`,
              [JSON.stringify(data), roomId]
            );
          } catch(e) { console.error('[snapshot] فشل حفظ البيانات:', e.message); }
        },
        reject: () => {}
      });
      ws.send(JSON.stringify({ type: 'dashboard_full_request', reqId: autoReqId }));
    }, 3000);

    ws.on('message', raw => {
      const txt = raw.toString().trim();
      try {
        const msg = JSON.parse(txt);

        // ── رد على ping التطبيقي القادم من POS (heartbeat) ─────────────────
        if (msg.type === 'ping') {
          ws.send(JSON.stringify({ type: 'pong' }));
          return;
        }

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
      // تحديث حالة الاتصال عند الانقطاع
      pool.query(
        `UPDATE client_snapshots SET is_online = FALSE, last_seen = NOW()
         WHERE room_id = $1`,
        [roomId]
      ).catch(() => {});
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

// ─────────────────────────────────────────────
//  Heartbeat: فحص الاتصالات الخاملة كل 30 ثانية
//  يحل مشكلة "half-open connections" التي تجعل
//  السيرفر يعتقد أن POS متصل بينما الاتصال ميت فعلاً
// ─────────────────────────────────────────────
const HEARTBEAT_INTERVAL = 30000; // 30 ثانية

setInterval(() => {
  wss.clients.forEach(ws => {
    if (ws.isAlive === false) {
      // لم يردّ على آخر ping → الاتصال ميت، نغلقه فعلياً
      return ws.terminate();
    }
    ws.isAlive = false;
    ws.ping();
  });
}, HEARTBEAT_INTERVAL);
