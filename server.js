const express = require('express');
const { WebSocketServer } = require('ws');
const http = require('http');
const path = require('path');
const fs   = require('fs');

const app    = express();
const server = http.createServer(app);
const wss    = new WebSocketServer({ server });

app.use(express.json());

// ── rooms ────────────────────────────────────────────────────────────────────
// room = { pos: WebSocket|null, phones: WebSocket[], pendingReqs: Map<reqId, {resolve,reject,timer}> }
const rooms = new Map();
function getRoom(id) {
  if (!rooms.has(id)) rooms.set(id, { pos: null, phones: [], pendingReqs: new Map() });
  return rooms.get(id);
}

// ── Static pages ──────────────────────────────────────────────────────────────
function sendFile(res, name) {
  const p = path.join(__dirname, name);
  if (!fs.existsSync(p)) return res.status(404).send(name + ' not found');
  res.sendFile(p);
}

app.get('/scanner/:roomId',   (req, res) => sendFile(res, 'scanner.html'));
app.get('/dashboard/:roomId', (req, res) => sendFile(res, 'dashboard.html'));
app.get('/health', (_, res) => res.json({ ok: true, rooms: rooms.size }));
app.get('/', (_, res) => res.send('POS Relay Server ✅'));

// ── Dashboard API ─────────────────────────────────────────────────────────────
// الهاتف يطلب /api/dashboard/:roomId
// الـ relay يرسل طلب للـ POS عبر WebSocket ثم ينتظر الجواب
app.get('/api/dashboard/:roomId', async (req, res) => {
  const room = getRoom(req.params.roomId);
  if (!room.pos || room.pos.readyState !== 1) {
    return res.status(503).json({ error: 'POS غير متصل حالياً' });
  }

  const reqId = Math.random().toString(36).slice(2);
  const TIMEOUT = 10000; // 10 ثانية

  try {
    const data = await new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        room.pendingReqs.delete(reqId);
        reject(new Error('timeout'));
      }, TIMEOUT);

      room.pendingReqs.set(reqId, { resolve, reject, timer });
      room.pos.send(JSON.stringify({ type: 'dashboard_request', reqId }));
    });
    res.json(data);
  } catch (e) {
    res.status(504).json({ error: e.message === 'timeout' ? 'انتهى وقت انتظار الـ POS' : e.message });
  }
});

// ── WebSocket ─────────────────────────────────────────────────────────────────
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

      // هل هو رد dashboard؟
      try {
        const msg = JSON.parse(txt);
        if (msg.type === 'dashboard_response' && msg.reqId) {
          const pending = room.pendingReqs.get(msg.reqId);
          if (pending) {
            clearTimeout(pending.timer);
            room.pendingReqs.delete(msg.reqId);
            pending.resolve(msg.data);
            return;
          }
        }
      } catch(e) {}

      // رسالة عادية → ابعثها للهواتف
      room.phones.forEach(p => { if (p.readyState === 1) p.send(txt); });
    });

    ws.on('close', () => {
      room.pos = null;
      // أفشل كل الطلبات المعلقة
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
      console.log(`[Barcode] room=${roomId} value=${txt}`);
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
server.listen(PORT, () => console.log(`[Relay] port=${PORT}`));
