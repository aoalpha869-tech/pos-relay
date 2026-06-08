const express = require('express');
const { WebSocketServer } = require('ws');
const http = require('http');
const path = require('path');

const app = express();
const server = http.createServer(app);
const wss = new WebSocketServer({ server });

// ── حالة الاتصالات ──────────────────────────────────────────────────────────
// roomId → { pos: WebSocket|null, phones: WebSocket[] }
const rooms = new Map();

function getRoom(id) {
  if (!rooms.has(id)) rooms.set(id, { pos: null, phones: [] });
  return rooms.get(id);
}

// ── صفحة السكانر ─────────────────────────────────────────────────────────────
app.get('/scanner/:roomId', (req, res) => {
  res.sendFile(path.join(__dirname, 'scanner.html'));
});

app.get('/health', (_, res) => res.json({ ok: true }));

// ── WebSocket Relay ───────────────────────────────────────────────────────────
wss.on('connection', (ws, req) => {
  const url = new URL(req.url, 'http://localhost');
  const role   = url.searchParams.get('role');   // 'pos' أو 'phone'
  const roomId = url.searchParams.get('room');   // معرف الجلسة

  if (!role || !roomId) { ws.close(4000, 'missing role or room'); return; }

  const room = getRoom(roomId);

  if (role === 'pos') {
    // ── POS يتصل ──────────────────────────────────────────────────────────
    room.pos = ws;
    console.log(`[POS] اتصل بالغرفة ${roomId}`);
    ws.send(JSON.stringify({ type: 'status', msg: 'connected', phones: room.phones.length }));

    ws.on('message', (data) => {
      // POS يرسل للهواتف (اختياري)
      room.phones.forEach(p => { if (p.readyState === 1) p.send(data.toString()); });
    });

    ws.on('close', () => {
      room.pos = null;
      console.log(`[POS] قطع الاتصال من الغرفة ${roomId}`);
    });

  } else if (role === 'phone') {
    // ── هاتف يتصل ────────────────────────────────────────────────────────
    room.phones.push(ws);
    console.log(`[Phone] هاتف جديد في الغرفة ${roomId} (${room.phones.length} هواتف)`);

    // أبلغ POS بوصول هاتف
    if (room.pos && room.pos.readyState === 1) {
      room.pos.send(JSON.stringify({ type: 'phone_connected', count: room.phones.length }));
    }

    ws.on('message', (data) => {
      const txt = data.toString().trim();
      if (!txt) return;
      console.log(`[Barcode] الغرفة ${roomId}: ${txt}`);
      // أرسل الباركود للـ POS
      if (room.pos && room.pos.readyState === 1) {
        room.pos.send(JSON.stringify({ type: 'barcode', value: txt }));
      }
    });

    ws.on('close', () => {
      room.phones = room.phones.filter(p => p !== ws);
      if (room.pos && room.pos.readyState === 1) {
        room.pos.send(JSON.stringify({ type: 'phone_disconnected', count: room.phones.length }));
      }
    });
  }
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => console.log(`[Relay] يعمل على المنفذ ${PORT}`));
