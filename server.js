const express = require('express');
const { WebSocketServer } = require('ws');
const http = require('http');
const path = require('path');
const fs = require('fs');

const app = express();
const server = http.createServer(app);

// ── WebSocket على نفس الـ HTTP server (يحل مشكلة 404) ───────────────────────
const wss = new WebSocketServer({ server });

// ── rooms ────────────────────────────────────────────────────────────────────
const rooms = new Map();
function getRoom(id) {
  if (!rooms.has(id)) rooms.set(id, { pos: null, phones: [] });
  return rooms.get(id);
}

// ── صفحة السكانر ─────────────────────────────────────────────────────────────
app.get('/scanner/:roomId', (req, res) => {
  const filePath = path.join(__dirname, 'scanner.html');
  if (!fs.existsSync(filePath)) {
    return res.status(404).send('scanner.html not found');
  }
  res.sendFile(filePath);
});

app.get('/health', (_, res) => res.json({ ok: true, rooms: rooms.size }));

app.get('/', (_, res) => res.send('POS Relay Server is running ✅'));

// ── WebSocket ─────────────────────────────────────────────────────────────────
wss.on('connection', (ws, req) => {
  const url    = new URL(req.url, 'http://localhost');
  const role   = url.searchParams.get('role');
  const roomId = url.searchParams.get('room');

  if (!role || !roomId) { ws.close(4000, 'missing role or room'); return; }

  const room = getRoom(roomId);

  if (role === 'pos') {
    room.pos = ws;
    console.log(`[POS] room=${roomId}`);
    ws.send(JSON.stringify({ type: 'status', msg: 'connected' }));

    ws.on('message', data => {
      room.phones.forEach(p => { if (p.readyState === 1) p.send(data.toString()); });
    });
    ws.on('close', () => { room.pos = null; });

  } else if (role === 'phone') {
    room.phones.push(ws);
    console.log(`[Phone] room=${roomId} phones=${room.phones.length}`);

    if (room.pos?.readyState === 1)
      room.pos.send(JSON.stringify({ type: 'phone_connected', count: room.phones.length }));

    ws.on('message', data => {
      const txt = data.toString().trim();
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
