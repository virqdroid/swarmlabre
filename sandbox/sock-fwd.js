'use strict';
// Loopback forwarder for sandboxes with no network: 127.0.0.1:$SWARMLABRE_PROXY_PORT -> the model proxy's Unix socket.
// Listens on loopback only and connects to one fixed path; it reads no arguments and no other environment.
const net = require('net');
const SOCK = '/run/proxy/model.sock';
const port = Number(process.env.SWARMLABRE_PROXY_PORT || 8801);
if (!Number.isInteger(port) || port < 1024 || port > 65535) process.exit(2);
net.createServer((c) => {
  const u = net.connect(SOCK);
  const end = () => { c.destroy(); u.destroy(); };
  c.pipe(u); u.pipe(c);
  c.on('error', end); u.on('error', end); c.on('close', end); u.on('close', end);
}).listen(port, '127.0.0.1');
