'use strict';
const express = require('express');
const session = require('express-session');
const helmet = require('helmet');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const app = express();
const LOG_FILE = path.join(__dirname, 'security.log');

/* ------------------------------------------------------------------
   "BASE DE DATOS" EN MEMORIA (todo ficticio)
   Los importes se guardan en centavos (enteros) para evitar errores
   de redondeo con decimales.
------------------------------------------------------------------- */
const users = [
  { id: 1, username: 'ana',    name: 'Ana Pérez',     passwordHash: bcrypt.hashSync('Ana-Demo-2024!', 12) },
  { id: 2, username: 'marcos', name: 'Marcos Gómez',  passwordHash: bcrypt.hashSync('Marcos-Demo-2024!', 12) },
];

const accounts = [
  {
    id: 101, ownerId: 1, number: 'AR00-0001-0101', balance: 15000000,
    movements: [
      { id: 1, date: '2026-10-01T10:00:00Z', concept: 'Sueldo',              amount: 20000000 },
      { id: 2, date: '2026-10-05T15:30:00Z', concept: 'Supermercado',        amount: -4500000 },
      { id: 3, date: '2026-10-10T09:10:00Z', concept: 'Alquiler',            amount: -3500000 },
      { id: 4, date: '2026-10-15T18:45:00Z', concept: 'Transferencia recibida', amount: 3000000 },
    ],
  },
  {
    id: 102, ownerId: 2, number: 'AR00-0001-0102', balance: 8000000,
    movements: [
      { id: 1, date: '2026-10-02T11:00:00Z', concept: 'Sueldo',   amount: 10000000 },
      { id: 2, date: '2026-10-08T20:00:00Z', concept: 'Cena',     amount: -2000000 },
    ],
  },
];

// Hash falso para comparar siempre, aunque el usuario no exista (evita revelar usuarios por tiempo de respuesta)
const DUMMY_HASH = bcrypt.hashSync('no-existe', 12);

/* ------------------------------------------------------------------
   REGISTRO DE EVENTOS (nunca se guardan contraseñas ni tokens)
------------------------------------------------------------------- */
function log(event, data, req) {
  const entry = {
    time: new Date().toISOString(),
    event,
    ip: req && req.ip,
    userId: req && req.session && req.session.userId,
    ...data,
  };
  fs.appendFile(LOG_FILE, JSON.stringify(entry) + '\n', () => {}); // JSON.stringify escapa saltos de línea (evita log injection)
}

/* ------------------------------------------------------------------
   MIDDLEWARES DE SEGURIDAD
------------------------------------------------------------------- */
app.set('trust proxy', false);
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],      // sin scripts inline => mitiga XSS
      styleSrc: ["'self'"],
      imgSrc: ["'self'"],
      objectSrc: ["'none'"],
      frameAncestors: ["'none'"], // anti-clickjacking
      upgradeInsecureRequests: null, // para poder probar en http://localhost
    },
  },
}));

app.use(express.json({ limit: '10kb' })); // limita el tamaño del body

app.use(session({
  name: 'sid',
  secret: process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex'),
  resave: false,
  saveUninitialized: false,
  rolling: true,
  cookie: {
    httpOnly: true,                                   // JS del navegador no puede leer la cookie
    sameSite: 'strict',                               // no se envía desde otros sitios (mitiga CSRF)
    secure: process.env.NODE_ENV === 'production',    // solo HTTPS en producción
    maxAge: 15 * 60 * 1000,                           // sesión de 15 minutos
  },
}));

app.use('/api', (req, res, next) => {
  res.set('Cache-Control', 'no-store'); // datos financieros: que no se cacheen
  next();
});

/* ------------------------------------------------------------------
   AUTENTICACIÓN: bloqueo de intentos fallidos
------------------------------------------------------------------- */
const MAX_ATTEMPTS = 5;
const LOCK_MS = 15 * 60 * 1000;
const attempts = new Map(); // clave: ip|usuario -> { count, lockedUntil }

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body || {};

  if (typeof username !== 'string' || typeof password !== 'string' ||
      !username || !password || username.length > 30 || password.length > 72) {
    return res.status(400).json({ error: 'Datos inválidos' });
  }

  const uname = username.toLowerCase();
  const key = `${req.ip}|${uname}`;
  const rec = attempts.get(key) || { count: 0, lockedUntil: 0 };

  if (rec.lockedUntil > Date.now()) {
    log('login_blocked', { username: uname }, req);
    return res.status(429).json({ error: 'Demasiados intentos. Probá más tarde.' });
  }

  const user = users.find((u) => u.username === uname);
  const ok = await bcrypt.compare(password, user ? user.passwordHash : DUMMY_HASH);

  if (!user || !ok) {
    rec.count += 1;
    if (rec.count >= MAX_ATTEMPTS) {
      rec.lockedUntil = Date.now() + LOCK_MS;
      rec.count = 0;
      log('account_locked', { username: uname }, req);
    }
    attempts.set(key, rec);
    log('login_failed', { username: uname }, req);
    // Mensaje genérico: no revela si el usuario existe
    return res.status(401).json({ error: 'Usuario o contraseña incorrectos' });
  }

  attempts.delete(key);
  // Nueva sesión al loguearse (previene "session fixation")
  req.session.regenerate((err) => {
    if (err) return res.status(500).json({ error: 'Error interno' });
    req.session.userId = user.id;
    req.session.csrf = crypto.randomBytes(32).toString('hex');
    log('login_ok', {}, req);
    res.json({ ok: true });
  });
});

app.post('/api/logout', (req, res) => {
  log('logout', {}, req);
  req.session.destroy(() => {
    res.clearCookie('sid');
    res.json({ ok: true });
  });
});

function requireAuth(req, res, next) {
  if (!req.session || !req.session.userId) {
    log('unauthenticated_access', { path: req.path }, req);
    return res.status(401).json({ error: 'No autenticado' });
  }
  next();
}

function requireCsrf(req, res, next) {
  const sent = req.get('x-csrf-token') || '';
  const expected = req.session.csrf || '';
  const a = Buffer.from(sent);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    log('csrf_rejected', { path: req.path }, req);
    return res.status(403).json({ error: 'Token CSRF inválido' });
  }
  next();
}

/* ------------------------------------------------------------------
   CONTROL DE ACCESO: la cuenta debe pertenecer al usuario de la sesión
------------------------------------------------------------------- */
function getOwnedAccount(req, res) {
  const id = Number(req.params.id);
  const acc = Number.isInteger(id) ? accounts.find((a) => a.id === id) : null;
  if (!acc || acc.ownerId !== req.session.userId) {
    log('access_denied', { accountId: req.params.id.slice(0, 20) }, req);
    // Misma respuesta si no existe o si es de otro: no se revela qué cuentas existen
    res.status(404).json({ error: 'Cuenta no encontrada' });
    return null;
  }
  return acc;
}

app.get('/api/me', requireAuth, (req, res) => {
  const user = users.find((u) => u.id === req.session.userId);
  const myAccounts = accounts
    .filter((a) => a.ownerId === user.id)
    .map((a) => ({ id: a.id, number: a.number }));
  res.json({ name: user.name, accounts: myAccounts, csrfToken: req.session.csrf });
});

app.get('/api/accounts/:id', requireAuth, (req, res) => {
  const acc = getOwnedAccount(req, res);
  if (!acc) return;
  res.json({ id: acc.id, number: acc.number, balance: acc.balance });
});

app.get('/api/accounts/:id/movements', requireAuth, (req, res) => {
  const acc = getOwnedAccount(req, res);
  if (!acc) return;
  res.json({ movements: [...acc.movements].reverse() });
});

/* ------------------------------------------------------------------
   TRANSFERENCIAS: validación estricta de datos (lista blanca)
------------------------------------------------------------------- */
const ACCOUNT_NUMBER_RE = /^AR00-\d{4}-\d{4}$/;
const CONCEPT_RE = /^[\p{L}\p{N} .,\-]{1,60}$/u;
const MAX_TRANSFER_CENTS = 100000000; // $1.000.000 por operación

app.post('/api/transfer', requireAuth, requireCsrf, (req, res) => {
  const { fromAccountId, toAccountNumber, amount, concept } = req.body || {};

  const fail = (msg) => {
    log('transfer_rejected', { reason: msg }, req);
    return res.status(400).json({ error: msg });
  };

  if (!Number.isInteger(fromAccountId)) return fail('Cuenta de origen inválida');
  if (typeof toAccountNumber !== 'string' || !ACCOUNT_NUMBER_RE.test(toAccountNumber)) {
    return fail('Cuenta de destino inválida');
  }
  if (typeof amount !== 'number' || !Number.isFinite(amount) || amount <= 0) {
    return fail('Importe inválido');
  }
  const cents = Math.round(amount * 100);
  if (Math.abs(cents - amount * 100) > 1e-6) return fail('Máximo 2 decimales');
  if (cents > MAX_TRANSFER_CENTS) return fail('Supera el límite por operación');
  if (typeof concept !== 'string' || !CONCEPT_RE.test(concept)) return fail('Concepto inválido');

  // El origen se valida contra la SESIÓN, nunca se confía en lo que manda el cliente
  const from = accounts.find((a) => a.id === fromAccountId);
  if (!from || from.ownerId !== req.session.userId) {
    log('access_denied', { action: 'transfer', accountId: fromAccountId }, req);
    return res.status(404).json({ error: 'Cuenta no encontrada' });
  }

  const to = accounts.find((a) => a.number === toAccountNumber);
  if (!to) return fail('Cuenta de destino inexistente');
  if (to.id === from.id) return fail('No podés transferir a la misma cuenta');
  if (from.balance < cents) return fail('Saldo insuficiente');

  const now = new Date().toISOString();
  from.balance -= cents;
  to.balance += cents;
  from.movements.push({ id: from.movements.length + 1, date: now, concept, amount: -cents });
  to.movements.push({ id: to.movements.length + 1, date: now, concept: `Transferencia recibida: ${concept}`, amount: cents });

  log('transfer_ok', { from: from.id, to: to.id, cents }, req);
  res.json({ ok: true, balance: from.balance });
});

/* ------------------------------------------------------------------
   FRONTEND ESTÁTICO + MANEJO DE ERRORES
------------------------------------------------------------------- */
app.use(express.static(path.join(__dirname, 'public')));

app.use((err, req, res, next) => { // eslint-disable-line no-unused-vars
  // No se devuelve el stack al cliente
  log('server_error', { message: String(err.message).slice(0, 100) }, req);
  res.status(err.status || 500).json({ error: 'Error en la solicitud' });
});

if (require.main === module) {
  const PORT = process.env.PORT || 3000;
  app.listen(PORT, '127.0.0.1', () => console.log(`Banco demo en http://localhost:${PORT}`));
}

module.exports = app;
