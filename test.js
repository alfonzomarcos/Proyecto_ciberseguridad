'use strict';
// Pruebas de seguridad. Ejecutar con: npm test  (Node 18 o superior)
const app = require('./server');

let passed = 0, failed = 0;
function check(name, condition) {
  if (condition) { passed++; console.log(`  ✔ ${name}`); }
  else { failed++; console.log(`  ✘ ${name}`); }
}

// Cliente mínimo que guarda la cookie de sesión
function client(base) {
  let cookie = '';
  let csrf = null;
  return {
    setCsrf: (t) => { csrf = t; },
    async req(method, path, body, { sendCsrf = true } = {}) {
      const headers = { 'Content-Type': 'application/json' };
      if (cookie) headers.Cookie = cookie;
      if (csrf && sendCsrf && method !== 'GET') headers['X-CSRF-Token'] = csrf;
      const res = await fetch(base + path, { method, headers, body: body ? JSON.stringify(body) : undefined });
      const set = res.headers.getSetCookie();
      if (set.length) cookie = set.map((c) => c.split(';')[0]).join('; ');
      return { status: res.status, data: await res.json().catch(() => ({})) };
    },
  };
}

(async () => {
  const server = app.listen(0, '127.0.0.1');
  await new Promise((r) => server.once('listening', r));
  const base = `http://127.0.0.1:${server.address().port}`;

  console.log('\nAutenticación');
  const ana = client(base);
  let r = await ana.req('POST', '/api/login', { username: 'ana', password: 'incorrecta' });
  check('Contraseña incorrecta es rechazada (401)', r.status === 401);

  r = await ana.req('POST', '/api/login', { username: 'noexiste', password: 'x' });
  check('Usuario inexistente da el mismo mensaje genérico', r.status === 401 && r.data.error === 'Usuario o contraseña incorrectos');

  r = await ana.req('POST', '/api/login', { username: { $ne: null }, password: { $ne: null } });
  check('Login con objetos en vez de texto es rechazado (400)', r.status === 400);

  const anon = client(base);
  r = await anon.req('GET', '/api/accounts/101');
  check('Sin sesión no se accede a cuentas (401)', r.status === 401);

  r = await ana.req('POST', '/api/login', { username: 'ana', password: 'Ana-Demo-2024!' });
  check('Credenciales correctas permiten ingresar', r.status === 200);

  r = await ana.req('GET', '/api/me');
  ana.setCsrf(r.data.csrfToken);
  check('/api/me devuelve token CSRF', typeof r.data.csrfToken === 'string' && r.data.csrfToken.length === 64);

  console.log('\nControl de acceso (IDOR)');
  r = await ana.req('GET', '/api/accounts/101');
  check('Ana ve su propia cuenta (200)', r.status === 200);

  r = await ana.req('GET', '/api/accounts/102');
  check('Ana NO ve la cuenta de Marcos (404)', r.status === 404);

  r = await ana.req('GET', '/api/accounts/102/movements');
  check('Ana NO ve los movimientos de Marcos (404)', r.status === 404);

  r = await ana.req('GET', '/api/accounts/abc');
  check('ID no numérico es rechazado (404)', r.status === 404);

  r = await ana.req('POST', '/api/transfer', { fromAccountId: 102, toAccountNumber: 'AR00-0001-0101', amount: 100, concept: 'robo' });
  check('Ana NO puede transferir desde la cuenta de Marcos (404)', r.status === 404);

  console.log('\nTransferencias');
  const good = { fromAccountId: 101, toAccountNumber: 'AR00-0001-0102', amount: 100.5, concept: 'Pago cena' };

  r = await ana.req('POST', '/api/transfer', good, { sendCsrf: false });
  check('Sin token CSRF se rechaza (403)', r.status === 403);

  r = await ana.req('POST', '/api/transfer', { ...good, amount: -50 });
  check('Importe negativo rechazado (400)', r.status === 400);

  r = await ana.req('POST', '/api/transfer', { ...good, amount: '100' });
  check('Importe como texto rechazado (400)', r.status === 400);

  r = await ana.req('POST', '/api/transfer', { ...good, amount: 10.999 });
  check('Más de 2 decimales rechazado (400)', r.status === 400);

  r = await ana.req('POST', '/api/transfer', { ...good, concept: '<script>alert(1)</script>' });
  check('Concepto con caracteres peligrosos rechazado (400)', r.status === 400);

  r = await ana.req('POST', '/api/transfer', { ...good, toAccountNumber: "AR00' OR 1=1" });
  check('Cuenta destino con formato inválido rechazada (400)', r.status === 400);

  r = await ana.req('POST', '/api/transfer', { ...good, amount: 999999 });
  check('Saldo insuficiente rechazado (400)', r.status === 400);

  const before = (await ana.req('GET', '/api/accounts/101')).data.balance;
  r = await ana.req('POST', '/api/transfer', good);
  const after = (await ana.req('GET', '/api/accounts/101')).data.balance;
  check('Transferencia válida aceptada y saldo actualizado', r.status === 200 && before - after === 10050);

  console.log('\nBloqueo por intentos fallidos');
  const bad = client(base);
  for (let i = 0; i < 5; i++) await bad.req('POST', '/api/login', { username: 'marcos', password: 'mala' });
  r = await bad.req('POST', '/api/login', { username: 'marcos', password: 'Marcos-Demo-2024!' });
  check('Tras 5 fallos, ni la contraseña correcta entra (429)', r.status === 429);

  console.log('\nCierre de sesión');
  await ana.req('POST', '/api/logout');
  r = await ana.req('GET', '/api/accounts/101');
  check('Tras logout la sesión ya no sirve (401)', r.status === 401);

  server.close();
  console.log(`\nResultado: ${passed} OK, ${failed} fallidas\n`);
  process.exit(failed ? 1 : 0);
})();
