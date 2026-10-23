'use strict';

const $ = (sel) => document.querySelector(sel);
const money = (cents) =>
  new Intl.NumberFormat('es-AR', { style: 'currency', currency: 'ARS' }).format(cents / 100);

let csrfToken = null;
let accountId = null;

async function api(path, options = {}) {
  const headers = { 'Content-Type': 'application/json' };
  if (options.method && options.method !== 'GET' && csrfToken) headers['X-CSRF-Token'] = csrfToken;
  const res = await fetch(path, { ...options, headers, credentials: 'same-origin' });
  const data = await res.json().catch(() => ({}));
  return { ok: res.ok, status: res.status, data };
}

function showView(loggedIn) {
  $('#login-view').hidden = loggedIn;
  $('#dashboard-view').hidden = !loggedIn;
}

async function loadDashboard() {
  const me = await api('/api/me');
  if (!me.ok) return showView(false);

  csrfToken = me.data.csrfToken;
  accountId = me.data.accounts[0].id;
  // textContent (no innerHTML): el navegador nunca interpreta datos como HTML => previene XSS
  $('#welcome').textContent = `Hola, ${me.data.name}`;
  $('#account-number').textContent = me.data.accounts[0].number;

  const [acc, mov] = await Promise.all([
    api(`/api/accounts/${accountId}`),
    api(`/api/accounts/${accountId}/movements`),
  ]);

  if (acc.ok) $('#balance').textContent = money(acc.data.balance);

  const tbody = $('#movements');
  tbody.replaceChildren();
  if (mov.ok) {
    for (const m of mov.data.movements) {
      const tr = document.createElement('tr');
      const date = document.createElement('td');
      date.textContent = new Date(m.date).toLocaleDateString('es-AR');
      const concept = document.createElement('td');
      concept.textContent = m.concept;
      const amount = document.createElement('td');
      amount.textContent = money(m.amount);
      amount.className = 'num ' + (m.amount < 0 ? 'neg' : 'pos');
      tr.append(date, concept, amount);
      tbody.append(tr);
    }
  }
  showView(true);
}

$('#login-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  $('#login-error').textContent = '';
  const res = await api('/api/login', {
    method: 'POST',
    body: JSON.stringify({ username: $('#username').value, password: $('#password').value }),
  });
  $('#password').value = '';
  if (res.ok) return loadDashboard();
  $('#login-error').textContent = res.data.error || 'No se pudo ingresar';
});

$('#transfer-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const msg = $('#transfer-msg');
  msg.className = '';
  const res = await api('/api/transfer', {
    method: 'POST',
    body: JSON.stringify({
      fromAccountId: accountId,
      toAccountNumber: $('#to').value.trim(),
      amount: Number($('#amount').value),
      concept: $('#concept').value.trim(),
    }),
  });
  if (res.ok) {
    msg.textContent = 'Transferencia realizada';
    msg.className = 'ok';
    e.target.reset();
    loadDashboard();
  } else {
    msg.textContent = res.data.error || 'No se pudo transferir';
    msg.className = 'error';
  }
});

$('#logout').addEventListener('click', async () => {
  await api('/api/logout', { method: 'POST' });
  csrfToken = null;
  showView(false);
});

// Si ya hay sesión activa, ir directo al panel
loadDashboard();
