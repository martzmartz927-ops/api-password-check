
const loginCard = document.getElementById('loginCard');
const panelCard = document.getElementById('panelCard');

const adminPass = document.getElementById('adminPass');
const loginBtn = document.getElementById('loginBtn');
const loginMsg = document.getElementById('loginMsg');
const logoutBtn = document.getElementById('logoutBtn');

const newKey = document.getElementById('newKey');
const addKeyBtn = document.getElementById('addKeyBtn');
const addMsg = document.getElementById('addMsg');

const bindBtn = document.getElementById('bindBtn');
const bindMsg = document.getElementById('bindMsg');
const refreshBtn = document.getElementById('refreshBtn');
const keysList = document.getElementById('keysList');

let pendingBindKey = null;
let bindEditor = null;

async function api(url, options = {}) {
  const res = await fetch(url, {
    credentials: 'include',
    headers: {
      'Content-Type': 'application/json',
      ...(options.headers || {})
    },
    ...options
  });
  let data = {};
  try { data = await res.json(); } catch {}
  return { res, data };
}

function showAuthed(auth) {
  loginCard.classList.toggle('hidden', auth);
  panelCard.classList.toggle('hidden', !auth);
}

function esc(text) {
  return String(text).replace(/[&<>"]/g, (c) => ({
    '&':'&amp;',
    '<':'&lt;',
    '>':'&gt;',
    '"':'&quot;'
  }[c]));
}

async function checkStatus() {
  const { data } = await api('/api/admin/status', { method: 'GET' });
  showAuthed(Boolean(data.admin));
  if (data.admin) loadKeys();
}

async function login() {
  loginMsg.textContent = 'Вход...';
  const password = adminPass.value.trim();
  const { data } = await api('/admin/login', {
    method: 'POST',
    body: JSON.stringify({ password })
  });
  if (!data.ok) {
    loginMsg.textContent = 'Неверный пароль.';
    return;
  }
  loginMsg.textContent = '';
  adminPass.value = '';
  await checkStatus();
}

async function logout() {
  await api('/admin/logout', { method: 'POST', body: '{}' });
  await checkStatus();
}

async function addKey() {
  const key = newKey.value.trim();
  if (!key) {
    addMsg.textContent = 'Введите ключ.';
    return;
  }
  addMsg.textContent = 'Добавление...';
  const { data } = await api('/api/admin/key/add', {
    method: 'POST',
    body: JSON.stringify({ key })
  });
  addMsg.textContent = data.ok ? 'Ключ добавлен.' : 'Не удалось добавить ключ.';
  if (data.ok) {
    newKey.value = '';
    await loadKeys();
  }
}

function closeBindEditor() {
  if (bindEditor) {
    bindEditor.remove();
    bindEditor = null;
    pendingBindKey = null;
  }
}

function openBindEditor(key) {
  closeBindEditor();
  pendingBindKey = key;

  bindEditor = document.createElement('div');
  bindEditor.className = 'bind-editor show';
  bindEditor.innerHTML = `
    <div class="box" style="margin-top: 0;">
      <h2>Привязка к ключу</h2>
      <div class="msg">Ключ: <strong>${esc(key)}</strong></div>
      <textarea id="scriptInput" placeholder="Вставь скрипт сюда"></textarea>
      <div class="row">
        <button id="saveScriptBtn">Сохранить скрипт</button>
        <button id="cancelScriptBtn" class="secondary">Отмена</button>
      </div>
      <div class="msg" id="scriptMsg"></div>
    </div>
  `;

  panelCard.querySelector('.box:nth-last-child(1)').appendChild(bindEditor);

  const scriptInput = bindEditor.querySelector('#scriptInput');
  const scriptMsg = bindEditor.querySelector('#scriptMsg');
  bindEditor.querySelector('#cancelScriptBtn').addEventListener('click', closeBindEditor);
  bindEditor.querySelector('#saveScriptBtn').addEventListener('click', async () => {
    const script = scriptInput.value;
    if (!script.trim()) {
      scriptMsg.textContent = 'Скрипт не должен быть пустым.';
      return;
    }
    scriptMsg.textContent = 'Сохранение...';
    const { data } = await api('/api/admin/key/attach', {
      method: 'POST',
      body: JSON.stringify({ key: pendingBindKey, script })
    });
    scriptMsg.textContent = data.ok ? 'Скрипт привязан.' : 'Не удалось привязать скрипт.';
    if (data.ok) {
      await loadKeys();
      closeBindEditor();
    }
  });
}

async function bindScript() {
  const key = prompt('Введи ключ:');
  if (!key) return;
  bindMsg.textContent = 'Проверка ключа...';

  const { data } = await api('/api/admin/keys', { method: 'GET' });
  if (!data.ok) {
    bindMsg.textContent = 'Нет доступа.';
    return;
  }

  const exists = data.keys.find(item => item.key === key.trim());
  if (!exists) {
    bindMsg.textContent = 'Ключ не найден.';
    return;
  }

  bindMsg.textContent = '';
  openBindEditor(key.trim());
}

async function loadKeys() {
  const { data } = await api('/api/admin/keys', { method: 'GET' });
  if (!data.ok) return;
  keysList.innerHTML = data.keys.length ? '' : '<div class="msg">Пока ключей нет.</div>';
  data.keys.forEach(item => {
    const row = document.createElement('div');
    row.className = 'keyrow';
    row.innerHTML = `
      <div class="keymeta">
        <div><strong>${esc(item.key)}</strong> ${item.hasScript ? '<span class="badge">script</span>' : '<span class="badge">empty</span>'}</div>
        <div>Создан: ${esc(item.createdAt || '-')}</div>
      </div>
      <button class="secondary">Привязать</button>
    `;
    row.querySelector('button').addEventListener('click', () => openBindEditor(item.key));
    keysList.appendChild(row);
  });
}

loginBtn.addEventListener('click', login);
adminPass.addEventListener('keydown', (e) => { if (e.key === 'Enter') login(); });
logoutBtn.addEventListener('click', logout);
addKeyBtn.addEventListener('click', addKey);
newKey.addEventListener('keydown', (e) => { if (e.key === 'Enter') addKey(); });
bindBtn.addEventListener('click', bindScript);
refreshBtn.addEventListener('click', loadKeys);

checkStatus();
