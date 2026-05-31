const passwordInput = document.getElementById('password');
const checkBtn = document.getElementById('checkBtn');
const result = document.getElementById('result');

async function checkPassword() {
  const pass = passwordInput.value.trim();
  if (!pass) {
    result.textContent = 'Введите пароль.';
    result.className = 'result bad';
    return;
  }

  try {
    const res = await fetch('/api/check', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ pass })
    });

    const data = await res.json();
    const ok = Boolean(data.ok);

    result.textContent = ok ? 'true' : 'false';
    result.className = ok ? 'result ok' : 'result bad';
  } catch (err) {
    result.textContent = 'Ошибка соединения с API.';
    result.className = 'result bad';
  }
}

checkBtn.addEventListener('click', checkPassword);
passwordInput.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') checkPassword();
});
