function filterUsers() {
  const filter = document.getElementById("searchUser").value.toLowerCase();
  document.querySelectorAll('.user-card').forEach(card => {
    const username = card.querySelector('h4').textContent.toLowerCase();
    card.style.display = username.includes(filter) ? '' : 'none';
  });
}

async function grantUserAccess(userId, btn) {
  const select = btn.closest('.user-card').querySelector('.controller-select');
  const controllers = Array.from(select.selectedOptions).map(opt => opt.value);
  if(controllers.length === 0) { alert("Выберите контроллер(ы)"); return; }

  const res = await fetch('/admin/grant-access', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({user_id: userId, controllers})
  });
  if(res.ok) alert("Доступ выдан");
  else alert("Ошибка");
}

async function revokeUserAccess(userId, btn) {
  const select = btn.closest('.user-card').querySelector('.controller-select');
  const controllers = Array.from(select.selectedOptions).map(opt => opt.value);
  if(controllers.length === 0) { alert("Выберите контроллер(ы)"); return; }

  const res = await fetch('/admin/revoke-access', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({user_id: userId, controllers})
  });
  if(res.ok) alert("Доступ удалён");
  else alert("Ошибка");
}

async function grantAllControllers(userId) {
  const res = await fetch('/admin/grant-access-all', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({user_id: userId})
  });
  if(res.ok) alert("Доступ ко всем выдан");
  else alert("Ошибка");
}

async function revokeAllControllers(userId) {
  const res = await fetch('/admin/revoke-access-all', {
    method: 'POST',
    headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({user_id: userId})
  });
  if(res.ok) alert("Доступ ко всем удалён");
  else alert("Ошибка");
}
