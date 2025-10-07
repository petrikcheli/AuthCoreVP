# AuthCoreVP
Сервис централизованной авторизации для промышленных контроллеров

# 📘 API документация: Admin Panel

Эти эндпоинты используются администратором для управления пользователями, контроллерами и доступами.  
Все API возвращают **JSON** и требуют **JWT-токен** (если не указано иное).

---

## 🔐 `/api/admin/login`
**Метод:** `POST`  
**Авторизация:** не требуется  

**Описание:**  
Авторизация администратора, получение JWT-токена.

**Вход (JSON):**
```json
{
  "username": "admin",
  "password": "admin123"
}
```

**Ответ (успешно):**
```json
{
  "token": "<JWT-token>",
  "username": "admin"
}
```

**Ошибки:**
- `400 Invalid JSON`
- `401 Unauthorized` — неверные данные входа

---

## 👥 `/api/admin/users`
**Метод:** `GET`  
**Авторизация:** `Bearer <token>`  

**Описание:**  
Возвращает список всех пользователей в системе.

**Ответ (JSON):**
```json
[
  {
    "id": 1,
    "username": "admin",
    "role": "admin"
  },
  {
    "id": 2,
    "username": "operator1",
    "role": "operator"
  }
]
```

**Ошибки:**
- `401 Unauthorized` — токен отсутствует или недействителен

---

## ➕ `/api/admin/add-user`
**Метод:** `POST`  
**Авторизация:** `Bearer <token>`  

**Описание:**  
Добавляет нового пользователя.

**Вход (JSON):**
```json
{
  "username": "operator1",
  "full_name": "Иван Иванов",
  "password": "12345",
  "role": "operator"
}
```

**Ответ:**  
`200 User added`  

**Ошибки:**
- `400 Missing fields`
- `400 Failed to add user`
- `401 Unauthorized`

---

## ❌ `/api/admin/delete-user`
**Метод:** `POST`  
**Авторизация:** `Bearer <token>`  

**Описание:**  
Удаляет пользователя по ID.

**Вход (JSON):**
```json
{
  "id": 2
}
```

**Ответ:**  
`200 User deleted`  

**Ошибки:**
- `400 Invalid user ID`
- `401 Unauthorized`

---

## ⚙️ `/api/admin/controllers`
**Метод:** `GET`  
**Авторизация:** `Bearer <token>`  

**Описание:**  
Возвращает список всех контроллеров.

**Ответ (JSON):**
```json
[
  {
    "id": 1,
    "name": "Main Entrance",
    "serial": "ABC12345"
  },
  {
    "id": 2,
    "name": "Server Room",
    "serial": "DEF67890"
  }
]
```

---

## ➕ `/api/admin/add-controller`
**Метод:** `POST`  
**Авторизация:** `Bearer <token>`  

**Описание:**  
Добавляет новый контроллер в базу.

**Вход (JSON):**
```json
{
  "name": "Warehouse Door",
  "serial": "WH123456"
}
```

**Ответ:**  
`200 Controller added`

**Ошибки:**
- `400 Missing fields`
- `401 Unauthorized`

---

## ❌ `/api/admin/delete-controller`
**Метод:** `POST`  
**Авторизация:** `Bearer <token>`  

**Описание:**  
Удаляет контроллер по ID.

**Вход (JSON):**
```json
{
  "id": 3
}
```

**Ответ:**  
`200 Controller deleted`

**Ошибки:**
- `400 Invalid controller ID`
- `401 Unauthorized`

---

## 🔑 `/api/admin/grant-access`
**Метод:** `POST`  
**Авторизация:** `Bearer <token>`  

**Описание:**  
Выдает доступ пользователю к конкретному контроллеру.

**Вход (JSON):**
```json
{
  "user_id": 2,
  "controller_id": 5
}
```

**Ответ:**  
`200 Access granted`

**Ошибки:**
- `400 Invalid fields`
- `401 Unauthorized`

---

## 🚫 `/api/admin/revoke-access`
**Метод:** `POST`  
**Авторизация:** `Bearer <token>`  

**Описание:**  
Удаляет доступ пользователя к конкретному контроллеру.

**Вход (JSON):**
```json
{
  "user_id": 2,
  "controller_id": 5
}
```

**Ответ:**  
`200 Access revoked`

**Ошибки:**
- `400 Invalid fields`
- `401 Unauthorized`

---

## 🔓 `/api/admin/grant-access-all`
**Метод:** `POST`  
**Авторизация:** `Bearer <token>`  

**Описание:**  
Выдает пользователю доступ ко всем контроллерам.

**Вход (JSON):**
```json
{
  "user_id": 2
}
```

**Ответ:**  
`200 Access granted to all`

**Ошибки:**
- `400 Invalid user ID`
- `401 Unauthorized`

---

## 🔒 `/api/admin/revoke-access-all`
**Метод:** `POST`  
**Авторизация:** `Bearer <token>`  

**Описание:**  
Удаляет доступ пользователя ко всем контроллерам.

**Вход (JSON):**
```json
{
  "user_id": 2
}
```

**Ответ:**  
`200 Access revoked from all`

**Ошибки:**
- `400 Invalid user ID`
- `401 Unauthorized`