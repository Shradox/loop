# LOOP Messenger

Реальный мессенджер с регистрацией, WebSocket и SQLite.

## Стек
- **Backend**: Node.js + Express + WebSocket (ws)
- **База данных**: SQLite (better-sqlite3) — один файл, не нужен отдельный сервис
- **Аутентификация**: JWT + bcrypt
- **Frontend**: Vanilla JS PWA, один HTML файл

## Деплой на Render.com

### Шаг 1 — GitHub
```bash
git init
git add .
git commit -m "initial"
git remote add origin https://github.com/ТВО_ИМЯ/loop-messenger.git
git push -u origin main
```

### Шаг 2 — Render
1. Идёшь на https://render.com
2. **New → Web Service**
3. Подключаешь GitHub репозиторий `loop-messenger`
4. Render сам подхватит `render.yaml` — всё настроено автоматически:
   - Build: `npm install`
   - Start: `npm start`
   - Disk: `/var/data` (1GB, для SQLite базы)
   - JWT_SECRET генерируется автоматически
5. Нажимаешь **Deploy**

Через ~2 минуты получаешь ссылку вида `https://loop-messenger.onrender.com`

### Шаг 3 — Готово!
Кидаешь ссылку другу, он регистрируется, ищет тебя по логину — и всё работает.

## Локальный запуск
```bash
npm install
npm start
# открыть http://localhost:3000
```

## Что работает
- ✅ Регистрация / вход (логин + пароль)
- ✅ Поиск пользователей по логину
- ✅ Создание диалогов
- ✅ Реалтайм сообщения через WebSocket
- ✅ Индикатор печатания
- ✅ История сообщений (SQLite)
- ✅ JWT авторизация (токен живёт 30 дней)
- ✅ Адаптивный UI под мобилку

## Структура
```
loop-messenger/
├── src/
│   └── server.js       # Весь бэкенд (Express + WS + SQLite)
├── public/
│   └── index.html      # Весь фронтенд (SPA)
├── render.yaml         # Конфиг для Render.com
└── package.json
```
