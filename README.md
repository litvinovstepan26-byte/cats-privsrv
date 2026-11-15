# CATS private server — Render (WebSocket)

Приватный сервер для C.A.T.S. 3.35.12. Render не даёт сырой TCP, поэтому игровые кадры
protobuf едут внутри WebSocket: одно бинарное WS-сообщение = один кадр протокола.

## Что внутри

| Файл | Что делает |
|---|---|
| `app.py` | aiohttp-сервис: `GET /` health, `WS /ws` игровой канал |
| `proto_schema.json` | восстановленная схема BBProtocol (747 сообщений) — по ней читаются имена запросов |
| `requirements.txt` | зависимости |
| `render.yaml` | blueprint для Render |

Сервер уже умеет:

- принимать кадры игры и определять разметку (varint / 4 байта BE / LE);
- разбирать `ClientMessage` → `requests`, `nonce`, `uuid`;
- печатать в лог, что просит клиент (`login`, `get_config`, …);
- отвечать `ServerMessage` с эхом nonce в той же разметке.

## Деплой на Render

1. Залей этот репозиторий на GitHub (публичный или приватный — Render умеет оба).
2. Render → **New** → **Web Service** → подключить репозиторий.
3. Настройки:
   - **Runtime**: Python 3
   - **Build Command**: `pip install -r requirements.txt`
   - **Start Command**: `python app.py`
   - **Instance Type**: Free
4. Deploy. Адрес будет `https://<имя>.onrender.com`, игровой канал — `wss://<имя>.onrender.com/ws`.

Либо проще: Render → **New** → **Blueprint** → выбрать репозиторий, он подхватит `render.yaml`.

## Проверка

```bash
curl https://<имя>.onrender.com/
# {"ok": true, "schema": 747, "stats": {"connections": 0, "frames": 0}}
```

В логах Render при подключении клиента появится:

```
[+] ws connect 1.2.3.4
[frame 1] login<0>, get_config<0>  nonce=17 uuid=...
```

## Локальный запуск

```bash
pip install -r requirements.txt
python app.py          # http://127.0.0.1:8080/ws
```

## Что дальше

Сейчас сервер отвечает заглушкой (nonce + пустой ответ). По логам видно, какие запросы
присылает клиент — по одному добавляются обработчики:

`login` → `get_config` → `get_my_profile` → `get_vehicles_and_inventory` →
`find_bot_match` → `start_match` → `save_match_result` → `store_purchase` → `gacha`.

## Замечания по free-плану Render

- инстанс засыпает после ~15 минут без трафика, холодный старт 30–60 с;
- `/` можно дёргать пингом (cron-job.org или UptimeRobot, бесплатно), чтобы сервис не спал.
