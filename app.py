"""
app.py — приватный сервер C.A.T.S. для Render (WebSocket, без карты).

Render не даёт сырой TCP, поэтому кадры игры едут внутри WebSocket-сообщений
(бинарные фреймы, 1 сообщение = 1 кадр протокола).

Эндпоинты:
    GET  /           —健康 check + счётчик
    WS   /ws         — игровой канал

Локальный запуск:
    pip install -r requirements.txt
    python app.py                    # http://127.0.0.1:8080/ws

Деплой на Render:
    New → Web Service → Python → build: pip install -r requirements.txt
                                  start: python app.py
"""

import json
import os
import struct
import sys
import uuid

from aiohttp import web, WSMsgType

HERE = os.path.dirname(os.path.abspath(__file__))
SCHEMA_CANDIDATES = [
    os.path.join(HERE, 'proto_schema.json'),
    os.path.join(HERE, '..', '..', 'work', 'proto_schema.json'),
]

from collections import deque

STATS = {'connections': 0, 'frames': 0}
LAST = deque(maxlen=60)


# ---------- protobuf ----------

def read_varint(buf, i):
    shift = val = 0
    while True:
        if i >= len(buf):
            raise ValueError('eof')
        b = buf[i]
        i += 1
        val |= (b & 0x7f) << shift
        if not b & 0x80:
            return val, i
        shift += 7
        if shift > 63:
            raise ValueError('varint too long')


def enc_varint(v):
    out = bytearray()
    v &= (1 << 64) - 1
    while True:
        b = v & 0x7f
        v >>= 7
        out.append(b | 0x80 if v else b)
        if not v:
            return bytes(out)


def field(num, wire, payload):
    if wire == 0:
        return enc_varint((num << 3) | 0) + enc_varint(payload)
    return enc_varint((num << 3) | 2) + enc_varint(len(payload)) + payload


def load_schema():
    for p in SCHEMA_CANDIDATES:
        try:
            raw = json.load(open(p, encoding='utf-8'))
        except Exception:
            continue
        out = {}
        for cls, ent in raw.items():
            nums = {}
            for fname, meta in ent.get('fields', {}).items():
                n = meta.get('number')
                if n:
                    nums[n] = (fname, meta)
            if nums:
                out[cls.split('::')[-1]] = nums
        return out
    return {}


SCHEMA = load_schema()
REQ = SCHEMA.get('ClientMessage_Request', {})


def describe_request(payload):
    hits = []
    try:
        i = 0
        while i < len(payload):
            tag, i = read_varint(payload, i)
            num, wt = tag >> 3, tag & 7
            name = REQ.get(num, ('field_%d' % num,))[0]
            if wt == 0:
                v, i = read_varint(payload, i)
                hits.append('%s=%d' % (name, v))
            elif wt == 2:
                ln, i = read_varint(payload, i)
                hits.append('%s<%d>' % (name, ln))
                i += ln
            elif wt == 5:
                i += 4
            elif wt == 1:
                i += 8
            else:
                break
    except Exception:
        pass
    return hits


def request_field_numbers(payload):
    """Возвращает номера полей из ClientMessage_Request (т.е. какие запросы прислали)."""
    nums = []
    i = 0
    try:
        while i < len(payload):
            tag, i = read_varint(payload, i)
            num, wt = tag >> 3, tag & 7
            if wt == 0:
                v, i = read_varint(payload, i)
            elif wt == 2:
                ln, i = read_varint(payload, i)
                i += ln
            elif wt == 5:
                i += 4
            elif wt == 1:
                i += 8
            else:
                break
    except Exception:
        pass
    return nums


def request_numbers(frame):
    """Номера запросов из ClientMessage (поле 4 = repeated ClientMessage_Request)."""
    out = []
    i = 0
    try:
        while i < len(frame):
            tag, i = read_varint(frame, i)
            num, wt = tag >> 3, tag & 7
            if wt == 0:
                _, i = read_varint(frame, i)
            elif wt == 2:
                ln, i = read_varint(frame, i)
                chunk = frame[i:i + ln]
                i += ln
                if num == 4:
                    out.extend(request_field_numbers(chunk))
            elif wt == 5:
                i += 4
            elif wt == 1:
                i += 8
            else:
                break
    except Exception:
        pass
    return out


def parse_client_message(payload):
    """ClientMessage: uuid=1, protocol_version=2, requests=4, nonce=1000, hash=1001."""
    out = {'requests': [], 'nonce': 0, 'hash': 0, 'uuid': None}
    i = 0
    try:
        while i < len(payload):
            tag, i = read_varint(payload, i)
            num, wt = tag >> 3, tag & 7
            if wt == 0:
                v, i = read_varint(payload, i)
                if num == 1000:
                    out['nonce'] = v
                elif num == 1001:
                    out['hash'] = v
            elif wt == 2:
                ln, i = read_varint(payload, i)
                chunk = payload[i:i + ln]
                i += ln
                if num == 4:
                    out['requests'].extend(describe_request(chunk))
                elif num == 1:
                    out['uuid'] = chunk.decode('utf-8', 'replace')
            elif wt == 5:
                i += 4
            elif wt == 1:
                i += 8
            else:
                break
    except Exception:
        pass
    return out


def build_response_for(nonce, req_nums, uuid_str, req_hash=0):
    parts = [field(1000, 0, nonce), field(1001, 0, req_hash)]
    if 164 in req_nums:  # check_tos -> ServerMessage_TOS{ ok{} }
        tos = field(1, 2, b'')          # ok: ServerMessage_TOS_Ok {}
        parts.append(field(67, 2, tos))  # Response.tos = 67
    if 4 in req_nums:  # register_
        rr = field(1, 2, uuid_str.encode()) + field(3, 0, 0)
        parts.append(field(3, 2, rr))
    resp = b''.join(parts)
    return field(1, 2, resp) + field(2, 0, 0)


def build_response(nonce):
    # ServerMessage { responses: [ Response { nonce } ], server_time }
    resp = field(1000, 0, nonce)
    return field(1, 2, resp) + field(2, 0, 0)


def split_frame(buf):
    """Определяет разметку кадра и возвращает (payload, kind)."""
    try:
        ln, i = read_varint(buf, 0)
        if 0 < ln <= len(buf) - i:
            return buf[i:i + ln], 'varint'
    except Exception:
        pass
    if len(buf) >= 4:
        ln, = struct.unpack('>I', buf[:4])
        if 0 < ln <= len(buf) - 4:
            return buf[4:4 + ln], 'be32'
        ln, = struct.unpack('<I', buf[:4])
        if 0 < ln <= len(buf) - 4:
            return buf[4:4 + ln], 'le32'
    return buf, 'raw'


def frame_out(payload, kind):
    """Отвечаем той же разметкой, какой пришёл запрос."""
    if kind == 'varint':
        return enc_varint(len(payload)) + payload
    if kind == 'be32':
        return struct.pack('>I', len(payload)) + payload
    if kind == 'le32':
        return struct.pack('<I', len(payload)) + payload
    return payload


# ---------- http ----------

async def health(request):
    return web.json_response({'ok': True, 'schema': len(SCHEMA), 'stats': STATS})


async def frames_api(request):
    return web.json_response({'stats': STATS, 'frames': list(LAST)})


HTTP_METHODS = (b'GET ', b'POST', b'PUT ', b'HEAD', b'DELE')


def build_http_response(body: bytes = b'{}', status: str = '200 OK',
                        ctype: str = 'application/json') -> bytes:
    head = (
        'HTTP/1.1 ' + status + '\r\n'
        'Content-Type: ' + ctype + '\r\n'
        'Content-Length: ' + str(len(body)) + '\r\n'
        'Connection: close\r\n'
        '\r\n'
    ).encode('ascii')
    return head + body


def log_http(payload: bytes):
    try:
        text = payload.decode('utf-8', 'replace')
        head = text.split('\r\n\r\n')[0]
        lines = head.split('\r\n')
        print('[http] ' + lines[0], flush=True)
        for line in lines[1:8]:
            if line.strip():
                print('       ' + line, flush=True)
        tail = text.split('\r\n\r\n', 1)
        if len(tail) == 2 and tail[1]:
            print('       body: ' + tail[1][:300], flush=True)
    except Exception:
        pass


async def ws_handler(request):
    ws = web.WebSocketResponse(max_msg_size=4 * 1024 * 1024)
    await ws.prepare(request)
    STATS['connections'] += 1
    peer = request.remote
    print('[+] ws connect %s' % peer, flush=True)

    buf = bytearray()

    async for msg in ws:
        if msg.type != WSMsgType.BINARY:
            if msg.type == WSMsgType.ERROR:
                break
            continue
        # HTTP-запрос от клиента (балансер) — идёт отдельным соединением
        if bytes(msg.data[:4]) in HTTP_METHODS:
            pass
        else:
            buf.extend(msg.data)
            while True:
                try:
                    n, i = read_varint(bytes(buf), 0)
                except Exception:
                    break
                if n <= 0 or len(buf) < i + n:
                    break
                frame = bytes(buf[i:i + n])
                del buf[:i + n]
                STATS['frames'] += 1
                info = parse_client_message(frame)
                try:
                    LAST.append({
                        'n': STATS['frames'], 'kind': 'pb', 'size': len(frame),
                        'requests': info['requests'], 'nonce': info['nonce'],
                        'uuid': info['uuid'], 'hex': frame[:96].hex(),
                    })
                except Exception:
                    pass
                print('[pb %d] %s nonce=%d' % (STATS['frames'], ', '.join(info['requests']) or '(empty)', info['nonce']), flush=True)
                nums = request_numbers(frame)
                u = uuid.uuid4().hex
                resp = build_response_for(info['nonce'], nums, u, info.get('hash', 0))
                print('[resp %d] requests=%s uuid=%s' % (STATS['frames'], nums, u), flush=True)
                await ws.send_bytes(frame_out(resp, 'varint'))
            continue

        STATS['frames'] += 1

        # HTTP-запрос от клиента: отвечаем HTTP, без префикса длины
        if msg.data[:4] in HTTP_METHODS:
            log_http(msg.data)
            try:
                line = msg.data.split(b'\r\n', 1)[0].decode('utf-8', 'replace')
                LAST.append({'n': STATS['frames'], 'kind': 'http', 'line': line,
                             'hex': msg.data[:160].hex()})
            except Exception:
                pass
            # точный формат балансера ZeptoLab (снят с живого ответа):
            # {"status":"OK","instance":{"host":"...","port":7010}}
            bal = {
                "status": "OK",
                "instance": {
                    "host": os.environ.get('GAME_HOST', '127.0.0.1'),
                    "port": int(os.environ.get('GAME_PORT', '7711')),
                },
            }
            body = json.dumps(bal).encode('utf-8')
            ctype = 'application/json'
            await ws.send_bytes(build_http_response(body, ctype=ctype))
            continue

        payload, kind = split_frame(msg.data)
        info = parse_client_message(payload)
        print('[frame %d] %s  nonce=%d uuid=%s kind=%s'
              % (STATS['frames'], ', '.join(info['requests']) or '(empty)',
                 info['nonce'], info['uuid'], kind), flush=True)
        try:
            LAST.append({
                'n': STATS['frames'],
                'kind': kind,
                'size': len(payload),
                'requests': info['requests'],
                'nonce': info['nonce'],
                'uuid': info['uuid'],
                'hex': payload[:64].hex(),
            })
        except Exception:
            pass
        await ws.send_bytes(frame_out(build_response(info['nonce']), kind))

    print('[-] ws close %s' % peer, flush=True)
    return ws


def main():
    app = web.Application()
    app.router.add_get('/', health)
    app.router.add_get('/ws', ws_handler)
    app.router.add_get('/api/frames', frames_api)
    port = int(os.environ.get('PORT', '8080'))
    web.run_app(app, host='0.0.0.0', port=port, print=lambda *a: print(*a, flush=True))


if __name__ == '__main__':
    main()
