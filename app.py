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

from aiohttp import web, WSMsgType

HERE = os.path.dirname(os.path.abspath(__file__))
SCHEMA_CANDIDATES = [
    os.path.join(HERE, 'proto_schema.json'),
    os.path.join(HERE, '..', '..', 'work', 'proto_schema.json'),
]

STATS = {'connections': 0, 'frames': 0}


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


async def ws_handler(request):
    ws = web.WebSocketResponse(max_msg_size=4 * 1024 * 1024)
    await ws.prepare(request)
    STATS['connections'] += 1
    peer = request.remote
    print('[+] ws connect %s' % peer, flush=True)

    async for msg in ws:
        if msg.type != WSMsgType.BINARY:
            if msg.type == WSMsgType.ERROR:
                break
            continue
        STATS['frames'] += 1
        payload, kind = split_frame(msg.data)
        info = parse_client_message(payload)
        print('[frame %d] %s  nonce=%d uuid=%s kind=%s'
              % (STATS['frames'], ', '.join(info['requests']) or '(empty)',
                 info['nonce'], info['uuid'], kind), flush=True)
        await ws.send_bytes(frame_out(build_response(info['nonce']), kind))

    print('[-] ws close %s' % peer, flush=True)
    return ws


def main():
    app = web.Application()
    app.router.add_get('/', health)
    app.router.add_get('/ws', ws_handler)
    port = int(os.environ.get('PORT', '8080'))
    web.run_app(app, host='0.0.0.0', port=port, print=lambda *a: print(*a, flush=True))


if __name__ == '__main__':
    main()
