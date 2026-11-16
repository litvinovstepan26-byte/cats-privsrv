"""
app.py - private C.A.T.S. server (WebSocket transport, Render-friendly).

The game talks TCP; the on-device bridge wraps every frame into a WebSocket
binary message, so this server only sees frames.

Responses are replayed from real ZeptoLab traffic captured on a live game
(work/cats_native.bin + msgCache.bin) and stored in repo/captured/.
Only uuid / name / coins / gems are substituted.

Endpoints:
    GET  /           health + counters
    WS   /ws         game channel
    GET  /api/frames last frames

Local run:
    pip install -r requirements.txt
    PORT=8082 python app.py
"""

import json
import os
import struct
import time
import uuid

from aiohttp import web, WSMsgType

HERE = os.path.dirname(os.path.abspath(__file__))
CAPTURED = os.path.join(HERE, 'captured')
SCHEMA_CANDIDATES = [
    os.path.join(HERE, 'proto_schema.json'),
    os.path.join(HERE, '..', 'work', 'proto_schema.json'),
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


def parse_fields(buf):
    """Return [(num, wire, raw)]; raw is int for wire0, bytes otherwise."""
    out = []
    i = 0
    while i < len(buf):
        tag, i = read_varint(buf, i)
        num, wt = tag >> 3, tag & 7
        if num == 0:
            raise ValueError('field 0')
        if wt == 0:
            v, i = read_varint(buf, i)
            out.append((num, 0, v))
        elif wt == 1:
            out.append((num, 1, bytes(buf[i:i + 8])))
            i += 8
        elif wt == 2:
            ln, i = read_varint(buf, i)
            if i + ln > len(buf):
                raise ValueError('overflow')
            out.append((num, 2, bytes(buf[i:i + ln])))
            i += ln
        elif wt == 5:
            out.append((num, 5, bytes(buf[i:i + 4])))
            i += 4
        else:
            raise ValueError('wire %d' % wt)
    return out


def ser_field(num, wt, raw):
    if wt == 0:
        return field(num, 0, raw)
    if wt == 1:
        return enc_varint((num << 3) | 1) + raw
    if wt == 2:
        return field(num, 2, raw)
    return enc_varint((num << 3) | 5) + raw


def ser_fields(items):
    return b''.join(ser_field(n, w, r) for n, w, r in items)


def set_first(msg, num, value, wire=None):
    out = []
    done = False
    for n, w, r in parse_fields(msg):
        if n == num and not done:
            out.append((n, wire if wire is not None else w, value))
            done = True
        else:
            out.append((n, w, r))
    if not done and num:
        out.append((num, wire if wire is not None else 2, value))
    return ser_fields(out)


def load_schema():
    for p in SCHEMA_CANDIDATES:
        try:
            return json.load(open(p, encoding='utf-8'))
        except Exception:
            continue
    return {}


SCHEMA = load_schema()
REQ = {}
PROFILE_FIELDS = {}
if SCHEMA:
    for cls, ent in SCHEMA.items():
        short = cls.split('::')[-1]
        if short == 'ClientMessage_Request':
            REQ = {m['number']: name for name, m in ent.get('fields', {}).items()}
        if short == 'Profile':
            PROFILE_FIELDS = {name: m['number'] for name, m in ent.get('fields', {}).items()}


def describe_request(payload):
    hits = []
    i = 0
    try:
        while i < len(payload):
            tag, i = read_varint(payload, i)
            num, wt = tag >> 3, tag & 7
            name = REQ.get(num, 'field_%d' % num)
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


def request_numbers(frame):
    """Request field numbers from ClientMessage field 4 (repeated)."""
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
                    j = 0
                    while j < len(chunk):
                        t2, j = read_varint(chunk, j)
                        n2, w2 = t2 >> 3, t2 & 7
                        out.append(n2)
                        if w2 == 0:
                            _, j = read_varint(chunk, j)
                        elif w2 == 2:
                            l2, j = read_varint(chunk, j)
                            j += l2
                        elif w2 == 5:
                            j += 4
                        elif w2 == 1:
                            j += 8
                        else:
                            break
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
    out = {'requests': [], 'nonce': 0, 'hash': 0, 'uuid': None, 'set_name': None}
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
                elif num == 37:  # set_name { name = 1 }
                    try:
                        for n2, w2, r2 in parse_fields(chunk):
                            if n2 == 1 and w2 == 2:
                                out['set_name'] = r2.decode('utf-8', 'replace')
                    except Exception:
                        pass
            elif wt == 5:
                i += 4
            elif wt == 1:
                i += 8
            else:
                break
    except Exception:
        pass
    return out


# ---------- captured templates ----------

def load_captured(name):
    for base in (CAPTURED, os.path.join(HERE, '..', 'work', 'captured')):
        try:
            return open(os.path.join(base, name), 'rb').read()
        except Exception:
            continue
    return None


T_CONFIG = load_captured('config.bin') or b''
T_PROFILE = load_captured('my_profile.bin') or b''

def _config_live(cfg):
    try:
        for n, w, r in parse_fields(cfg):
            if n == 93 and w == 2:
                return r
    except Exception:
        pass
    return b''


T_LIVE_CONFIG = _config_live(T_CONFIG)
T_PROFILE_WITH_VEHICLE = load_captured('profile_lite_with_vehicle.bin') or b''
T_PARCELS = load_captured('parcels.bin') or b''
T_INTRO = load_captured('intro_fight_opponents.bin') or b''
T_BIGFIGHT = load_captured('big_fight_data.bin') or b''
T_LEADERBOARD = load_captured('leaderboard.bin') or b''
T_LBPOS = load_captured('leaderboard_position.bin') or b''
T_TUTDIALOGS = load_captured('tutorial_dialogs.bin') or b''
T_OPPONENT = load_captured('opponent.bin') or b''
T_NEWS = load_captured('news_result.bin')
T_POPUPLP = load_captured('popup_live_paks.bin')
T_MISSIONS = load_captured('missions.bin')
T_BOX = load_captured('box_display_result.bin') or b''
T_VAI = load_captured('vehicles_and_inventory.bin') or b''
T_BET = load_captured('bet_fights.bin') or b''
T_GLOBAL_LB = load_captured('global_leaderboard.bin') or b''
T_BOX = load_captured('box_display_result.bin') or b''
T_VAI = load_captured('vehicles_and_inventory.bin') or b''
T_BET = load_captured('bet_fights.bin') or b''
T_GLB = load_captured('global_leaderboard.bin') or b''
T_GROOVY = load_captured('groovy_thrust_inventory.bin')

try:
    CONFIG_META = json.load(open(os.path.join(CAPTURED, 'config_meta.json')))
except Exception:
    CONFIG_META = {'hash': 0, 'live_config_hash': ''}

LIVE_CONFIG_HASH = CONFIG_META.get('live_config_hash', '')


def lite_and_vehicles(profile):
    lite_num = PROFILE_FIELDS.get('profile_lite', 1)
    vai_num = PROFILE_FIELDS.get('vehicles_and_inventory')
    lite = b''
    vai = b''
    for n, w, r in parse_fields(profile):
        if n == lite_num and w == 2:
            lite = r
        if vai_num is not None and n == vai_num and w == 2:
            vai = r
    return lite, vai


def patch_profile(profile, uuid_str):
    """Real profile with substituted uuid / name / tag / device / currency."""
    raw_uuid = bytes.fromhex(uuid_str) if len(uuid_str) == 32 else uuid_str.encode()[:16]
    raw_uuid = raw_uuid[:16].ljust(16, b'\0')
    name = ('player' + uuid_str[:4]).encode()
    tag = int(uuid_str[:6], 16) % 100000
    device = uuid_str[:16].encode()
    nfs_num = PROFILE_FIELDS.get('name_for_support')

    out = []
    for n, w, r in parse_fields(profile):
        if w != 2:
            out.append((n, w, r))
            continue
        if n == 1:  # ProfileLite
            lite = set_first(r, 1, raw_uuid)
            lite = set_first(lite, 2, name)
            lite = set_first(lite, 9, tag, 0)
            if 20 in [x[0] for x in parse_fields(lite)]:
                lite = set_first(lite, 20, device)
            r = lite
        elif n == 10:  # Resources
            res = set_first(r, 1, 900000000, 0)
            res = set_first(res, 2, 9000000, 0)
            r = res
        elif nfs_num is not None and n == nfs_num:
            r = name + b'#' + str(tag).encode()
        out.append((n, w, r))
    return ser_fields(out)


# ---------- response builder ----------

def build_response_for(nonce, req_nums, uuid_str, req_hash=0, player_name=None):
    """Replay responses in the exact order the requests were sent.

    Client correlates responses positionally, and protobuf lite validates
    required fields: LoginResponse requires profile(1),
    time_until_league_round_end(2) and has_medal_logs(3). RegisterResult
    requires all three of its fields.
    """
    profile = patch_profile(T_PROFILE, uuid_str) if T_PROFILE else b''
    if profile and player_name:
        profile = set_first(profile, 1, set_first(lite_and_vehicles(profile)[0], 2, player_name.encode()))
    lite, vai = lite_and_vehicles(profile) if profile else (b'', b'')
    resps = []

    def add(req):
        parts = []
        if req == 164:  # check_tos
            parts.append(field(67, 2, field(1, 2, b'')))
        elif req == 4:  # register_
            rr = (field(1, 2, uuid_str.encode()) +
                  field(2, 2, (uuid_str + uuid_str).encode()) +
                  field(3, 0, 0))
            parts.append(field(3, 2, rr))
        elif req == 13:  # login: all three required fields
            lr = field(1, 2, profile) if profile else b''
            lr += field(2, 0, int(time.time() * 1000) + 3600 * 1000)
            lr += field(3, 0, 0)
            parts.append(field(10, 2, lr))
        elif req == 14:  # get_config
            parts.append(field(9, 2, T_CONFIG))
            if CONFIG_META.get('hash'):
                parts.append(field(1001, 0, int(CONFIG_META['hash'])))
            if LIVE_CONFIG_HASH:
                parts.append(field(1002, 2, LIVE_CONFIG_HASH.encode()))
        elif req == 7 and profile:  # get_my_profile
            parts.append(field(6, 2, profile))
            if LIVE_CONFIG_HASH:
                parts.append(field(1002, 2, LIVE_CONFIG_HASH.encode()))
        elif req == 48:
            if T_VAI:
                parts.append(field(25, 2, T_VAI))
            elif vai:
                parts.append(field(25, 2, vai))
        elif req == 98 and lite:
            parts.append(field(38, 2, lite))
        elif req == 37:  # set_name -> updated ProfileLite
            if player_name and lite:
                parts.append(field(38, 2, set_first(lite, 2, player_name.encode())))
            elif lite:
                parts.append(field(38, 2, lite))
        elif req == 181 and T_LIVE_CONFIG:  # get_live_config
            body = field(74, 2, T_LIVE_CONFIG)
            if LIVE_CONFIG_HASH:
                body += field(1002, 2, LIVE_CONFIG_HASH.encode())
            parts.append(body)
        elif req == 163 and T_BOX:  # get_box_display
            parts.append(field(66, 2, T_BOX))
        elif req in (32, 49, 159, 160):  # setters: complete_tutorial_step /
            # update_client_preferences / start_tutorial_step / set_locale
            parts.append(field(26, 2, b''))  # Response.no_change
        elif req == 44 and T_BET:  # get_bet_fights -> Response.bet_fights(23)
            parts.append(field(23, 2, T_BET))
        elif req == 35 and T_GLB:  # get_global_leaderboard -> Response(18)
            parts.append(field(18, 2, T_GLB))
        elif req == 214:  # get_groovy_thrust_boosters — отвечаем всегда, пусть и пустым
            parts.append(field(96, 2, T_GROOVY or b''))
        elif req == 101 and T_PROFILE_WITH_VEHICLE:
            parts.append(field(40, 2, T_PROFILE_WITH_VEHICLE))
        elif req == 28 and T_PARCELS:
            parts.append(field(16, 2, T_PARCELS))
        elif req == 79 and T_INTRO:
            parts.append(field(29, 2, T_INTRO))
        elif req == 40 and T_BIGFIGHT:
            parts.append(field(21, 2, T_BIGFIGHT))
        elif req == 10 and T_LEADERBOARD:
            parts.append(field(7, 2, T_LEADERBOARD))
        elif req == 19 and T_LBPOS:
            parts.append(field(11, 2, T_LBPOS))
        elif req == 150 and T_TUTDIALOGS:
            parts.append(field(62, 2, T_TUTDIALOGS))
        elif req == 31 and T_OPPONENT:
            parts.append(field(4, 2, T_OPPONENT))
        elif req == 132 and T_NEWS is not None:
            parts.append(field(55, 2, T_NEWS))
        elif req == 218 and T_POPUPLP is not None:
            parts.append(field(97, 2, T_POPUPLP))
        elif req == 236 and T_MISSIONS is not None:
            parts.append(field(105, 2, T_MISSIONS))
        elif req in (33, 266):  # heartbeat / ping
            parts.append(field(5, 2, b''))
        if parts:
            resps.append(b''.join(parts))

    for req in req_nums:
        if req == 1:  # ClientMessage_Request.continue_on_error
            continue
        add(req)

    return b''.join(field(1, 2, r) for r in resps) + field(2, 0, int(time.time() * 1000))


def build_response(nonce):
    resp = field(1000, 0, nonce)
    return field(1, 2, resp) + field(2, 0, int(time.time() * 1000))


def split_frame(buf):
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
    if kind == 'varint':
        return enc_varint(len(payload)) + payload
    if kind == 'be32':
        return struct.pack('>I', len(payload)) + payload
    if kind == 'le32':
        return struct.pack('<I', len(payload)) + payload
    return payload


# ---------- http ----------

async def health(request):
    # Игра стучится в балансер как GET /?version=99&uuid=...&host=
    # Отдаём тот же JSON, что и мост, но по обычному HTTP (без TLS и без моста).
    if 'version' in request.query:
        return web.json_response({
            'status': 'OK',
            'instance': {
                'host': os.environ.get('GAME_HOST', '127.0.0.1'),
                'port': int(os.environ.get('GAME_PORT', '7711')),
            },
        })
    return web.json_response({
        'ok': True, 'schema': len(SCHEMA), 'stats': STATS,
        'templates': {
            'config': len(T_CONFIG), 'profile': len(T_PROFILE),
            'vehicles_and_inventory': len(T_PROFILE_WITH_VEHICLE),
            'live_config_hash': bool(LIVE_CONFIG_HASH),
        },
    })


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
    ws = web.WebSocketResponse(max_msg_size=8 * 1024 * 1024)
    await ws.prepare(request)
    STATS['connections'] += 1
    peer = request.remote
    print('[+] ws connect %s' % peer, flush=True)

    buf = bytearray()
    player_uuid = uuid.uuid4().hex
    player_name = None

    async for msg in ws:
        if msg.type != WSMsgType.BINARY:
            if msg.type == WSMsgType.ERROR:
                break
            continue
        if bytes(msg.data[:4]) in HTTP_METHODS:
            log_http(msg.data)
            try:
                line = msg.data.split(b'\r\n', 1)[0].decode('utf-8', 'replace')
                LAST.append({'n': STATS['frames'], 'kind': 'http', 'line': line,
                             'hex': msg.data[:160].hex()})
            except Exception:
                pass
            bal = {
                "status": "OK",
                "instance": {
                    "host": os.environ.get('GAME_HOST', '127.0.0.1'),
                    "port": int(os.environ.get('GAME_PORT', '7711')),
                },
            }
            body = json.dumps(bal).encode('utf-8')
            await ws.send_bytes(build_http_response(body))
            continue

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
            print('[pb %d] %s nonce=%d' % (STATS['frames'],
                  ', '.join(info['requests']) or '(empty)', info['nonce']), flush=True)
            nums = request_numbers(frame)
            if info['uuid']:
                player_uuid = info['uuid']
            if info.get('set_name'):
                player_name = info['set_name']
            resp = build_response_for(info['nonce'], nums, player_uuid, info['hash'], player_name)
            print('[resp %d] requests=%s uuid=%s out=%d' % (
                STATS['frames'], nums, player_uuid, len(resp)), flush=True)
            await ws.send_bytes(frame_out(resp, 'varint'))

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
