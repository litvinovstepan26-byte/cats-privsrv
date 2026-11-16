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

import asyncio
import io
import json
import os
import sqlite3
import struct
import time
import uuid

from aiohttp import web, WSMsgType

HERE = os.path.dirname(os.path.abspath(__file__))
CAPTURED = os.path.join(HERE, 'captured')


def _load_env_file(path):
    """Локальный .env.local / .env (на Render переменные приходят из дашборда)."""
    try:
        with io.open(path, encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#') or '=' not in line:
                    continue
                k, v = line.split('=', 1)
                os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))
    except OSError:
        pass


_load_env_file(os.path.join(HERE, '.env.local'))
_load_env_file(os.path.join(HERE, '.env'))
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
RESP = {}
if SCHEMA:
    for cls, ent in SCHEMA.items():
        short = cls.split('::')[-1]
        if short == 'ClientMessage_Request':
            REQ = {m['number']: name for name, m in ent.get('fields', {}).items()}
        if short == 'ServerMessage_Response':
            RESP = {name: m['number'] for name, m in ent.get('fields', {}).items()}
        if short == 'Profile':
            PROFILE_FIELDS = {name: m['number'] for name, m in ent.get('fields', {}).items()}


def _norm(s):
    return (s.replace('get_', '')
             .replace('_response', '')
             .replace('_result', '')
             .replace('_request', ''))


RESP_NORM = {}
for _name, _num in RESP.items():
    RESP_NORM.setdefault(_norm(_name), _num)


def guess_response_field(req_num):
    """По имени запроса найти поле ответа (когда явного шаблона нет)."""
    name = REQ.get(req_num)
    if not name:
        return None
    key = _norm(name)
    if key in RESP_NORM:
        return RESP_NORM[key]
    for rn, num in RESP_NORM.items():
        if key and (key in rn or rn in key):
            return num
    return None


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


def request_payloads(frame):
    """[(номер запроса, payload)] из ClientMessage field 4."""
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
                        tag2, j = read_varint(chunk, j)
                        rn, rw = tag2 >> 3, tag2 & 7
                        if rw == 0:
                            _, j = read_varint(chunk, j)
                        elif rw == 2:
                            ln2, j = read_varint(chunk, j)
                            out.append((rn, chunk[j:j + ln2]))
                            j += ln2
                        elif rw == 5:
                            j += 4
                        elif rw == 1:
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
T_TUTDIALOGS_FIGHT = load_captured('tutorial_dialogs_fight.bin') or b''
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


def _replace_field(buf, num, newval, wire=2):
    out = []
    done = False
    for n, w, v in parse_fields(buf):
        if n == num and not done:
            out.append((n, wire, newval))
            done = True
        else:
            out.append((n, w, v))
    if not done:
        out.append((num, wire, newval))
    return ser_fields(out)


def vai_with_part(vai, template_id=4, drop_stash=True):
    """Поставить деталь в шасси (и убрать её из «стойки»).

    Структура (по дампу):
      normal_garage(1) -> garage(1) -> vehicle(2) -> container(1) -> chassis(2)
      шасси: поле 4 (repeated) = {6: template_id, 7: позиция, 8: ids, 9, 12}
      стойка: normal_garage(1) -> поле 3
    """
    try:
        garage = [v for n, w, v in parse_fields(vai) if n == 1 and isinstance(v, bytes)][0]
        g1 = [v for n, w, v in parse_fields(garage) if n == 1 and isinstance(v, bytes)][0]
        g2 = [v for n, w, v in parse_fields(g1) if n == 2 and isinstance(v, bytes)][0]
        cont = [v for n, w, v in parse_fields(g2) if n == 1 and isinstance(v, bytes)][0]
        chassis = [v for n, w, v in parse_fields(cont) if n == 2 and isinstance(v, bytes)][0]
        entries = [v for n, w, v in parse_fields(chassis) if n == 4 and isinstance(v, bytes)]
        if not entries:
            return vai
        new_fields = []
        for n, w, v in parse_fields(entries[-1]):
            new_fields.append((n, 0, template_id) if n == 6 else (n, w, v))
        chassis2 = chassis + field(4, 2, ser_fields(new_fields))
        cont2 = _replace_field(cont, 2, chassis2)
        g2b = _replace_field(g2, 1, cont2)
        g1b = _replace_field(g1, 2, g2b)

        garage_out = []
        for n, w, v in parse_fields(garage):
            if n == 1:
                garage_out.append((n, w, g1b))
            elif n == 3 and drop_stash:
                continue
            else:
                garage_out.append((n, w, v))
        return _replace_field(vai, 1, ser_fields(garage_out))
    except Exception as e:
        print('[-] vai_with_part: %r' % (e,), flush=True)
        return vai


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


def patch_profile(profile, uuid_str, player_name=None, coins=None, gems=None,
                  stage=None, tutorial=None, bigfight=None):
    """Real profile with substituted uuid / name / tag / device / currency."""
    try:
        raw_uuid = bytes.fromhex(uuid_str) if len(uuid_str) == 32 else uuid_str.encode()[:16]
    except ValueError:
        raw_uuid = uuid_str.encode()[:16].ljust(16, b'\0')
    raw_uuid = raw_uuid[:16].ljust(16, b'\0')
    name = (player_name or ('player' + uuid_str[:4])).encode()
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
            res = set_first(r, 1, coins if coins is not None else 900000000, 0)
            res = set_first(res, 2, gems if gems is not None else 9000000, 0)
            r = res
        elif nfs_num is not None and n == nfs_num:
            r = name + b'#' + str(tag).encode()
        out.append((n, w, r))
    res = ser_fields(out)
    if stage is not None:
        res = set_first(res, 12, int(stage), 0)
    if tutorial is not None:
        res = set_first(res, 14, int(tutorial), 0)
    if bigfight is not None:
        res = set_first(res, 23, int(bigfight), 0)
    return res


# ---------- response builder ----------

def build_response_for(nonce, req_nums, uuid_str, req_hash=0, player_name=None,
                       player=None):
    """Replay responses in the exact order the requests were sent.

    Client correlates responses positionally, and protobuf lite validates
    required fields: LoginResponse requires profile(1),
    time_until_league_round_end(2) and has_medal_logs(3). RegisterResult
    requires all three of its fields.
    """
    coins = player.get('coins') if player else None
    gems = player.get('gems') if player else None
    stage = player.get('stage') if player else None
    tutorial = player.get('tutorial') if player else None
    # tutorial >= 200 считаем "туториал пройден": не подсовываем диалоги дяди Тони
    tutorials_done = tutorial is not None and tutorial >= 200
    bigfight = player.get('bigfight') if player else None
    profile = patch_profile(T_PROFILE, uuid_str, player_name, coins, gems,
                            stage, tutorial, bigfight) if T_PROFILE else b''
    if profile and player_name and player is None:
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
        elif req in (15, 17):  # install/uninstall_vehicle_part
            mode = INSTALL_MODE
            if mode == 'vai':
                parts.append(field(25, 2, T_VAI or vai or b''))
            elif mode == 'profile' and profile:
                parts.append(field(6, 2, profile))
            elif mode == 'both' and profile:
                body = field(6, 2, profile)
                if T_VAI or vai:
                    body += field(25, 2, T_VAI or vai)
                parts.append(body)
            else:
                parts.append(field(26, 2, b''))
        elif req == 48:
            base = T_VAI or vai
            if base:
                parts.append(field(25, 2, base))
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
            # в шаблоне записан uuid настоящего игрока; подменяем на наш, иначе
            # клиент считает бои чужими и не показывает кнопку боя
            bet = T_BET
            try:
                raw = bytes.fromhex(uuid_str) if len(uuid_str) == 32 else uuid_str.encode()[:16]
                bet = bet.replace(bytes.fromhex('f578a14c9ef147caa0d74fcc26f03cba'), raw)
            except Exception:
                pass
            parts.append(field(23, 2, bet))
        elif req == 35 and T_GLB:  # get_global_leaderboard -> Response(18)
            parts.append(field(18, 2, T_GLB))
        elif req == 214:  # get_groovy_thrust_boosters — отвечаем всегда, пусть и пустым
            parts.append(field(96, 2, T_GROOVY or b''))
        elif req == 101 and T_PROFILE_WITH_VEHICLE:
            parts.append(field(40, 2, T_PROFILE_WITH_VEHICLE))
        elif req == 28 and T_PARCELS:
            parts.append(field(16, 2, T_PARCELS))
        elif req == 79:
            parts.append(field(29, 2, T_INTRO or b''))
        elif req == 40 and T_BIGFIGHT:
            parts.append(field(21, 2, T_BIGFIGHT))
        elif req == 10 and T_LEADERBOARD:
            parts.append(field(7, 2, T_LEADERBOARD))
        elif req == 19 and T_LBPOS:
            parts.append(field(11, 2, T_LBPOS))
        elif req == 150:  # get_tutorial_dialogs
            # до установки — вводные диалоги, после (шаг 26) — реплика перед боем
            if (tutorial or 0) >= 26 and T_TUTDIALOGS_FIGHT:
                parts.append(field(62, 2, T_TUTDIALOGS_FIGHT))
            else:
                parts.append(field(62, 2, T_TUTDIALOGS or b''))
        elif req == 154:  # get_tutorial_championship -> список соперников туториала
            parts.append(field(29, 2, T_INTRO or b''))
        elif req == 155:  # get_tutorial_championship_opponent
            parts.append(field(4, 2, T_OPPONENT or b''))
        elif req in (5, 6, 31) and T_OPPONENT:  # find_league/bot/championship
            parts.append(field(4, 2, T_OPPONENT))
        elif req == 156:  # start_tutorial_big_fight -> сразу даём соперника
            parts.append(field(4, 2, T_OPPONENT or b''))
        elif req in (8, 40) and T_BIGFIGHT:  # start_match / big fight
            parts.append(field(21, 2, T_BIGFIGHT))
        elif req in (9, 41, 157):  # save match / big fight / tutorial fight result
            parts.append(field(22, 2, b''))
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
        before = len(resps)
        add(req)
        if len(resps) == before:
            # Явного шаблона нет. Пустой ответ нужного типа ломает парсер, если
            # в сообщении есть required-поля (клиент показывает сбой 1000).
            # Поэтому отвечаем универсальным Response.no_change(26).
            resps.append(field(26, 2, b''))
            print('[resp] unhandled req %d (%s) -> no_change' %
                  (req, REQ.get(req, '?')), flush=True)

    return b''.join(field(1, 2, r) for r in resps) + field(2, 0, int(time.time() * 1000))


def build_response(nonce):
    resp = field(1000, 0, nonce)
    return field(1, 2, resp) + field(2, 0, int(time.time() * 1000))


def frame_response(resp):
    """Список payload'ов для отправки: по одному Response на ServerMessage."""
    if os.environ.get('SPLIT_RESPONSES', '0') != '1':
        return [resp]
    try:
        fields = parse_fields(resp)
    except Exception:
        return [resp]
    st = [v for n, w, v in fields if n == 2 and not isinstance(v, bytes)]
    now = st[0] if st else int(time.time() * 1000)
    resps = [v for n, w, v in fields if n == 1 and isinstance(v, bytes)]
    if len(resps) <= 1:
        return [resp]
    return [field(1, 2, r) + field(2, 0, now) for r in resps]


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


async def grant_api(request):
    """Начитка валюты: /api/grant?uuid=...&coins=99999999&gems=99999 (или &name=...)."""
    uuid_str = request.query.get('uuid')
    name = request.query.get('name')
    coins = request.query.get('coins')
    gems = request.query.get('gems')
    conn = db()
    try:
        if uuid_str:
            row = conn.execute('SELECT uuid FROM players WHERE uuid=?', (uuid_str,)).fetchone()
        elif name:
            row = conn.execute('SELECT uuid FROM players WHERE name=? ORDER BY last_seen DESC',
                               (name,)).fetchone()
        else:
            return web.json_response({'ok': False, 'error': 'need uuid or name'}, status=400)
        if not row:
            return web.json_response({'ok': False, 'error': 'player not found'}, status=404)
        uuid_str = row[0]
        if coins is not None:
            conn.execute('UPDATE players SET coins=? WHERE uuid=?', (int(coins), uuid_str))
        if gems is not None:
            conn.execute('UPDATE players SET gems=? WHERE uuid=?', (int(gems), uuid_str))
        for key, col in (('stage', 'stage'), ('tutorial', 'tutorial'),
                         ('bigfight', 'bigfight')):
            val = request.query.get(key)
            if val is not None:
                conn.execute('UPDATE players SET %s=? WHERE uuid=?' % col,
                             (int(val), uuid_str))
        conn.commit()
        p = conn.execute('SELECT uuid,name,token,coins,gems,stage,tutorial,bigfight'
                         ' FROM players WHERE uuid=?', (uuid_str,)).fetchone()
    finally:
        conn.close()
    return web.json_response({'ok': True, 'player': {
        'uuid': p[0], 'name': p[1], 'coins': p[3], 'gems': p[4],
        'stage': p[5], 'tutorial': p[6], 'bigfight': p[7]}})


async def players_api(request):
    conn = db()
    try:
        rows = conn.execute('SELECT uuid,name,coins,gems,last_seen,stage,tutorial,bigfight'
                            ' FROM players ORDER BY last_seen DESC LIMIT 50').fetchall()
    finally:
        conn.close()
    return web.json_response({'ok': True, 'players': [
        {'uuid': r[0], 'name': r[1], 'coins': r[2], 'gems': r[3], 'last_seen': r[4],
         'stage': r[5], 'tutorial': r[6], 'bigfight': r[7]}
        for r in rows]})


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


# ---------- persistence ----------

DB_PATH = os.environ.get('DB_PATH', os.path.join(HERE, 'cats.db'))


def _clean_dsn(value):
    v = (value or '').strip()
    while len(v) >= 2 and v[0] == v[-1] and v[0] in ('"', "'"):
        v = v[1:-1].strip()
    return v


DATABASE_URL = _clean_dsn(os.environ.get('DATABASE_URL', ''))


class PgConn:
    """Обёртка, чтобы код с sqlite-плейсхолдерами работал и на Postgres."""

    def __init__(self, dsn):
        import psycopg2
        self._c = psycopg2.connect(dsn)

    def execute(self, sql, args=()):
        cur = self._c.cursor()
        cur.execute(sql.replace('?', '%s'), args)
        return cur

    def commit(self):
        self._c.commit()

    def rollback(self):
        try:
            self._c.rollback()
        except Exception:
            pass

    def close(self):
        self._c.close()


def db():
    if DATABASE_URL:
        conn = PgConn(DATABASE_URL)
        conn.execute("""CREATE TABLE IF NOT EXISTS players (
            uuid TEXT PRIMARY KEY, name TEXT, token TEXT,
            coins INTEGER, gems INTEGER, created BIGINT, last_seen BIGINT,
            stage INTEGER DEFAULT 0, tutorial INTEGER DEFAULT 25,
            bigfight INTEGER DEFAULT 0, device TEXT)""")
        # В Postgres упавший ALTER обрывает транзакцию, поэтому коммитим каждый шаг
        conn.commit()
        for name, ddl in (('stage', 'INTEGER DEFAULT 0'),
                          ('tutorial', 'INTEGER DEFAULT 25'),
                          ('bigfight', 'INTEGER DEFAULT 0'),
                          ('device', 'TEXT')):
            try:
                conn.execute('ALTER TABLE players ADD COLUMN %s %s' % (name, ddl))
                conn.commit()
            except Exception:
                conn.rollback()
        return conn
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""CREATE TABLE IF NOT EXISTS players (
        uuid TEXT PRIMARY KEY, name TEXT, token TEXT,
        coins INTEGER, gems INTEGER, created INTEGER, last_seen INTEGER,
        stage INTEGER DEFAULT 0, tutorial INTEGER DEFAULT 25,
        bigfight INTEGER DEFAULT 0, device TEXT)""")
    cols = {r[1] for r in conn.execute('PRAGMA table_info(players)')}
    for name, ddl in (('stage', 'INTEGER DEFAULT 0'),
                      ('tutorial', 'INTEGER DEFAULT 25'),
                      ('bigfight', 'INTEGER DEFAULT 0'),
                      ('device', 'TEXT')):
        if name not in cols:
            conn.execute('ALTER TABLE players ADD COLUMN %s %s' % (name, ddl))
    return conn


DEFAULT_COINS = int(os.environ.get('START_COINS', '1000'))
DEFAULT_GEMS = int(os.environ.get('START_GEMS', '0'))
DEFAULT_STAGE = int(os.environ.get('START_STAGE', '0'))
INSTALL_MODE = os.environ.get('INSTALL_MODE', 'ack')
DEFAULT_TUTORIAL = int(os.environ.get('START_TUTORIAL', '25'))


def player_get(uuid_str):
    conn = db()
    try:
        row = conn.execute('SELECT uuid,name,token,coins,gems,stage,tutorial,bigfight'
                           ' FROM players WHERE uuid=?', (uuid_str,)).fetchone()
    finally:
        conn.close()
    if not row:
        return None
    return {'uuid': row[0], 'name': row[1], 'token': row[2],
            'coins': row[3], 'gems': row[4],
            'stage': row[5], 'tutorial': row[6], 'bigfight': row[7]}


def player_upsert(uuid_str, name=None):
    now = int(time.time() * 1000)
    conn = db()
    try:
        row = conn.execute('SELECT uuid,name,token,coins,gems,stage,tutorial,bigfight'
                           ' FROM players WHERE uuid=?', (uuid_str,)).fetchone()
        if row is None:
            nm = name or ('player' + uuid_str[:4])
            token = uuid_str + uuid_str
            # Переустановка APK меняет device id, поэтому новый игрок наследует
            # прогресс самого «богатого» — иначе туториал и валюта откатываются.
            inherit = None
            try:
                inherit = conn.execute(
                    'SELECT coins,gems,stage,tutorial,bigfight FROM players'
                    ' ORDER BY coins DESC, last_seen DESC LIMIT 1').fetchone()
            except Exception:
                pass
            if inherit and (inherit[0] or 0) > DEFAULT_COINS:
                coins, gems, stage_id, tut, bf = inherit
            else:
                coins, gems, stage_id, tut, bf = (DEFAULT_COINS, DEFAULT_GEMS,
                                                  DEFAULT_STAGE, DEFAULT_TUTORIAL, 0)
            conn.execute('INSERT INTO players(uuid,name,token,coins,gems,created,last_seen,'
                         'stage,tutorial,bigfight) VALUES(?,?,?,?,?,?,?,?,?,?)',
                         (uuid_str, nm, token, coins, gems, now, now,
                          stage_id, tut, bf))
            row = (uuid_str, nm, token, DEFAULT_COINS, DEFAULT_GEMS,
                   DEFAULT_STAGE, DEFAULT_TUTORIAL, 0)
        else:
            if name and name != row[1]:
                conn.execute('UPDATE players SET name=? WHERE uuid=?', (name, uuid_str))
                row = (row[0], name, row[2], row[3], row[4], row[5], row[6], row[7])
            conn.execute('UPDATE players SET last_seen=? WHERE uuid=?', (now, uuid_str))
        conn.commit()
    finally:
        conn.close()
    return {'uuid': row[0], 'name': row[1], 'token': row[2],
            'coins': row[3], 'gems': row[4],
            'stage': row[5], 'tutorial': row[6], 'bigfight': row[7]}


def player_by_device(device_hex):
    if not device_hex:
        return None
    conn = db()
    try:
        row = conn.execute('SELECT uuid,name,token,coins,gems,stage,tutorial,bigfight'
                           ' FROM players WHERE device=? ORDER BY last_seen DESC LIMIT 1',
                           (device_hex,)).fetchone()
    finally:
        conn.close()
    if not row:
        return None
    return {'uuid': row[0], 'name': row[1], 'token': row[2], 'coins': row[3],
            'gems': row[4], 'stage': row[5], 'tutorial': row[6], 'bigfight': row[7]}


def player_set_device(uuid_str, device_hex):
    if not device_hex:
        return
    conn = db()
    try:
        conn.execute('UPDATE players SET device=? WHERE uuid=?', (device_hex, uuid_str))
        conn.commit()
    except Exception:
        conn.rollback()
    finally:
        conn.close()


def player_set_tutorial(uuid_str, value):
    conn = db()
    try:
        conn.execute('UPDATE players SET tutorial=? WHERE uuid=?', (int(value), uuid_str))
        conn.commit()
    finally:
        conn.close()


# ---------- общая обработка одного protobuf-кадра ----------

def process_frame(frame, state):
    STATS['frames'] += 1
    info = parse_client_message(frame)
    LAST.append({
        'n': STATS['frames'], 'kind': 'pb', 'size': len(frame),
        'requests': info['requests'], 'nonce': info['nonce'],
        'uuid': info['uuid'], 'hex': frame[:96].hex(),
    })
    print('[pb %d] %s nonce=%d' % (STATS['frames'],
          ', '.join(info['requests']) or '(empty)', info['nonce']), flush=True)
    nums = request_numbers(frame)
    device = None
    for _num, _payload in request_payloads(frame):
        if _num != 4:
            continue
        _i = 0
        try:
            while _i < len(_payload):
                _tag, _i = read_varint(_payload, _i)
                _n, _w = _tag >> 3, _tag & 7
                if _w == 0:
                    _, _i = read_varint(_payload, _i)
                elif _w == 2:
                    _ln, _i = read_varint(_payload, _i)
                    _chunk = _payload[_i:_i + _ln]
                    _i += _ln
                    if _n == 3:
                        device = _chunk.hex()
        except Exception:
            pass
    if not info['uuid'] and not nums:
        # Пустой кадр (пинг/мониторинг) — не создаём нового игрока в базе.
        return field(2, 0, int(time.time() * 1000))
    for _num, _payload in request_payloads(frame):
        if _num in (15, 17, 32, 159, 154, 156, 157, 158):
            print('[tut] req %d payload=%s' % (_num, _payload.hex()), flush=True)
    if info['uuid']:
        _cand = info['uuid'].strip()
        # uuid приходит как 32 hex-символа; в «служебных» кадрах поле 1 может
        # быть мусором — иначе int(uuid,16) роняет весь обработчик
        if len(_cand) == 32 and all(c in '0123456789abcdefABCDEF' for c in _cand):
            state['uuid'] = _cand
    try:
        player = player_upsert(state['uuid'], info.get('set_name'))
    except Exception as e:
        print('[-] db error: %r' % (e,), flush=True)
        player = {'uuid': state['uuid'], 'name': info.get('set_name') or 'player',
                  'token': state['uuid'] * 2, 'coins': DEFAULT_COINS,
                  'gems': DEFAULT_GEMS, 'stage': 0, 'tutorial': DEFAULT_TUTORIAL,
                  'bigfight': 0}
    state['name'] = player['name']
    if device:
        player_set_device(state['uuid'], device)
    # complete_tutorial_step{ step=1 } -> tutorial_progress = step
    # (в профиле реального игрока tutorial_progress=25, а клиент присылает 0x1a=26)
    for _num, _payload in request_payloads(frame):
        if _num != 32:
            continue
        _i = 0
        _step = None
        try:
            while _i < len(_payload):
                _tag, _i = read_varint(_payload, _i)
                _n, _w = _tag >> 3, _tag & 7
                if _w == 0:
                    _v, _i = read_varint(_payload, _i)
                    if _n == 1:
                        _step = _v
        except Exception:
            pass
        if _step is not None:
            # только вперёд: клиент при переподключении повторяет прошлые шаги,
            # и если писать step как есть, прогресс откатывается назад
            cur = int(player.get('tutorial') or 0)
            new_tut = max(cur, min(2000, int(_step)))
            if new_tut != cur:
                player_set_tutorial(state['uuid'], new_tut)
            player['tutorial'] = new_tut
            print('[tut] progress %d -> %d' % (cur, new_tut), flush=True)
    resp = build_response_for(info['nonce'], nums, state['uuid'],
                              info['hash'], state['name'], player)
    print('[resp %d] requests=%s uuid=%s coins=%d out=%d' % (
        STATS['frames'], nums, state['uuid'], player['coins'], len(resp)), flush=True)
    out = [resp]
    if 15 in nums and T_OPPONENT:
        # настоящий сервер после установки детали сам присылает соперника —
        # с этого начинается туториальный бой
        push = field(1, 2, field(4, 2, T_OPPONENT)) + field(2, 0, int(time.time() * 1000))
        out.append(push)
        print('[push] opponent after install', flush=True)
    return out


# ---------- сырой TCP (LAN-режим, без моста) ----------

async def tcp_client(reader, writer):
    peer = writer.get_extra_info('peername')
    print('[+] tcp connect %s' % (peer,), flush=True)
    STATS['connections'] += 1
    buf = bytearray()
    state = {'uuid': uuid.uuid4().hex, 'name': None}
    try:
        while True:
            chunk = await reader.read(65536)
            if not chunk:
                break
            buf.extend(chunk)
            while True:
                try:
                    n, i = read_varint(bytes(buf), 0)
                except Exception:
                    break
                if n <= 0 or len(buf) < i + n:
                    break
                frame = bytes(buf[i:i + n])
                del buf[:i + n]
                for _one in process_frame(frame, state):
                    for _p in frame_response(_one):
                        writer.write(frame_out(_p, 'varint'))
                await writer.drain()
    except Exception as e:
        print('[-] tcp error %s: %r' % (peer, e), flush=True)
    finally:
        print('[-] tcp close %s' % (peer,), flush=True)
        try:
            writer.close()
        except Exception:
            pass


async def start_tcp():
    port = int(os.environ.get('TCP_PORT', '8083'))
    srv = await asyncio.start_server(tcp_client, '0.0.0.0', port)
    print('raw game protocol on 0.0.0.0:%d' % port, flush=True)
    async with srv:
        await srv.serve_forever()


async def _on_startup(app_):
    if os.environ.get('TCP_ENABLE', '1') == '1':
        asyncio.create_task(start_tcp())


async def ws_handler(request):
    ws = web.WebSocketResponse(max_msg_size=8 * 1024 * 1024)
    await ws.prepare(request)
    STATS['connections'] += 1
    peer = request.remote
    print('[+] ws connect %s' % peer, flush=True)

    buf = bytearray()
    state = {'uuid': uuid.uuid4().hex, 'name': None}

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
            for _one in process_frame(frame, state):
                for _p in frame_response(_one):
                    await ws.send_bytes(frame_out(_p, 'varint'))

    print('[-] ws close %s' % peer, flush=True)
    return ws


def main():
    app = web.Application()
    app.router.add_get('/', health)
    app.router.add_get('/ws', ws_handler)
    app.router.add_get('/api/frames', frames_api)
    app.router.add_get('/api/grant', grant_api)
    app.router.add_get('/api/players', players_api)
    app.on_startup.append(_on_startup)
    port = int(os.environ.get('PORT', '8080'))
    web.run_app(app, host='0.0.0.0', port=port, print=lambda *a: print(*a, flush=True))


if __name__ == '__main__':
    main()
