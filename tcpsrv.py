import asyncio
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

import app  # noqa: E402

TCP_PORT = int(os.environ.get('TCP_PORT', '8083'))


async def handle(reader, writer):
    peer = writer.get_extra_info('peername')
    print('[+] tcp connect %s' % (peer,), flush=True)
    buf = bytearray()
    player_uuid = app.uuid.uuid4().hex
    player_name = None
    try:
        while True:
            chunk = await reader.read(65536)
            if not chunk:
                break
            buf.extend(chunk)
            while True:
                try:
                    n, i = app.read_varint(bytes(buf), 0)
                except Exception:
                    break
                if n <= 0 or len(buf) < i + n:
                    break
                frame = bytes(buf[i:i + n])
                del buf[:i + n]
                app.STATS['frames'] += 1
                info = app.parse_client_message(frame)
                app.LAST.append({
                    'n': app.STATS['frames'], 'kind': 'pb', 'size': len(frame),
                    'requests': info['requests'], 'nonce': info['nonce'],
                    'uuid': info['uuid'], 'hex': frame[:96].hex(),
                })
                print('[pb %d] %s nonce=%d' % (
                    app.STATS['frames'],
                    ', '.join(info['requests']) or '(empty)', info['nonce']), flush=True)
                nums = app.request_numbers(frame)
                if info['uuid']:
                    player_uuid = info['uuid']
                if info.get('set_name'):
                    player_name = info['set_name']
                resp = app.build_response_for(info['nonce'], nums, player_uuid,
                                              info['hash'], player_name)
                print('[resp %d] requests=%s uuid=%s out=%d' % (
                    app.STATS['frames'], nums, player_uuid, len(resp)), flush=True)
                writer.write(app.frame_out(resp, 'varint'))
                await writer.drain()
    except Exception as e:
        print('[-] tcp error %s: %r' % (peer, e), flush=True)
    finally:
        print('[-] tcp close %s' % (peer,), flush=True)
        try:
            writer.close()
        except Exception:
            pass


async def main():
    server = await asyncio.start_server(handle, '0.0.0.0', TCP_PORT)
    print('raw game protocol on 0.0.0.0:%d' % TCP_PORT, flush=True)
    async with server:
        await server.serve_forever()


if __name__ == '__main__':
    asyncio.run(main())
