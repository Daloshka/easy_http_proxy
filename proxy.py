import asyncio
import base64

users = {
    "user1": "pass1"
}

def is_authorized(headers):
    for line in headers:
        if line.lower().startswith("proxy-authorization:"):
            try:
                value = line.split(" ")[2]
                decoded = base64.b64decode(value).decode()
                username, password = decoded.split(":", 1)
                return users.get(username) == password
            except:
                return False
    return False

async def handle_client(reader, writer):
    try:
        data = await reader.readuntil(b"\r\n\r\n")
    except asyncio.IncompleteReadError:
        writer.close()
        return

    header_lines = data.decode(errors="ignore").split("\r\n")
    first_line = header_lines[0]
    headers = header_lines[1:]

    if not is_authorized(headers):
        writer.write(b"HTTP/1.1 407 Proxy Authentication Required\r\n")
        writer.write(b"Proxy-Authenticate: Basic realm=\"Proxy\"\r\n\r\n")
        await writer.drain()
        writer.close()
        return

    if first_line.startswith("CONNECT"):
        # HTTPS
        _, target, _ = first_line.split()
        host, port = target.split(":")
        port = int(port)

        try:
            remote_reader, remote_writer = await asyncio.open_connection(host, port)
            writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            await writer.drain()

            async def tunnel(src_reader, dst_writer):
                try:
                    while True:
                        chunk = await src_reader.read(4096)
                        if not chunk:
                            break
                        dst_writer.write(chunk)
                        await dst_writer.drain()
                except:
                    pass
                finally:
                    dst_writer.close()

            asyncio.create_task(tunnel(reader, remote_writer))
            asyncio.create_task(tunnel(remote_reader, writer))

        except:
            writer.write(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
            await writer.drain()
            writer.close()

    else:
        # HTTP (простой)
        try:
            method, url, _ = first_line.split()
            for h in headers:
                if h.lower().startswith("host:"):
                    host = h.split(":", 1)[1].strip()
                    break
            else:
                writer.close()
                return

            remote_reader, remote_writer = await asyncio.open_connection(host, 80)
            remote_writer.write(data)
            await remote_writer.drain()

            while True:
                resp = await remote_reader.read(4096)
                if not resp:
                    break
                writer.write(resp)
                await writer.drain()

            remote_writer.close()
        except:
            writer.close()

async def main():
    server = await asyncio.start_server(handle_client, "0.0.0.0", 9432)
    async with server:
        await server.serve_forever()

if __name__ == "__main__":
    asyncio.run(main())
