"""انواع تونل‌های پروکسی"""
import asyncio
import ssl
import logging
from helpers import is_ip_literal

try:
    import certifi
except ImportError:
    certifi = None

log = logging.getLogger("Proxy")

async def open_tcp_connection(target: str, port: int, timeout: float = 10.0, use_doh=False):
    """اتصال TCP ساده با fallback به DNS سیستم"""
    import socket
    loop = asyncio.get_running_loop()
    try:
        infos = await asyncio.wait_for(
            loop.getaddrinfo(target, port, family=socket.AF_UNSPEC, type=socket.SOCK_STREAM),
            timeout=timeout)
        for family, _, _, _, sockaddr in infos:
            try:
                return await asyncio.wait_for(asyncio.open_connection(sockaddr[0], port, family=family), timeout=timeout)
            except Exception: continue
    except Exception as e:
        raise OSError(f"connect failed: {target}:{port}: {e}") from e
    raise OSError(f"connect failed: {target}:{port}")

async def direct_tunnel(host: str, port: int, reader, writer, tcp_timeout: float = 10.0, connect_ip: str | None = None):
    target_ip = connect_ip or host
    try:
        r_remote, w_remote = await open_tcp_connection(target_ip, port, timeout=tcp_timeout)
    except Exception as e:
        log.error("Direct tunnel failed (%s via %s): %s", host, target_ip, e)
        return False

    async def pipe(src, dst, label):
        try:
            while True:
                data = await src.read(65536)
                if not data: break
                dst.write(data); await dst.drain()
        except (ConnectionError, asyncio.CancelledError): pass
        except Exception as e: log.debug("Pipe %s ended: %s", label, e)

    await asyncio.gather(pipe(reader, w_remote, f"cli→{host}"), pipe(r_remote, writer, f"{host}→cli"))
    return True

async def sni_rewrite_tunnel(host: str, port: int, reader, writer, mitm, fronter, connect_ip: str | None = None):
    target_ip = connect_ip or fronter.connect_host
    sni_out = fronter.sni_host
    ssl_ctx_server = mitm.get_server_context(host)
    loop = asyncio.get_running_loop()
    transport = writer.transport; protocol = transport.get_protocol()
    try:
        new_transport = await loop.start_tls(transport, protocol, ssl_ctx_server, server_side=True)
    except Exception as e:
        log.debug("SNI-rewrite TLS accept failed (%s): %s", host, e); return
    writer._transport = new_transport
    ssl_ctx_client = ssl.create_default_context()
    if certifi is not None:
        try: ssl_ctx_client.load_verify_locations(cafile=certifi.where())
        except Exception: pass
    if not fronter.verify_ssl: ssl_ctx_client.check_hostname = False; ssl_ctx_client.verify_mode = ssl.CERT_NONE
    try:
        r_out, w_out = await asyncio.wait_for(
            asyncio.open_connection(target_ip, port, ssl=ssl_ctx_client, server_hostname=sni_out),
            timeout=15)
    except Exception as e:
        log.error("SNI-rewrite outbound failed (%s via %s): %s", host, target_ip, e); return

    async def pipe(src, dst, label):
        try:
            while True:
                data = await src.read(65536)
                if not data: break
                dst.write(data); await dst.drain()
        except (ConnectionError, asyncio.CancelledError): pass
        except Exception as exc: log.debug("Pipe %s ended: %s", label, exc)

    await asyncio.gather(pipe(reader, w_out, f"cli→{host}"), pipe(r_out, writer, f"{host}→cli"))

async def mitm_connect(host: str, port: int, reader, writer, mitm, fronter, relay_http_stream):
    ssl_ctx = mitm.get_server_context(host)
    loop = asyncio.get_running_loop()
    transport = writer.transport; protocol = transport.get_protocol()
    try:
        new_transport = await loop.start_tls(transport, protocol, ssl_ctx, server_side=True)
    except Exception as e:
        if is_ip_literal(host) and port == 443:
            log.info("Non-TLS on %s:%d (MTProto) – forwarding", host, port)
            await direct_tunnel(host, port, reader, writer)
        elif port != 443:
            log.debug("TLS skipped for %s:%d (non-HTTPS)", host, port)
            await direct_tunnel(host, port, reader, writer)
        else:
            log.debug("TLS handshake failed for %s: %s", host, e)
        return
    writer._transport = new_transport
    await relay_http_stream(host, port, reader, writer)