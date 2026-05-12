import socket, ssl, time
try:
    import socks
except ImportError:
    exit("pip install PySocks")

# تنظیمات خود را اینجا تغییر دهید
PROXY_HOST = "127.0.0.1"
PROXY_PORT = 10808
GOOGLE_IP = "216.239.38.120"
WORKER_HOST = "tgiranfiltertime.arshia-kingforcallofduty.workers.dev"

sock = socks.socksocket()
sock.set_proxy(socks.SOCKS5, PROXY_HOST, PROXY_PORT)
sock.settimeout(10)
sock.connect((GOOGLE_IP, 443))

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
ssock = ctx.wrap_socket(sock, server_hostname="www.google.com")

req = f"GET / HTTP/1.1\r\nHost: {WORKER_HOST}\r\nConnection: close\r\n\r\n"
ssock.sendall(req.encode())

resp = b""
while True:
    data = ssock.recv(4096)
    if not data:
        break
    resp += data

print(resp.decode(errors="replace"))
ssock.close()