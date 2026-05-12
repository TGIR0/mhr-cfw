import asyncio, socket, struct, sys, time

async def test_echo():
    """Send a UDP packet through the tunnel and wait for reply."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("127.0.0.1", 0))
    sock.settimeout(5)

    # Build packet: 2B port + hostname + \x00 + payload
    target = ("1.1.1.1", 53)  # Cloudflare DNS as example
    data = struct.pack("!H", target[1]) + target[0].encode() + b'\x00' + b"test"
    sock.sendto(data, ("127.0.0.1", 5353))

    try:
        reply, addr = sock.recvfrom(1024)
        print(f"✅ Received {len(reply)} bytes from {addr}")
        return True
    except socket.timeout:
        print("❌ No response (timeout)")
        return False
    finally:
        sock.close()

if __name__ == "__main__":
    asyncio.run(test_echo())