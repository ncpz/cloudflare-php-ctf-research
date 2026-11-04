# Cloudflare PHP CTF — php2shell WAF-bypass research

**Target:** [Cloudflare PHP Capture The Flag challenge](https://php-rce.cloudflare.app/) (run through the [Cloudflare Bug Bounty on HackerOne](https://hackerone.com/cloudflare))
**Vulnerabilities:** CVE-2026-109618 / CVE-2026-109619 ("php2shell", disclosed 2026-10-21 by [Wiz](https://www.wiz.io/blog/php2shell-php-rce), fixed in PHP 8.5.12)
**Outcome:** Complete 3-stage RCE chain built and verified **3× against a byte-comparable lab replica** of the CTF sandbox. Live flag capture blocked by Cloudflare's php2shell managed WAF rules, which were iteratively tightened using other researchers' CTF reports (2026-10-28 / 10-30 / 11-03 WAF releases). This repository documents the chain, the original findings, the WAF analysis, and the mathematical reason the arm method is now fused with the detection.

> ⚠️ This is a **negative-result research writeup**: the exploit is complete and reproducible locally, but the live gate (Cloudflare's WAF) closes the delivery path. PHP ≥ 8.5.12 is not vulnerable. Do not run anything here against systems you do not own or are not explicitly authorized to test.

---

## TL;DR

- **The chain**: (1) a ~1 MB multipart POST drives the request past `memory_limit=128M` so the OOM lands *inside* `php_session_initialize` → `php_session_reset_id` → `php_url_encode`, after `create_sid`, leaving stale session globals in the prefork worker (the CVE-2026-109619 state leak); (2) a second request grooms the worker's heap with 15 large form values so the session cookie emitter reads a forged `zend_string.len` (0x1C048 instead of 32) and emits a **241 KB `Set-Cookie`** whose body leaks heap and libphp image pointers — ASLR defeated in-band over HTTP; (3) a third request positions a failing allocation at a bracketed key and reuses a groomed fake object whose handlers form a ROP chain (`pop rdi/rsi/ret` → `zif_system`) → `system()` as `uid=33(www-data)`.
- **Local verification**: 3 independent end-to-end runs — leak 114,696 B decoded / 695 pointers / dtor-aligned libphp base vote **902 of 903** → RCE → proof file served 200 OK.
- **Live verdict**: the arm stage is flagged by the "PHP OOM" managed rules. Those rules were updated on 2026-10-28, 10-30 and 11-03 with CTF-report-informed detections. The arm's heap state is **byte-exact razor-sensitive** (details below), so no padding, reordering, or encoding survives — and the OOM mass is only reachable at one legal nesting depth, which is the flagged one. The lock is mathematical, not incidental.
- **What's original here**: the cookie-emission laws extracted from the PHP 8.5.11 source, the gdb walk-oracle for armed workers, the state-razor characterization, the forge mechanics (the forged length is the *fill size itself*, not injected content), and the game-theory of the live worker pool.

---

## Background

**php2shell** ([Wiz](https://www.wiz.io/blog/php2shell-php-rce), [Huntress](https://www.huntress.com/blog/php2shell-leaked-critical-php-vulnerabilities), CVSS 9.2) is a pair of memory-safety bugs in the PHP runtime that chain to full RCE in default configurations. [Cloudflare deployed emergency WAF rules](https://blog.cloudflare.com/php-vulnerabilities-waf-protection/) on 2026-10-21, then launched [the CTF](https://blog.cloudflare.com/php-ctf) on 2026-10-27: a stock PHP 8.5.11 + Apache `mod_php` container with an empty `index.php`, behind those same rules. Goal: `POST` something to `/php/*` that yields RCE and the contents of `/flag`; bounties ($3,000) require a **materially distinct** WAF bypass submitted privately to HackerOne.

A reference chain exists publicly as **Exploit-DB 52704**. Our decoded analysis of it is in [`docs/edb52704-analysis.md`](docs/edb52704-analysis.md); this repository's scripts build on that foundation (see [Attribution](#attribution)).

**Sandbox (and our replica) configuration:** PHP 8.5.11 official Docker build, `memory_limit=128M`, `post_max_size=8M`, `max_input_vars=1000`, `session.upload_progress` enabled, `session.use_strict_mode=Off`, Apache 2.4 prefork (`MaxRequestWorkers=160`), ASLR on. The replica is defined in [`lab-conf/`](lab-conf/) and matches the CTF build byte-for-byte (`libphp.so` md5 `39a5b69694ed9410ea5ef2a687213833`).

---

## The chain

### Stage 1 — A1: the state-producer arm

A single multipart POST (1,056,221 B, 973 parts) whose dominant content is **860 parts with names nesting 62 array levels deep** — `files[R%05d` + 90×`K` + `]` + `[a]`×62 — forces PHP to build ~53,320 nested `HashTable` levels (~128 MB of parse-tree memory) inside the `$_POST` auto-globals construction. The exact body is reproducible:

```bash
python scripts/exp_aa.py --host 127.0.0.1 --port 8080 --help   # builder is exp_aa.build_a1_body
python - <<'EOF'
import argparse
from pathlib import Path
import sys; sys.path.insert(0, "scripts")
import exp_aa as E
ns = argparse.Namespace(a1_parts=860, a1_fillers128=14, a1_keypad=90, a1_big=78,
                        a1_burners=19, a1_burner_len=4000, a1_progress_len=4072,
                        a1_filepad=0, a1_dummies=0, a1_churn=False,
                        a1_big_shrink="", a1_progress_position=None, nested_fields=900)
E.build_a1_body(Path("a1.bin"), ns)
EOF
# → a1.bin: 1,056,221 B, sha256 90378064dfd32cdc…, 973 parts
```

The OOM fires during the END-of-request session cleanup → `php_session_initialize` → `php_session_reset_id` → `php_url_encode` — **after** `create_sid()` and the `PS(id)` assignment, with `PS(send_cookie)=1`. The bailout leaves **stale session globals** in the worker: the half-open `PS(id)`, `send_cookie=1`, and a leaked `mod_data` file handle. In-band it renders as:

```
PHP Fatal error: Allowed memory size of 134217728 bytes exhausted (tried to allocate 4096 bytes)
```

The `tried to allocate N` value is the **site discriminator**: 4096/12288 = the session-initialization phase (the arm), 8192 = the parse phase (no state produced).

### Stage 2 — B1: the overlong Set-Cookie leak

A second POST on the **same keep-alive worker** carries 15 large form values in a fixed choreography (the "S12" body, 17,705,395 B):

| Fill | Size | Role |
|---|---|---|
| 12 × | 1,048,576 B | **the walk** — consecutive large-run grants that consume the free-run list down to the panic-target run left by the A1 |
| PHPSESSID + `PHP_SESSION_UPLOAD_PROGRESS` pair | ~160 B | placed after fill 2 (also clears the WAF scan window) |
| 1 × | 2,093,033 B | **the shroud** — a 511-page value that covers the sid's whole 2 MB chunk |
| 1 × | 1,048,576 B | positioning |
| 1 × | 1,978,345 B | **the forge carrier** — 483 pages |

At the END-cleanup `php_session_initialize`, `ps_close_files` releases A1-era strings; uncovered frees hit re-carved heap metadata and **panic** (`zend_mm_heap corrupted`, SIGABRT — the child dies, the state with it). The walk+shroud shield exactly those frees. The final 483-page fill's own multipart-value `zend_string` header then lands at the stale sid's address, and the cookie emitter — `php_url_encode` with the stale `PS(id)` and `send_cookie=1` — reads `len = 0x1C048` (114,696) instead of 32:

- **241,282-byte `Set-Cookie: PHPSESSID=…`**, URL-decoding to 114,696 B
- `exp_aa.summarize_cookie` extracts 8-byte little-endian pointers → **695 candidates**
- 2 MiB bucketing → dominant bucket = the sid's chunk; subtracting `zval_ptr_dtor` offset (0x7b47a0) and voting on 2 MiB alignment → **libphp base, 902/903 votes**

**Why the walk is 12 steps and not compressible:** each fill is a ~1 MB kept value; the allocator (best-fit, chunk-chain order) grants them head-first, and the panic-target run sits 12 grants deep — the A1-era chunk's position in the chain. Fills of other size classes (128/96/64 pages) walk different lists and always panic. The 12×1 MB + shroud + positioning + forge floor is **17.7 MB**, which is the crux of the live-delivery problem (below).

### Stage 3 — RCE

Third request to the same worker: ~402,500 `X:` header "tuner" lines plus nested-name amplifiers position the failing allocation at a bracketed key's 81,920 B alloc (`--nested-fields 900`). A forged structure (fake object + handlers + ROP: `pop rdi` / `pop rsi` / `ret` → `zif_system`, command at +0x80) registered and freed earlier is re-carved at the predicted address; the interrupted insertion's shutdown dispatch calls through it → **`system(command)`**, e.g. `cat /flag > /var/www/html/php/f.txt`, then `GET /php/f.txt`.

The sink offset is build-specific. On the official `php:8.5.11-apache` build the boot-stable value is **0xA5B9E8** (the author-build's 0x5C400 hangs the worker — measured twice). The heap→libphp delta is per-parent and re-derived every run from the leak's 2 MiB buckets; never transplant it.

**Local end-to-end (the verification run):**

```
[*] decoded_cookie=114696 candidates=695
[+] base vote 0x7c9f0aa00000 votes=902
[+] derived main_chunk=0x7c9f0b000000 (libphp+0x600000 this run)
[+] 128M amplified RCE: uid=33(www-data) gid=33(www-data) groups=33(www-data)
[+] composed leak-to-RCE chain succeeded
```

Reproduce with `python scripts/exp_live.py --host 127.0.0.1 --port 8080 --ka --b1-file <s12-body> --rce --rce-block-offset 0xA5B9E8` against the lab (see [Reproduction](#reproduction)).

---

## Original findings

These are documented nowhere else, to our knowledge; each was established by measurement on the replica.

1. **Cookie-emission laws** (from `ext/session/session.c` 8.5.11 + behavior): `PS(send_cookie)=1` only in the create path; `reset_id` emits on both paths guarded by `SG(headers_sent)`; the rfc1867 progress-START handler sets `PS(id)` from the form field and **suppresses** send_cookie; the FILE-part event assigns `PS(id)` at FILE_START. Consequences: a progress-part body without a file part = create-path cookie; file-less bodies re-create the sid; every failure branch logs.
2. **The walk-oracle**: attaching gdb during a mid-parse stall on the armed worker (KeepAliveTimeout=5 s makes any plain post-A1 pause close the socket — the stall keeps it busy) dumps the armed state: `PS(id)` alive at page 483 of chunk `0x…0b000000`, which is literally `cache[30]`, the bottom of the 31-entry chunk cache; `ps_files->path` corrupted. Scripts: [`scripts/gdb/g_walk2.gdb`](scripts/gdb/g_walk2.gdb), [`g_map.gdb`](scripts/gdb/g_map.gdb).
3. **The state-razor**: the armed state survives **only ±0-byte mutations** of the A1 body. Verified survivors: same-length content swaps (`K`→`a`, `[a]`→`[z]`, `NAME=` uppercase, sid repositioning). Verified killers: −3.4 KB renames, byte-compensated renames, sub-MB preambles (even though they allocate nothing — the SAPI read-buffer *sequence* defines the rubble), +1 MB burner churn, ±6 nesting units, +14 parts. The razor tracks **units-exact (860×62 = 53,320), parts-exact (973), and bytes-exact (1,056,221 = one 1 MB read + a 7,645 B tail)**.
4. **The forge is the fill size, not content**: the 483-page carrier is plain `'A'`s — no injected header pattern. Its own multipart-value `zend_string` header (written by the parser) is what the emitter reads. Moving the sid (e.g. +3 pages under filepad) requires re-sizing that final fill to the new page.
5. **The live pool's armed workers are unforgeable**: Cloudflare's sandbox pool carries residue from other participants running the public EDB chain, whose churn relocates their sid into a cached 64 B run of the main chunk (page 107). That page is never carvable, so `last_key`'s release hits a re-carved slot and **any** second initialize panics — 40+ B1-only live requests produced exactly that 500-signature and never a leak. The B1-only "lottery" over the pool has EV 0.
6. **The WAF's body scan is partial and position-dependent → position-independent after 11-03**: through 11-02 the pair-position law held (the `PHP_SESSION_UPLOAD_PROGRESS` signature had to sit past ~1 MB). The [2026-11-03 WAF release](https://developers.cloudflare.com/waf/change-log/changelog/) ("PHP OOM rule-expression updates informed by security researcher reports from the PHP CTF challenge") made every position variant 403.

---

## The WAF analysis and the lock

Cloudflare shipped seven request-phase rules ("Generic Rules — Anomalous Execution 1–7", renamed 2026-10-22 to *"PHP Remote Code Execution Attack (CVE-2026-109618, CVE-2026-109619)"*) plus a response-phase rule (`afffe227…`, "Default block for High confidence Signatures"). The changelog shows three post-launch detection updates:

| WAF release | Change |
|---|---|
| 2026-10-28 | rule #6 detection updated |
| 2026-10-30 | rules #3, #4 + the response-signature rule updated |
| **2026-11-03** | **rules #2, #3 — "PHP OOM rule-expression updates informed by … the PHP CTF challenge"** |

The 11-03 release is the night every A1 variant started returning 403 (the same config passed 5× live on 11-02/03). The detections now flag the OOM-inducing shape itself.

**Why the arm cannot dodge them (the divisor proof):**

- The OOM mass requires ~53,320 nested array units (~128 MB of parse tree). `max_input_vars=1000` caps part count, so shallow×many tops out at ~4 MB — deep nesting is the only amplifier, and the unit count is fixed by the 128 M budget.
- The armed state is units-exact, parts-exact and bytes-exact (finding 3). 53,320 = 2³·5·31·43; its only divisor ≤ 62 that keeps parts ≤ 1000 is **62** — the flagged depth. Depth 61 needs 874 trees (+14 parts) and lands −6 units: measured dead. Depth 43 needs 1,240 parts: over the var cap.
- The razor forbids every encoding trick: `%5B` encoding adds 3 B/level (mass shift → state-kill, measured), header folding moves the fatal to a pre-assignment site (measured), and PHP's parser tolerates no case/space games on the progress field (measured).

So the arm stage is **provably fused with the detection** under the current ruleset. The B1 stage alone cannot win (finding 5), and the RCE stage needs the leak. The chain is complete; the delivery gate is closed by rule composition that has only tightened (10-22 → 10-28 → 10-30 → 11-03).

---

## Verdict

**The CTF flag was not captured.** The research ends as a rigorous negative with a fully-characterized chain:

- the complete A1→B1→RCE chain, local-verified 3× against the exact CTF build;
- the armed-state oracle and the byte-exact state-razor;
- the proof that the surviving arm method is the one Cloudflare's 11-03 detections now flag, with the divisor argument that no legal A1 variant escapes both the razor and the rule;
- the measured mechanics of the live pool, the walls (CF de-chunking → hard 8 MiB `post_max_size`; Apache `LimitRequestBody` 10 MiB; response-phase signature rule) and the prior-report landscape (see [`docs/h1_distinctness_draft.md`](docs/h1_distinctness_draft.md) and the unsubmitted [`docs/h1_report_draft.md`](docs/h1_report_draft.md)).

What would reopen live delivery: a Cloudflare ruleset change that stops flagging the OOM shape (the changelog arc is monotonic tightening — unlikely), or a *materially different* state-producing mechanism that is not the nested-name OOM (none found; the session-stage OOM is the CVE mechanism itself).

---

## Repository layout

```
├── README.md                 ← this writeup
├── docs/
│   ├── edb52704-analysis.md            ← decoded analysis of the public EDB 52704 chain
│   ├── hypotheses.md                   ← the research hypothesis register (H01–H12)
│   ├── h1_report_draft.md              ← the unsubmitted HackerOne report draft
│   ├── h1_distinctness_draft.md        ← the eligibility/distinctness analysis
│   ├── live_shot_list.md               ← the pre-computed live-shot sequence (unfired)
│   └── build_live_b1.py                ← the ≤8 MiB live B1 body builder
├── scripts/
│   ├── exp_aa.py             ← the EDB 52704 exploit (extracted, instrumented; see Attribution)
│   ├── exp_live.py           ← the experiment driver: pin/rebind, A1/B1 slots, ka mode, RCE stage
│   ├── full_chain.py         ← the one-pass local chain (rinse → season → arm → leak)
│   ├── chain_run.py          ← the single-process variant
│   ├── ka_chain.py           ← the one-socket A1→B1 chain
│   ├── rce_from_resp.py      ← saved-response → decode → base vote → RCE
│   ├── draw_engine.py        ← the live B1-only rotation engine (pool-state lottery)
│   ├── window_watch.py       ← the WAF window prober
│   ├── extract_exp.py        ← regenerates exp_aa.py from the EDB page capture
│   ├── build_live_b1.py      ← the ≤8 MiB spray-body builder
│   └── gdb/                  ← the armed-state walk/oracle scripts (attach via docker exec)
└── lab-conf/
    ├── docker-compose.yml    ← the lab replica (php:8.5.11-apache + zz-lab overrides)
    └── zz-lab.ini            ← the PHP overrides matching the CTF sandbox
```

## Reproduction

```bash
# 1. bring up the replica
cd lab-conf && docker compose up -d && cd ..
# (the replica listens on :8080; verify libphp md5 = 39a5b69694ed9410ea5ef2a687213833)

# 2. build the A1 and the S12 leak body (see scripts/exp_aa.py docstring; S12 recipe in the table above)

# 3. run the chain (ka = one-socket, deterministic same-worker routing)
python scripts/exp_live.py --host 127.0.0.1 --port 8080 --ka \
    --b1-file b1_s12.bin --rce "id>/var/www/html/proof.txt" --rce-block-offset 0xA5B9E8

# 4. read the proof
curl http://127.0.0.1:8080/proof.txt
```

Payload `.bin` files are not committed (multi-MB, and the CTF records request payloads — regenerate them from the recipes). PHP ≥ 8.5.12 is not affected; run this only against the patched-vulnerable lab image you build yourself.

## Attribution

- **Exploit-DB 52704** — the base chain (`scripts/exp_aa.py` is the extracted, instrumented copy; `scripts/extract_exp.py` documents the exact provenance). All stage mechanics, the ROP design, and the original constants derive from that public research.
- **Wiz** — discovery and disclosure of CVE-2026-109618/109619.
- **Cloudflare** — the CTF, the sandbox configuration, and the WAF ruleset; the changelog quotations are from the public [WAF changelog](https://developers.cloudflare.com/waf/change-log/changelog/).
- The walk-oracle, the state-razor, the forge-mechanics, the emission-law experiments, the pool game-theory and the divisor lock are original to this repository.

## Timeline (UTC)

- **2026-10-21** — php2shell disclosed; Cloudflare emergency WAF rules.
- **2026-10-27** — the CTF launches; research begins (lab replica, EDB 52704 decode).
- **2026-11-02/03** — full local chain verified (leak → base → RCE); live A1 still passing the WAF.
- **2026-11-03** — Cloudflare "PHP OOM rule-expression" release; every A1 variant 403s live.
- **2026-11-04** — the lock characterized and proven; live delivery declared closed; this repository published.

## License

MIT — see [LICENSE](LICENSE).
