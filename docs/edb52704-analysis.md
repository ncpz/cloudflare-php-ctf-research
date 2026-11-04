# V7 — Exploit-DB 52704 source analysis (the complete chain decoded)

Source: `ext/edb52704_view.txt` (the full 1005-line exploit, extracted from
the EDB page). The exploit targets **exactly the CTF's configuration**:
php.ini-production defaults (memory_limit=128M, post_max_size=8M,
max_input_vars=1000, max_file_uploads=20, nesting=64), Apache prefork
mod_php, ASLR on, PHP 8.5.11 NTS official source build.

## The three-stage architecture

### Stage 0 — worker discovery + scrub + pinning (delivery/affinity)
- `discover_worker_pool`: 150 probe connections → the worker count
- `scrub_worker_pool`: aborted requests force the gracefully-retiring
  children to exit (the IPv6-listener wakeup quirk in the validated
  Apache build)
- `hold_workers_parallel`: pins ALL workers with keep-alive holders;
  exactly one unpinned worker remains → A1 and B1 are serialized onto it
- **Live-prohibited** (worker saturation = DoS); locally deterministic.

### Stage A1 — the OOM producer (the nested-name request)
- 860 parts × nested name `files[R%05d + 90×'K'][a]×62` (64 levels,
  ~93B/level, ~6KB wire/part)
- Each part creates 64 nested HashTables + ~90-char key strings per level
  ≈ 64 × ~420B ≈ 27KB heap per part → **~23MB total** (not the OOM yet)
- Content-Type headers: "C"×103 (part 0), "C"×231 (part 1) — **the llist
  size-class grooming** (the header entries land in specific bins)
- `PHPSESSID = "\x00"` (a NULL-byte sid → the early-find_sid stores the
  stale/empty pointer)
- `PHP_SESSION_UPLOAD_PROGRESS = "k" × progress_len` — the trigger
- Sent **chunked** (`start_chunked`): the streaming keeps the worker
  inside the parse while the state ripens
- The OOM fires during the progress update's serialize → the bailout
  before the state reset → **PS(id) stale, PS(send_cookie)=1**,
  in_rfc1867_update stuck

### Stage B1 — the reclaim + forged-cookie disclosure
- Queued behind A1 on the SAME worker (the pinning + the FIFO)
- The body: 16 × 511-page (~2MB) form values with **forged zend_string
  headers packed at page boundaries** (`header = page*4096 - 0x1018`,
  refcount=1, type_info=0x16=IS_STRING|..., the leak tag) + the nested
  reclaim fields
- **The reclaim: B1's allocations reuse A1's freed PS(id) memory; the
  forged zend_string header lands at the stale pointer's page**
- B1 OOMs → the shutdown → the session close → `php_url_encode(PS(id))`
  → **Set-Cookie contains the forged string + the leaked pointers**
- `summarize_cookie`: the decoded cookie → the 8-byte pointer candidates
  → the dominant = `zval_ptr_dtor` (the libphp pointer!) → **the libphp
  base = dominant − 0x7ae960; the main chunk = libphp + the delta**
- **ASLR defeated in-band** (the HTTP cookie, no debugger)

### Stage RCE — the interrupted-insertion sink (the second request)
- The RCE request runs on the SAME worker (the pinning), with the forged
  cookie as the sid, **after the complete A1/B1 history** (the heap state
  = calibrated post-A1/B1, not virgin)
- The body:
  1. `memshift` = 40KB "M"s (the heap shift)
  2. 30 × `a[<80KB key>][c]=v` (the 80KB-key nested fields = the heap
     layout shaping)
  3. `pad` = the 2528-byte forged structure (the fake object + the
     handlers + the ROP: pop rdi/rsi/ret + zif_system + the execute_data
     + the command at +0x80) registered into $_POST['pad']
  4. `pad=x` (the overwrite → the 2528B block freed → the free-list)
  5. 15 × `a[<80KB key>][c]=v` (the further shaping)
  6. **`X: a\r\n` × 402,500** (the header lines: the memory-limit
     headroom tuner — swept so the failing allocation = the final
     bracketed name's 81,920B key alloc)
  7. The final bracketed-name field → **the interrupted insertion**:
     nNumUsed/nNumOfElements committed, the key alloc (81,920B) fails →
     the bailout → Bucket[final] = the PAD's forged bytes (the block
     reused via the pad free-and-reuse) → the shutdown destroy →
     **the fake object → the handlers → jump_fcontext pivot → the ROP →
     `zif_system(command)`** ✓✓✓
- The guard: `if len(body) >= 8*1024*1024: raise` — **the body stays
  under post_max_size=8M** ✓

## The build-specific constants (the recalibration checklist in the source)

- `zval_ptr_dtor=0x7ae960`, `zif_system=0x598650`,
  `jump_fcontext+0x2e=0x6362ae`, `pop rdi=0x280d8d`, `pop rsi=0x2cbe07`,
  `ret=0x280d8e` (the libphp image-relative)
- The Zend main chunk = libphp+0x3400000; the controlled block =
  main+0x5c400; the forge page = 0x1e3
- The source: php-8.5.11.tar.xz SHA-256 d9be75c0..., the commit
  678778973bb4d4185c06ef1320de50f1a975d3c8, -O2 -g
  -fno-omit-frame-pointer -fcf-protection=none, glibc 2.43, Apache 2.4.66
- The recalibration procedure is IN the exploit source (the nm/ROPgadget/
  the GDB driver for the --forge-page/--rce-block-offset derivation)

## Why my V5/V6 conclusion was wrong

I modeled the OOM as requiring the request allocations to reach 128M
*within one request*. The 52704 chain:
1. The A1 nested-name request (~23MB heap) does NOT OOM — it **creates
   the interrupted-adjacent state** (the stale PS(id), the heap layout)
2. The B1 reclaim **converts the stale state into the information
   disclosure** (the cookie)
3. The RCE request uses the **leaked addresses** to place the forged
   structures precisely, and the 402,500 headers tune which allocation
   fails — the memory_limit fatal at the *final* bracketed key, with the
   pad block already groomed at the predicted address
4. The dispatch = the shutdown destroy → the fake object → the ROP →
   zif_system — no decode-side interrupt needed

The "128M unreachable" conclusion conflated the *memory_limit* with the
*allocation-failure site*: the exploit doesn't exhaust 128M of parsing —
it makes a small, precisely-placed allocation fail at the boundary
reached by the earlier stages' residual heap state, then reuses the
groomed block. My 25MB/22MB ceilings were real but irrelevant.

## What transfers to the Cloudflare target vs what doesn't

**Transfers (the mechanism level):** the A1/B1 chain (the nested-name
OOM producer, the reclaim, the forged-cookie disclosure), the RCE sink's
structure, the php.ini-production config match, the prefork worker model.

**Doesn't transfer directly:**
- The build constants (the target's libphp = a different build: the
  official Docker image vs the author's Ubuntu source build — the
  offsets/gadgets differ; the recalibration procedure is in the source)
- The worker scrub's IPv6-listener quirk (the validated Apache build's
  behavior; the target's Apache version/MPM unknown)
- The glibc/ROP specifics (the target's libc version unknown)

**Live-prohibited:** the worker discovery (150 connections), the scrub,
the pinning (all = worker-pool saturation = DoS per the CTF rules).
