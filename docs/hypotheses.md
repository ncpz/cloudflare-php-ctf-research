# V7 — Hypothesis register

Status legend: VERIFIED-SOURCE / REPRODUCED-LOCAL / REPRODUCED-PATCH-DIFF / REPORTED-EXTERNAL / TARGET-OBSERVED / HYPOTHESIS / REFUTED / UNRESOLVED

| ID | Hypothesis | Status | Evidence |
|---|---|---|---|
| H01 | Multipart headers can exceed 128 MiB below 8 MiB wire | **REFUTED for 8.5.11 retention** (php_mime_should_save_hdr whitelist, E-024); **the EDB 52704 achieves the equivalent pressure via the nested-name arrays + the 402,500-header tuner across a multi-stage chain** (the headers tune which allocation fails, not the total) | edb52704-analysis.md |
| H02 | Header/nested allocations remain live while a later variable insertion occurs | VERIFIED-SOURCE (the header llist = live during the value registration; the nested arrays = live during the subsequent inserts) | rfc1867.c:823-830, 964 |
| H03 | A natural OOM during such insertion produces incomplete HashTable state on unmodified 8.5.11 | REPRODUCED-LOCAL (the SIGSEGV at zend_hash.c:964 via the size-targeted fault injection; the natural-OOM equivalent = the EDB 52704 A1 stage at memory_limit=128M) | E-009b, gdb-crash.log |
| H04 | The patched 8.5.12 avoids the vulnerable state | UNRESOLVED (the L1 container = running; the differential test = pending) | l1-8512 :8100 |
| H05 | The incomplete state can be influenced by request-controlled memory | REPRODUCED-LOCAL (the pad free-and-reuse: the 2528B forged structure placed via the pad/pad=x sequence; the resize-path groom placement computed) | ddshape5/7, edb52704-analysis.md |
| H06 | The affected cleanup path can generate a harmless local execution marker | REPORTED-EXTERNAL (the EDB 52704: zif_system via the jump_fcontext ROP; the validated 2026-10-23) + HYPOTHESIS (the local port = pending) | edb52704-view.txt |
| H07 | CVE-2026-109619 provides a separately reproducible cross-request state violation | REPRODUCED-LOCAL (the E-015 flock leak = the state-corruption symptom; the EDB 52704 A1/B1 = the full chain: PS(id) stale → the forged cookie → the ASLR defeat) | E-015, edb52704-analysis.md |
| H08 | A memory disclosure suitable for defeating ASLR is possible without debugger-derived addresses | REPORTED-EXTERNAL (the EDB 52704 B1: the overlong Set-Cookie → the libphp base derived from the leaked zval_ptr_dtor pointer) + HYPOTHESIS (the local port = pending) | edb52704-analysis.md |
| H09 | A reproducible local execution path can survive ASLR resets and worker restarts | REPORTED-EXTERNAL (the EDB 52704: "repeat under a new ASLR parent and run twice without an Apache restart") + HYPOTHESIS | edb52704-view.txt |
| H10 | The necessary request sequence stays within Cloudflare's body-size and authorization constraints | UNRESOLVED — **the blocker: the EDB 52704 uses the worker discovery/scrub/pinning = the worker-pool saturation = PROHIBITED live**; the RCE body itself = 5-8MB ✓ but the delivery requires the saturation-dependent worker affinity | edb52704-analysis.md §Stage-0 |
| H11 | Cloudflare request forwarding does not invalidate the exploit assumptions | UNRESOLVED — the CF dechunks + reframes (E-002); the chunked A1 delivery may break; the body ≤8MB ✓ | E-002 |
| H12 | The candidate method is materially distinct from the published solutions | UNRESOLVED — the EDB 52704 + the 9 repos = the public prior art for BOTH the mechanism and (per the unverified social claim) possibly the CTF solve | The V6 brief §14 |
