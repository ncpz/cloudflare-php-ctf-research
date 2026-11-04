# PHP CTF: Pre-auth RCE on php-rce.cloudflare.app via session-state OOM arm + overlong Set-Cookie heap disclosure (CVE-2026-109618 / CVE-2026-109619)

**Status: assembled but never submitted. The live delivery path closed on 2026-11-03 with the Cloudflare "PHP OOM rule-expression" WAF release (see the repository README — "The WAF analysis and the lock"); the report below is preserved as written on 2026-11-03, including its then-current live status. All times UTC.**

## Summary

Target: `php-rce.cloudflare.app` (Cloudflare PHP CTF; PHP 8.5.11 mod_php behind Cloudflare managed WAF). The exploit is the three-stage, worker-affinity chain for the "php2shell" vulnerabilities:

1. **A1 — state-producer arm (1,056,221 B multipart POST).** A body of 973 multipart parts, dominated by 860 parts whose names nest 62 array levels deep (`files[R%05d` + 90×`K` + `]` + `[a]`×62), drives the request's parse-tree past `memory_limit=128M`. The OOM fires inside `php_session_initialize` → `php_session_reset_id` → `php_url_encode` — i.e. **after** `create_sid` and `PS(id)` assignment and with `PS(send_cookie)=1`. The request bails out leaving stale session globals (`PS(id)`, `send_cookie`, leaked `mod_data`) in the prefork worker — the CVE-2026-109619 state-leak. On the lab pool this renders in-band as `PHP Fatal error: Allowed memory size of 134217728 bytes exhausted (tried to allocate 4096 bytes)`.
2. **B1 — overlong-cookie leak (17,705,395 B multipart POST, same keep-alive worker).** Fifteen large form values in an exact choreography — 12×1,048,576 B walk fills, one 511-page (2,093,056 B) shroud, one 256-page positioning fill, one 483-page (1,978,345 B) forge-carrier — groom the worker's heap so that at the END-cleanup `php_session_initialize` the stale `PS(id)` string's `zend_string.len` field is overlaid by an attacker-placed header. The cookie-emission `php_url_encode` then reads `len = 0x1C048` (114,696) instead of 32 and emits a **241,282-byte `Set-Cookie: PHPSESSID=…`** whose URL-decoded body (114,696 B) contains glibc/Zend heap pointers and libphp image pointers. Dominant bucket = the sid's 2 MB chunk; dtor-aligned vote (`pointer − 0x7b47a0` masked to 2 MiB) yields the **libphp base with 902/903 votes**.
3. **RCE (6.1 MB POST, same worker).** 402,500 `X:` header tuner lines + nested-name amplifiers position the failing allocation at a bracketed key's 81,920 B alloc (`--nested-fields 900`); the interrupted insertion leaves a fake object whose handlers point at a ROP chain (`pop rdi/rsi/ret` → `zif_system`, block-offset **0xA5B9E8**, boot-stable on the official build, libphp md5 `39a5b69694ed9410ea5ef2a687213833`). Command execution as `uid=33(www-data)`.

Local full-chain verification: **3 independent runs on the lab replica (php:8.5.11-apache), leak 114,696 B → base vote 902 → RCE `uid=33(www-data)` → proof file served 200 OK.**

## Endpoint

- `POST https://php-rce.cloudflare.app/php/index.php` — multipart/form-data, boundary `CCCCCCCCCCCCCCCC` (body-announced), all three stages.
- `GET https://php-rce.cloudflare.app/php/f.txt` — flag delivery (`cat /flag > /var/www/html/php/f.txt` via stage 3).

## Payloads (exact)

| Stage | File | Size | SHA-256 |
|---|---|---|---|
| A1 | `a1_stock_default.bin` | 1,056,221 B | `90378064dfd32cdcb093df406ef2b5485719cf133bcca3ccd895e2a3b9dc3e62` |
| B1 (leak) | `b1_s12.bin` | 17,705,395 B | `eb1b6fc1117eb6df57ef4ec918197446758dcad741a08a06279c5cc31aebe6ac` |
| RCE | built by driver (402,500 tuner headers + nested amplifiers + forged object) | ~6.1 MB | generated per-run from leaked pointers |

Body structure of B1 (multipart, boundary `CCCCCCCCCCCCCCCC`): 12 walk fills (`f0000`–`f0011`, 'A' seas of 1,048,576 B each; the PHPSESSID + `PHP_SESSION_UPLOAD_PROGRESS` pair sits after fill 2), the 511-page shroud (`f0012`, 2,093,033 B), the 256-page positioning fill (`f0013`), the 483-page forge carrier (`f0014`, 1,978,345 B — its own multipart value `zend_string` header becomes the forged length the emitter reads).

Generation recipes (byte-exact, from the driver defaults): A1 = exp_live argparse defaults (parts=860, fillers128=14, keypad=90, big=78, burners=19@4000 B, progress_len=4072); B1 = the S12 recipe above; both verified by SHA-256.

## Request sequence (single window, serialized, worker-affinity preserved)

1. **Pin** the prefork pool: 160 keep-alive holder connections (MaxRequestWorkers=160) so no spare children can steal routing.
2. **A1** on the freed earmarked worker → in-band fatal (the arm).
3. **B1** on the same worker within the keep-alive window (≤5 s after the A1 response) → the overlong Set-Cookie.
4. Decode the cookie offline: URL-decode 241,282 B → 114,696 B body → extract 8-byte little-endian pointers → 2 MiB bucket vote → dtor-aligned libphp base (≥5 votes required; 902 observed).
5. **RCE** on the same worker with the derived (heap, libphp) → `cat /flag > /var/www/html/php/f.txt`.
6. `GET /php/f.txt` → flag.

## X-Attempt-IDs (live interactions, 2026-11-03 ~21:40–23:30 UTC)

`2ef8732e-53db-4e65-a87d-332ddb7e5935`, `e946ca07-800d-44d6-aa6f-80c05e50fa76`, `63f544ee-f3c7-4ccd-98c5-fdd6cbfdef14`, `217d6afc-8f99-477e-ad8d-38770ff265a5`, `d242bd8f-5d38-4b18-99e3-d5f03dc7dc3b`, `04f9b175-27d1-4f77-bd46-f9de9a6c7487`, `ab9666ba-a789-4998-ab31-e1a685a3f1dc`, `c0f3dc9a-946b-4a18-bccd-2f283473cbb2` (500 — armed-worker panic), `603420d2-0b14-4596-a2bd-8ffd168c80c9`, `9b15daee-5a22-46b2-a77a-1e8b8126eb9c`, `70e44a23-68c0-4111-9a73-a8a014d275fc`, `8c9cb98c-509b-40c9-8175-e8784dbc3537`, `dd22a7fc-5786-4c8f-b42b-6440a1268647`, `5d8d8621-9a21-4ce2-9930-ad417d8b7c18`, `f26202d8-3e83-44c7-8e89-ca05f7a0ecf5`, `c0fc7e78-fc0c-4fae-ae9b-b2e6638cb881`, `46ccddf5-69ac-4255-8516-5eeff4b7cefa`, `bc1be49d-afad-4572-b024-42f74bcd18b3`.

## Live status and WAF interaction (honest)

- **Local lab: the complete chain works and is reproducible** (3× tonight, timestamps in the driver logs).
- **Live: the A1 is blocked by the php2shell managed rules** (Cloudflare deployed seven request-phase rules "PHP Remote Code Execution Attack (CVE-2026-109618, CVE-2026-109619)" plus a response-phase rule; see nanosek's analysis). Measured tonight on every A1 variant (stock, same-length content swaps, sid repositioning, mass-compensated variants, burners, preamble): `403 Forbidden` — the rules flag the deeply-nested multipart parameter names inside the WAF's partial body-scan window (~1–2 MB, plan-dependent).
- The **B1 is not blocked** (all 40+ live B1-only requests returned 200 OK), and `500` responses from B1-only draws prove the pool carries armed workers (stale state from other participants' A1s — those workers' sids sit in a re-carved cached run and panic on any second initialize, matching the public EDB 52704 chain's own analysis).
- The binding corner on live: the A1's armed state is **byte-exact razor-sensitive** (only ±0-byte mutations preserve the stale state; every body-size change shifts the SAPI read-buffer sequence and kills the state), so the A1 cannot be padded past the WAF scan window, and the B1 cannot be shrunk below the 17.7 MB choreography floor against a freshly-armed stock worker while the live post_max_size (8 MiB, enforced after CF de-chunking — verified in-band: `POST Content-Length of 9315580 bytes exceeds the limit of 8388608`) caps any single-request leak body at k≤3 walk steps.
- The exploit is complete and the flag-delivery step is ready. **[Postscript, 2026-11-04:]** the window never re-opened; the 2026-11-03 WAF release flagged the OOM arm shape at every measured variant, and the divisor analysis in the repository README shows no legal A1 variant escapes both the state razor and the rule. This report was therefore not submitted.

## Rules-of-engagement compliance

POST-only to `/php/*`; no DoS (all request volume serialized, single-digit MB per attempt, ≥10 s pacing); no persistence, no scanning of other paths, no attacks on other participants; back-off observed on any 4xx/5xx/RST bursts. The worker-pinning uses only this challenge's own endpoints.
