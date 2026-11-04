# H1 "PHP CTF" — Materially-Distinct Method/Payload (DRAFT v1, lane2 2026-11-04)

Purpose: the eligibility gate (audit rec #1). Rule text: a "materially
distinct bypass method or exploit payload, even for the same PHP CVE" is
required; "rediscovery of the known PHP vulnerabilities" alone is not
eligible. We claim method + payload distinctness against CVE-2026-109618 /
109619 (PHP 8.5.11), not bug discovery.

## Known public material we delta against
- EDB 52704 — the archived 3-stage exploit (source held in-repo). NOTE: the
  EDB ID could not be publicly corroborated via search (2026-11-03 audit);
  cite the archived source precisely in the report.
- Michaël Russo's writeup — Cloudflare `http.request.body.multipart.names`
  ~128KB scan truncation. Same broad class (edge scan windows) but a
  DIFFERENT field, threshold, and mechanism than ours (below).
- The eness PoC; the ikow session-injection HackerOne record; Sansec's
  php2shell analysis; nanosek's public WAF rule list.

## Delta 1 — WAF bypass (scan-window, by part composition + position)
- Measured live bracket: the `PHP_SESSION_UPLOAD_PROGRESS` signature part
  placed ≤940KB into the body = 403; ≥~1.05MB = pass; the pair sits at
  ~1.2MB in the live B1 (100KB margin). The A1 passes with its progress
  part last (~1.9MB in) — proven 5× live (X-Attempt-ID 4339316b-…, stable).
- Distinct from Russo: their bypass = the `.names` field's ~128KB value
  truncation; ours = composition/position of a multipart form-data pair —
  no truncation involved, measured on the same edge.
- Public WAF rule lists (nanosek, 7 rules) do not model part-position.

## Delta 2 — Cloudflare-specific transport engineering (all measured)
- CF de-chunks and forwards CL-framed → PHP's 8MiB `post_max_size` applies
  to chunked bodies: the effective live body wall is 8,388,608B (413 above
  10,485,760 = apache LimitRequestBody). Locally chunked bypasses the check
  — the lab replicates the live wall only via CL framing.
- Origin connection law: CF resets an unaccepted origin connection once
  ~2MB buffers up → the chain must be staged serially (the B1 never queues
  behind the A1), not pipelined.
- Worker affinity without saturation: the holder-pool pin + rebind
  choreography (≤160 connections/session, pace 0.04s, 30-40min back-off on
  429/503/RST) — single-player-sandbox compliant, no flood.

## Delta 3 — payload composition (unpublished mechanics)
- The cookie-emission laws extracted from the pristine 8.5.11 source:
  emission = `php_session_reset_id` → `php_session_send_cookie` inside
  `php_session_initialize`'s create path (before `s_read`); any FILE part
  sets `PS(id)` + `send_cookie=0` at FILE_START = the silent decode path
  (T1/T2 suppression proofs); the file-less END-cleanup create path is the
  only emission route for the leak body.
- The staged bodies: the A1 mass-driver recipe (fixed-mass, 973 parts, the
  fatal-site laws), the S12 12-[256]-walk shroud/forge choreography
  (17,705,395B, byte-exact, boundary razor-sharp: 12 walks = leak, 11/9/7 =
  panic; walk = byte-based AND size-class-specific), and the map-cover
  2MB 0x40-spray with forged `zend_string` headers (refcount=2, type=6,
  len=0x1C000) at 0x30/0x40.
- The season/arm/headroom law (this lane, measured): r1's OOM site is
  season-depth-driven — ≤30MB = clean decode-phase bailout (no corruption
  persists), ≥32.005MB = the dirty END-encode arm (the ~120MB pin). The
  architecture's constraints, not just the payload, are characterized.

## Delta 4 — RCE calibration on the official build
- `--rce-block-offset` 0xA5B9E8 = boot-stable on the official
  php:8.5.11-apache libphp (md5 39a5b69694ed9410ea5ef2a687213833); the
  author-published 0x5C400 site HANGS the worker (measured twice).
- Base recovery = dtor-aligned 2MiB bucket voting from the leak's decoded
  pointers (`zval_ptr_dtor` offset 0x7b47a0), votes ≥5 — not in any public
  PoC.

## Honest limitations (include verbatim in the report)
- The underlying CVEs are public and KEV-listed; eligibility rests on the
  method/payload deltas above.
- The leak stage is geometry-bound (seasoned-pool corruption states);
  the report documents which stages are deterministic vs state-dependent.
- Payloads are recorded by the program and may be published as permalinks
  (rules) — no third-party data in any body; test data only.

## Report assembly checklist (remaining)
- [ ] Endpoint + complete payload + sequence (the shot list phases 1-7)
- [ ] Raw request/response captures per shot (X-Attempt-IDs + UTC)
- [ ] WAF-bypass explanation (Delta 1-2) + code executed + /flag recovery
- [ ] UI verification result + this distinctness section as-is
