# LIVE SHOT LIST — pre-computed for one throttle window (lane2, 2026-11-04)

Basis: all local lanes measured closed except the seasoned-LIVE-pool route.
Leak geometry = container-era-bound (V18j law: pristine 8192/366B in-band
cannot leak; runCD's S12 proof not yet reproduced on the current main
container — see the V18j-verdicts decisive test). The LIVE pool = weeks of
residue = the only confirmed leak-capable geometry.

## Hard walls (measured, live)
- post_max_size 8MiB = 8,388,608B on CL-framed bodies (CF de-chunks → the
  8MiB check applies to MY chunked bodies too). Apache LimitRequestBody
  10,485,760B = 413 above. → every body below is ≤8MiB.
- CF resets an unaccepted origin connection once ~2MB buffers up → the B1
  must NOT queue behind the A1: serialized requests, never pipelined.
- Edge throttle: ~160-250 new connections/session → holders ≤160, pace 0.04.
- WAF: the [PHPSESSID][PHP_SESSION_UPLOAD_PROGRESS] pair must sit AFTER
  ~1.05MB of body (940KB = 403, ~1.05MB = pass); --a1-big-shrink ≤2000 OK,
  ≥5000 = 403. The A1's progress part sits last (~1.9MB in) = passes (proven
  5× live, V18d).
- Back-off: any 429/503/RST → abort the window, wait 30-40 min. The A1
  response = in-band 200 + X-Attempt-ID (stable across shots: 4339316b-…).

## Pre-flight (offline, before the window)
1. Verify the other agent's lane is NOT firing live (coordination note in
   the shared memory; live = the one shared resource).
2. Bodies:
   a. A1 = V15-config (STABLE 5× live, 16384-site in-band):
      exp_live.py --tls --port 443 --a1-keypad 300 --a1-parts 850
      --a1-big 55 --a1-filepad 450000 --a1-progress-len 500000  (~1.5MB)
   b. B1 = the map-cover spray, V18h-corrected shape, pair LATE, NO file
      part: [~0.9MB filler value][PHPSESSID][PHP_SESSION_UPLOAD_PROGRESS]
      [2MB 0x40-spray value (forged len 0x1C000 headers every 0x40)] ≤ 8MiB.
      NOT YET BUILT — builder: lane2/build_live_b1.py (TODO: 30 min).
      The pair-late reshuffle does not move the spray's run (the pair parts
      are bin-class allocs); the spray value = the last part = the run
      claiming the stale sid's page (map[107] = 0 state, V17).
   c. State probe first (cheap): exp_live --state-probe against the live
      pool to check the seasoned sid-in-main state exists TODAY. If absent
      → the shot window is wasted; re-check after the pool churns.
3. RCE args: --rce "cat /flag>/var/www/html/lane2f.txt; cp /flag /var/www/html/lane2flag.txt"
   --proof-url /lane2flag.txt --rce-block-offset 0xA5B9E8 (boot-stable;
   the 0x5C400 default HANGS). NOTE: the RCE body's WAF visibility is
   UNVERIFIED live — if the RCE request 403s, the window still yields the
   leak (report-worthy) and the RCE needs a reshaped body next window.

## The shot sequence (one window, ~8 min)
| # | Action | Oracle | Capture |
|---|--------|--------|---------|
| 1 | state probe (1 req) | seasoned state present? | note |
| 2 | WAF probe: the B1 body minus the pair (1 req) | 200 not 403 | X-Attempt-ID |
| 3 | A1 (V15-config) | in-band fatal (16384-site) | X-Attempt-ID + UTC |
| 4 | B1 (map-cover spray) ≤10s after the A1 | Set-Cookie >> 40B | raw response |
| 5 | offline: decode cookie → 2MiB buckets → dtor-aligned base (votes ≥5) | libphp base | save .resp |
| 6 | RCE request (0xA5B9E8) | proof file served | flag bytes + UTC |
| 7 | UI verify the flag in the CTF panel | visible flag | X-Attempt-ID retention |
| 8 | STOP — no further live traffic; write the H1 report | | |

Abort rules: any 403 mid-sequence → stop (the WAF tightened again);
any RST/429/503 → 30-40 min back-off; the A1 not fataling in-band → the
pool's state moved → abort, re-probe later.

## Post-shot (offline)
- If 4-6 succeeded: the flag = the report's verification section.
- If only 3-4: the leak bytes = the report's partial-evidence section.
- Either way: the distinctness section (audit rec #1) references the
  measured deltas vs EDB 52704 / Russo's multipart.names truncation /
  the eness PoC — delivery engineering (dechunk+reframe, the ≤12MiB→8MiB
  cap mapping, pacing, worker affinity) + the V17/V18 small-B1 work.
