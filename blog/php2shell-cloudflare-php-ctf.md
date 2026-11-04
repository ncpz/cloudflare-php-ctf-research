---
title: "I built the complete exploit for Cloudflare's PHP CTF. Their WAF still won."
published: false
description: "A negative-result research writeup: full A1→B1→RCE chain verified locally against the exact CTF build, and the mathematical reason Cloudflare's WAF rules can no longer be dodged."
tags: security, php, infosec, ctf
canonical_url: https://github.com/ncpz/cloudflare-php-ctf-research
---

On October 27th, Cloudflare published a dare: a stock PHP 8.5.11 server with an empty `index.php`, sitting behind their own WAF. Get remote code execution, read `/flag`, get $3,000 — **but only if you can do it without tripping the php2shell managed rules they deployed the day those CVEs went public.**

This is a story about getting all the way to the last step and finding the door welded shut. The exploit chain is complete and reproducible locally — three end-to-end runs, ROP to `system()`, `uid=33(www-data)`, proof file served over HTTP. The live capture failed, and the interesting part is *why*: the failure isn't bad luck or tuning. It's structural, and you can prove it with factorization.

Everything below is documented with scripts in [the repository](https://github.com/ncpz/cloudflare-php-ctf-research). Fair warning up front: this is a **negative result**. The flag was never captured.

## The target

php2shell ([Wiz's disclosure](https://www.wiz.io/blog/php2shell-php-rce), CVE-2026-109618 / CVE-2026-109619, CVSS 9.2) is a pair of memory-safety bugs that chain to unauthenticated RCE in default PHP configurations. Cloudflare shipped WAF rules before the disclosure even landed, then [turned their own defenses into a CTF](https://blog.cloudflare.com/php-ctf) a week later. The rules of engagement: POST requests to `/php/*` only, no DoS, report privately on HackerOne, and — the clause that did all the work — only a **"materially distinct"** bypass pays. Rediscovering the known CVEs is explicitly ineligible.

A working chain was already public, as Exploit-DB 52704. So the game wasn't "exploit PHP"; everyone had that. The game was "exploit PHP *in a shape the WAF doesn't flag*."

I started by decoding that reference exploit — full analysis in [`docs/edb52704-analysis.md`](https://github.com/ncpz/cloudflare-php-ctf-research/blob/main/docs/edb52704-analysis.md), and the extracted source lives in my repo with attribution — then built a byte-comparable replica of the CTF sandbox (official `php:8.5.11-apache`, `libphp.so` md5 `39a5b696…`) and set about understanding *why* it works, not just that it works.

## Stage 1: the crash in the wrong place

The first request is a ~1 MB multipart POST whose field names nest 62 array levels deep — things like `files[R00001][KKKK…KKK][a][a][a]…` sixty-two brackets deep. 860 of those parts, plus fillers, force PHP's parser to build ~53,320 nested hash-table levels, which costs about 128 MB of parse-tree memory. That's exactly `memory_limit`, so PHP bails out with the familiar:

```
PHP Fatal error: Allowed memory size of 134217728 bytes exhausted
```

Out-of-memory during request parsing is normally boring. The CVE is *where* this one lands. The OOM fires during the session initialization that runs at the end of the request, inside `php_url_encode`, **after** the code has already generated a session ID and set `PS(send_cookie) = 1`. The fatal unwinds the request but never cleans the session globals up. The prefork worker — which lives for thousands of requests — is now carrying stale session state: a half-initialized `PS(id)`, a "send a cookie" flag stuck on, a leaked file handle.

One request. No response needed. The worker is armed.

## Stage 2: a 241 KB session cookie

The second request, on the same keep-alive connection, is 17.7 MB of multipart form values in a precise choreography. Its job is heap grooming: twelve consecutive ~1 MB values that walk the allocator's free-run list down to the run the armed request left behind, a 2 MB "shroud" value covering the old session ID's chunk, and a final 483-page value whose own multipart-value header lands exactly on the stale `PS(id)` string.

When the request finishes, the session code runs again, sees the stale `PS(id)` with `send_cookie` set, and emits a `Set-Cookie` header. But the header of that string has been overwritten — by our filler's own `zend_string` header, written by PHP itself — so the emitter reads a length of `0x1C048` instead of 32 bytes.

The response carries a **241 KB `Set-Cookie: PHPSESSID=…`**. URL-decoded, it's 114,696 bytes of raw memory: glibc heap pointers, Zend allocator structures, and — the prize — libphp image pointers. Bucket the pointers into 2 MiB pages, find the dominant bucket, subtract a known offset, and vote on alignment: **902 out of 903 pointers agree** on the libphp base address. ASLR, defeated in-band, over plain HTTP, with no crash and no error channel.

The detail I find most elegant: the forged length isn't injected data at all. The final filler is plain `'A'` characters. *PHP's own parser writes the forged header* when it allocates that multipart value — the exploit just arranges for the allocation to land on the right address, at the right size class, with the stale pointer still pointed at it.

## Stage 3: ROP

Third request, same worker: ~400,000 small header lines tune the heap until a failing allocation lands on a bracketed key, and the interrupted hash insertion re-carves a fake object registered earlier — one whose handler table is a ROP chain. The shutdown dispatch calls through it: `pop rdi`, `pop rsi`, `ret`, `zif_system`. Command execution as `www-data`.

On the official build, the ROP gadget sink sits at offset **0xA5B9E8** (the author-build constant hangs the worker — measured twice). The heap-to-libphp delta is re-derived from the leak every run; transplanting it never survives.

Three stages, three requests, one worker. Locally: verified three times, start to finish.

## What the local grind taught me

The things worth publishing are the invariants nobody documents:

**The armed state is byte-exact.** I tried every mutation of the first-stage body: renaming parts, reordering, padding, byte-compensated variants, ±6 nesting units, burner churn, even a sub-megabyte preamble that allocates nothing. Everything kills the armed state except *same-length content swaps* — the state tracks the part count exactly (973), the nesting-unit count exactly (860 × 62 = 53,320), and the byte count exactly (one full 1 MB SAPI read buffer plus a 7,645-byte tail). I call it the razor. It has one harmless edge, and everything else cuts.

**The walk is not compressible.** Each 1 MB filler consumes exactly one grant on the allocator's free-run list, and the panic-target run sits twelve grants deep. Fillers of any other size class walk a different list and always crash the worker with a heap corruption panic instead of producing a leak. Twelve is not a tuning parameter; it's the position of the target.

**The 500-responses were other players.** Live B1-only requests kept returning `500` from workers I'd never touched. The explanation: the sandbox pool carries residue from *other participants* running the public exploit. Their arm choreography relocates their session IDs into a cached small run that my forge can never carve — and any second session initialization on those workers panics. The public chain had effectively salted the earth. No amount of lottery tickets on armed workers pays out.

## The wall, and the proof it's a wall

Live, the first-stage request returned `403 Forbidden`. Every variant of it. Same-length content swaps, repositioned session fields, mass-compensated renames, preambles — all 403, all night, while the identical bytes sailed through locally.

Cloudflare's [WAF changelog](https://developers.cloudflare.com/waf/change-log/changelog/) tells the story: rules updated October 28, October 30, and November 3 — the last one annotated, verbatim, *"PHP OOM rule-expression updates informed by security researcher reports from the PHP CTF challenge."* The detections had moved from "flag the payload" to "flag the OOM-inducing shape itself," position-independently.

Here's why that's fatal for this exploit class, and it fits in one paragraph:

The OOM mass requires ~53,320 nested array units, because `max_input_vars=1000` caps the number of parts — shallow and wide tops out around 4 MB, nowhere near 128. Deep nesting is the only amplifier, and the razor demands the unit count stay *exactly* 53,320. But 53,320 = 2³ × 5 × 31 × 43. Its only divisor ≤ 62 that keeps the part count under 1,000 is **62** — precisely the depth the rules flag. Depth 61 needs 874 parts and lands six units short (measured dead). Depth 43 needs 1,240 parts: over the cap.

So the one legal shape of this exploit is the exact shape the rules flag. The arm isn't just detected — it's *fused* to the detection. No encoding trick survives the razor, no reorganization survives the var cap, and the changelog arc runs one direction. That's the proof, and it's arithmetic, not an opinion about WAF tuning.

## What I take away

- **For defenders:** the Cloudflare rules that matter don't signature payloads; they recognize the resource-exhaustion *shape* and are position-independent. That's why they've held while everything else churned.
- **For PHP admins:** if you're still on 8.5.11 or below, this chain needs no authentication, no file upload, and no error output — just POST. 8.5.12 fixes it. Update and restart your workers; the state leak survives the request that caused it.
- **For CTF players:** the meta of this challenge was brutal by design — a public reference exploit meant the pool was poisoned with other people's armed workers, and the WAF could be retuned *mid-game* with reports from other participants. Cloudflare was playing against the entire internet in parallel and it showed.
- **For me:** the negative result is the publishable result. The lock proof, the emission-law experiments, the walk oracle, the razor characterization — none of that exists in public writing anywhere else, and it's all in [the repo](https://github.com/ncpz/cloudflare-php-ctf-research), with the curated scripts, the gdb scripts for the armed-state oracle, the HackerOne draft I never submitted, and the honest live-shot list that never fired.

## Attribution and credit

The exploit mechanics derive from the public Exploit-DB 52704 chain — my repository builds on it and says so throughout. CVE discovery and disclosure by Wiz. The CTF, the sandbox, and the WAF ruleset are Cloudflare's; their changelog quotations are public record. The walk-oracle, the state razor, the forge mechanics, the emission laws, the pool game theory, and the divisor lock are original to this research.

All testing followed the CTF's published rules: POST-only to `/php/*`, serialized requests, no DoS, back-off on errors. The research stopped the moment the path closed, and everything here targets either the patched-vulnerable lab replica or the CTF's own published boundaries.
