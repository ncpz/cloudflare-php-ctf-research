# Measured model of the live php2shell WAF rules (2026-11-05)

Result of a systematic probe campaign (~35 tiny POSTs to `/php/index.php`, ≤500 B
bodies, 15 s pacing, RoE-clean) mapping what the managed rules actually match.
All probes saved in the engagement workspace (`recon_A/`, `recon_B/`, `recon_C/`,
`recon_D/`); this document is the distilled model.

## Detectors

Two independent detections guard multipart parameter names:

- **α — anchored depth**: ≥ **20** consecutive bracket groups counted from the
  *start of the parsed name* fires. (`[a]`×19 passes; `[a]`×22 fires; base
  group + 18 more = 20 fires; depth ≤ 10 passes.)
- **β — raw run depth**: a bracket-group run ≥ ~31–39 anywhere in a
  `name=`-attribute region fires, independent of parsing.
  (Interior run 21 passes; interior 30 inside a duplicate `name=` passes;
  interior 39 fires.)

Supporting findings:

- The rules operate on **raw name bytes** — they do **not** url-decode
  (`%5B`-encoded 62-level names pass: every group broken).
- Deep bracket text in a **value** never fires — name regions only.
- Index content is irrelevant (10-char indices, same verdicts).
- The name extractor is **robust**: unquoted `name=`, tab separators, and
  duplicate `name=` parameters are all still evaluated (raw β scan covers
  every name-region, so first/last resolution does not matter).
- obs-fold (403) and CRLF→`\n\r` swapping (200, but see below) break the
  extraction — however PHP 8.5.11's rfc1867 parser **also** fails on `\n\r`
  bodies (verified locally: the part loses its `Content-Disposition`
  entirely), so that shape is a mutual kill, not a differential.

## The closure proof (measured, not assumed)

Arming the OOM (the CVE-2026-109619 state leak) requires ~53,320 nested array
units of parse tree. Constraints, each independently measured:

1. `max_input_vars=1000` (sandbox) ⇒ tree count ≤ ~1000 ⇒ **depth ≥ 54 per
   tree** (987 × 54 = 53,298 units; the small mass delta is filler-compensable).
2. PHP 8.5.11 nests only on **strict `][` adjacency** — verified locally:
   inter-index junk (`[a]x[b]`), `%5B` encoding (no decode), and doubled
   brackets all fail to produce the tree the stock body produces.
3. Strict adjacency ⇒ the raw body shows the full 54–62 group run ⇒
   **β fires (threshold ≤ 39 < 54)**.

Every escape candidate was probed and measured dead:

| Candidate | PHP side | WAF side |
|---|---|---|
| `%5B` run-breaking | no decode → no tree | (would pass — useless) |
| `[[a]` doubled brackets | nests (key `[a`) | counts as a group → run intact → 403 |
| `[][a]` append alternation | nests (int keys) | `[]` counted → run intact → 403 |
| inter-index junk bytes | depth collapses to 1 | — |
| duplicate `name=` (PHP takes last) | nests from 2nd param | β scans all name regions → 403 |
| unquoted `name=` | nests | extractor robust → 403 |
| tab separator | nests | extractor robust → 403 |
| CRLF→`\n\r` swap | rfc1867 loses the part | (would pass — useless) |
| obs-fold | — | 403 |

The nesting byte and the detection byte are the same (`[`), PHP demands the
adjacency the detector keys on, and the parts cap forces the depth above the
detector threshold. The differential space between the two parsers was
enumerated and is empty at every measured branch.

## Verdict

The 2026-11-03 "PHP OOM rule-expression" release produced a detection that is
**complete over the PHP-legal request space** for this CVE class. Live flag
delivery remains closed; the local chain (see README) remains fully
reproducible. This model documents the rule behavior for defenders and closes
the research record.
