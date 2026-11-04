# Scripts

Python 3.10+, standard library only — no dependencies to install. All scripts target the lab replica from [`lab-conf/`](../lab-conf/) by default. Payload `.bin` bodies are not committed; the recipes in the [main README](../README.md#reproduction) regenerate them.

## Chain and stages

| Script | Purpose |
|---|---|
| `exp_aa.py` | The Exploit-DB 52704 exploit (extracted, instrumented): `build_a1_body`, `cookie_value`, `summarize_cookie`, `amplified_rce`. Needs the EDB page capture at `ext/edb52704_view.txt` to regenerate — see `extract_exp.py`. |
| `exp_live.py` | The main experiment driver: holder pinning, A1/B1/RCE stages, keep-alive (ka) mode with mid-parse stall, `--rce-block-offset 0xA5B9E8`. |
| `full_chain.py` | One-pass local chain (rinse → season → arm → leak). |
| `chain_run.py` | Single-process chain variant. |
| `ka_chain.py` | One-socket A1→B1 chain (same worker, no pinning). |
| `rce_from_resp.py` | Saved response → cookie decode → pointer extraction → 2 MiB base vote → RCE compose. |

## Measurement and live tooling

| Script | Purpose |
|---|---|
| `draw_engine.py` | Live B1-only rotation engine (pool-state lottery; historically produced the 500-signature evidence). |
| `window_watch.py` | WAF window prober (A1 probe loop; kept as a record of the watcher phase). |
| `build_live_b1.py` | ≤8 MiB live-capped B1 spray-body builder. |
| `extract_exp.py` | Regenerates `exp_aa.py` from the EDB 52704 page capture (provenance). |

## gdb oracles (`gdb/`)

Attach from the host via `docker exec` into the lab container; each script targets a running worker:

| Script | Purpose |
|---|---|
| `g_walk2.gdb` | The walk oracle: dump `PS(id)` / chunk cache on a mid-parse stalled armed worker. |
| `g_map.gdb` | Heap/chunk map of the armed worker. |
| `g100_spray.gdb`, `g97_spray.gdb` | Spray-state inspection at fill counts 100/97. |
| `g_abort.gdb` | Panic-path capture (heap-corruption aborts). |
| `g_leak2.gdb` | Post-leak inspection (`//tmp/g_leak2.gdb` probe site). |

## Attribution reminder

`exp_aa.py` is the extracted, instrumented public Exploit-DB 52704 exploit — see [Attribution](../README.md#attribution) in the main README before building on it.
