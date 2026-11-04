# Security policy

This repository is **documentation and research tooling**, not a product — there is no supported release, runtime, or service to secure.

## Scope and expectations

- The scripts here exploit **known, already-patched** vulnerabilities (CVE-2026-109618 / CVE-2026-109619, fixed in PHP 8.5.12) and are intended for the local lab replica defined in [`lab-conf/`](lab-conf/), or for systems you own or are explicitly authorized to test.
- We do not accept reports about "the scripts can exploit PHP" — that is the documented purpose, the bugs are public record, and the fixed release has been available since before this repository was published.

## Reporting a concern

- **Issue with the repository's content** (an error, an unsafe default, a file that should not be public): open a GitHub issue, or contact the author via GitHub (`ncpz`).
- **php2shell or other PHP security issues**: report to the PHP security team (security@php.net) or via the Wiz disclosure channels — not here.
