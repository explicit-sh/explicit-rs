@/Users/onnimonni/.codex/RTK.md

# explicit

- `explicit verify` and any stop-hook output must report only one blocking item at a time.
- Keep a strict priority order for failures so smaller models can follow the next action deterministically.
- Internal execution may be parallelized or cached for speed, but the externally visible result must still surface only the highest-priority unresolved failure.
- Do not emit aggregated multi-failure stop-hook messages for lint/build/test/repository checks.
