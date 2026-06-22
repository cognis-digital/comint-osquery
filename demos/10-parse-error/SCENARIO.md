# 10 — Corrupt / truncated snapshot (resilience)

**Where the data came from.** A host where the osquery collector was killed
mid-write (disk filled, container OOM, network drop) and shipped a **truncated
JSON** file. Real fleets hit this constantly; the scanner must not crash on one
bad artifact and silently skip the rest of the run.

`truncated.json` is deliberately invalid (the array and object are never
closed).

**What to expect.** comint-osquery does **not** raise. It emits one **LOW**
finding instead:

- `CO-PARSE` — *"Couldn't parse ... truncated.json: ..."* — pointing at the
  offending file so an operator can re-collect it.

This makes the failure **visible and actionable** rather than a swallowed
exception, and keeps any other valid `*.json` files in the same scan flowing.

**Run it.**

```bash
comint-osquery demos/10-parse-error/ --format console
comint-osquery demos/10-parse-error/ --format json | python -c "import sys,json; print(json.load(sys.stdin)['findings'][0]['id'])"
```

**How to act.** Re-run the collector on that host and re-scan. If truncation
recurs, check the collector's disk/CPU limits — a chronically truncated host is
an availability problem in its own right.
