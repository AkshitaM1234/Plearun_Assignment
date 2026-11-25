   # Verified Findings checker

`python3 plearun_cli.py REPORT RECORDS_DIR > findings.json` — offline, deterministic, stdlib only, no LLM.
`make test` runs 25 offline tests; `make findings` regenerates `findings.json` for the sample.7

## How it works
1. **Load** every file into one row model: UTF-8/BOM/cp1252 decoding, `#` marker lines, CSV, nested JSON (any depth, iterative walk),
   WebVTT. Timestamps: epoch s/ms, ISO with/without offset, naive, `HH:MM`. Bad files/rows are skipped, never fatal.
   Row ids: CSV = 1-based data row, JSON = 1-based event object, VTT = 1-based cue.
2. **Align clocks** only from events of the same kind seen exactly once in each of two sources, and only if >=2 such anchors agree
   within their resolution. Otherwise the device stays unaligned and is assumed to be up to 10 min off.
3. **Extract claims** (clause level: time, speed, "N minutes after X"); anything else is `not_checkable`.
4. **Decide** from candidate rows (below), then **verify**: the quote must be an exact substring of the row's raw text *and* of the file,
   else the finding is downgraded to `not_settled`.
Record text is only ever parsed with regexes into fields; nothing in it is executed or obeyed.

## Three hardest decisions
- **When is a time gap a conflict?** Only if the gap exceeds the device's clock uncertainty (10 min if unaligned), there is exactly one
  event of that kind in all records, and it is stated explicitly. So a 5-minute gap is `not_settled`; the 41 s dispatch/report gap on the 911 call is too.
- **Cameras have no vehicle id**, so a camera reading can corroborate a claim only if the report itself points at the camera, and it can never
  contradict one. Speed conflicts must come from a statement naming the same zone ("62 in a 45") and not about "the other car".
- **Durations across clocks** ("unit on scene 2 min after the stop") are only computed within one source or between aligned sources.
  Sample: on-scene is in CAD, the stop is in notes/bodycam, one anchor only -> `not_settled` rather than a naive subtraction.

## What it gets wrong
- Matches check only the checkable part of a claim ("near mile marker 4" is not verified). Officer's own words (bodycam/notes) can match
  the officer's own report: independent, but not impartial. Claim extraction is regex-based: unusual phrasing becomes `not_checkable`.
- Alignment is star-shaped around one reference source; no drift, no DST/day-rollover handling; minute-only times assume truncation.
- Row numbering convention is a guess (documented above).

## What breaks first on real records
Free-text event classification (keywords like "stopped"/"arrived"), then multi-vehicle camera logs, then the 10-minute clock-error constant.
Memory: whole files are held in RAM (500k rows ~ 5 s here). No LLM path was built (optional); `mock_llm.py` is unused.
