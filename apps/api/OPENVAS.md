# OpenVAS Connector — Documentation

Owner: Muneeb Musharaf
Last updated: 2026-09-27

This document covers the OpenVAS ingestion journey: reading raw OpenVAS
XML output, extracting the relevant fields, and normalising it into the
project's Unified Finding model. It's written so another developer (or
future-me) can pick this up without re-deriving anything from scratch.

## Where this fits in the pipeline

```
Raw OpenVAS XML → connectors/openvas.py → (list of raw dicts)
                → normalisers/openvas.py → Finding (Unified Finding model)
                → validation (Taha's ownership — not yet formally defined)
                → db/findings_repo.py → Supabase `findings` table
                → deduplication (Taha's ownership — not yet built)
```

## Status summary

- **Extraction and normalisation: complete and verified.** All 151
  `<result>` entries in the sample file parse and normalise
  successfully with zero failures (see Tests below).
- **Persistence: complete and verified against the live database.**
  Confirmed working end-to-end on 2026-09-27, after Rafue applied the
  missing `fingerprint` / `is_canonical` / `canonical_finding_id`
  migration to the production `findings` table (see "Resolved issues"
  below).
- **Validation:** no formal validation layer exists yet beyond
  Pydantic's own type-level checks (required fields present, severity
  coerced to a known value, malformed input handled without crashing).
  A dedicated validation layer is Taha's ownership per the delivery
  plan and hasn't been defined yet.
- **Deduplication:** not yet possible to test. Only a scaffold file
  (`dedup/fingerprint.py`) exists; the actual dedup logic hasn't been
  built. This is Taha's ownership, not part of this connector's scope.
- **No changes were made to shared logic.** `schemas/finding.py` and
  `db/findings_repo.py` were not modified — every fix described below
  is scoped entirely to `connectors/openvas.py` and
  `normalisers/openvas.py`.

## Files involved

- `connectors/openvas.py` — parses the raw OpenVAS XML into a list of
  plain Python dicts (one per `<result>`).
- `normalisers/openvas.py` — `OpenVASNormalizer` converts each raw dict
  into a validated `Finding` object.
- `schemas/finding.py` — the shared Unified Finding model (unmodified).
- `scripts/local_openvas_test.py` — manual, local-only script to
  quickly re-run the parse+normalise pipeline against the sample file.
  No network calls, no Supabase.
- `scripts/smoke_test_db.py` — manual end-to-end DB test (Section 3
  covers OpenVAS specifically: insert a real normalised finding into
  Supabase, read it back, verify, then delete it).
- `tests/test_openvas.py` — automated pytest regression suite; this is
  the one to run in CI or before any future change to these two files.
- `sample-data/openvas/openvas.xml` — the representative OpenVAS input
  file everything above is tested against.

## Expected input format

A standard OpenVAS XML report export. The connector looks for
`<result>` elements anywhere in the document (`root.findall(".//result")`)
and reads these child elements per result: `id` (attribute), `host`,
`port` (format `"<number-or-general>/<protocol>"`), `name`, `description`,
`severity`, `threat`, `.//cvss_base_vector`, `.//ref` (for CVE/URL
references), `.//oid`, `.//solution` (and its `type` attribute),
`.//qod/value`. Some results are software/version detection entries
rather than vulnerabilities — these lack a top-level `<name>` and
instead nest their description inside
`<details><detail><name>source_name</name><value>...</value></detail>`
(handled by the title fallback described below).

## Output format

`OpenVASNormalizer.normalize()` returns a `Finding` object (see
`schemas/finding.py`). Key fields for an OpenVAS finding:
`source_scanner="openvas"`, `title`, `description`, `severity_level`
(mapped from OpenVAS's Log/Low/Medium/High/Critical via
`SEVERITY_MAP`), `severity_score`, `target_host`, `target_port`
(nullable — see limitations), `target_protocol` (nullable — see
limitations), `cve_ids`, `raw_payload` (a dict: `{"raw_xml": "<original
<result> element as a string>"}`).

## How to run

From `apps/api`, with the venv active (`venv\Scripts\Activate.ps1` on
Windows) and dependencies installed (`pip install -r requirements.txt`
— note this now includes `defusedxml`, required by the connector):

Local parse+normalise check, no network:
```
python scripts/local_openvas_test.py
```
Expected: `Parsed 151 raw findings from the sample file` /
`Normalised OK: 151   Failed: 0`.

Automated regression tests:
```
pytest tests/test_openvas.py -v
```
Expected: 6 passed.

Live database round-trip (inserts one tagged test row into the real
Supabase `findings` table, then deletes it — safe to run, leaves
nothing behind as long as `CLEANUP_AFTER_TEST = True`, which is the
committed default):
```
python scripts/smoke_test_db.py
```
Expected: all three sections pass, ending with "No test rows left
behind."

## Bugs found and fixed

1. **General-port crash (silent data loss).** OpenVAS uses the literal
   value `"general"` (not a number) as the port for host-level findings
   not tied to a specific port (e.g. `general/tcp`). The connector's
   original `int(port_number)` call crashed on this, and the per-result
   `except` block silently dropped the result — 8 of 151 findings were
   lost with no visible error. Fixed by only converting to `int` when
   the value is actually digits, otherwise storing `None`.
2. **`raw_payload` type mismatch (100% normalisation failure).** The
   Unified Finding schema requires `raw_payload` to be a `dict`, but the
   OpenVAS connector was passing the raw XML through as a plain string.
   This failed Pydantic validation for every single OpenVAS finding.
   Fixed by wrapping it: `{"raw_xml": "<the XML string>"}` — matching
   how the ZAP connector already stores its raw evidence as a dict.
3. **Missing title on non-vulnerability results.** Some OpenVAS results
   are software/version detection entries (e.g. "TWiki Version
   Detection"), not vulnerabilities — they have no top-level `<name>`,
   which fails the schema's required `title: str` field. Fixed with a
   fallback: use the nested `<detail><name>source_name</name>` value if
   present, otherwise a generic `"OpenVAS finding (untitled)"`.
4. **Non-standard protocol labels.** A few host-level checks label the
   protocol half of `port` as a scan type rather than a real transport
   protocol (`icmp`, `CPE-T`, `SMBClient`), which fails the schema's
   `Literal["tcp", "udp", "http", "https"]` constraint. Fixed by
   treating anything outside that set as "no specific protocol" (`None`)
   rather than letting it fail validation.

## Known limitations

- The fallback title for detection-only results (`"OpenVAS finding
  (untitled)"`) is generic when no `source_name` detail is available.
  It prevents a crash but isn't as descriptive as a real vulnerability
  title.
- Testing has only been done against the one representative sample
  file (`sample-data/openvas/openvas.xml`). Other OpenVAS report
  variants or scanner versions haven't been tested and may expose
  further edge cases.
- No dedicated validation layer exists yet — only Pydantic's built-in
  type checks. Full validation rules (per the delivery plan) are
  Taha's ownership and haven't been defined.
- Deduplication is entirely untested for OpenVAS findings, as the
  dedup logic itself doesn't exist yet beyond a scaffold file.

## Resolved issues

- **Production DB schema mismatch (resolved 2026-09-27).** The live
  `findings` table was missing `fingerprint`, `is_canonical`, and
  `canonical_finding_id` columns that the schema (added in commit
  `04f4edf`) expected, causing every insert — for any scanner, not just
  OpenVAS — to fail with `PGRST204: canonical_finding_id column not
  found`. Rafue added the missing columns to production and verified
  constraints/keys were intact. Confirmed fixed by running
  `smoke_test_db.py` against the live database: all three sections
  (ZAP insert, ZAP upsert, OpenVAS insert) passed, with test rows
  properly cleaned up afterward.

## Other open items (not OpenVAS-specific, flagged separately)

- Ayoub's `cleanup-review` branch also modifies OpenVAS handling but
  has an unresolved severity mapping regression (every finding comes
  back `severity_level: "informational"` regardless of actual score)
  and deletes the `apps/web` folder. Flagged to Ayoub and Rafue
  directly; not merged into `main` as of this writing.
