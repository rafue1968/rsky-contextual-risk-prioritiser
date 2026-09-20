# local_openvas_test.py
#
# PURPOSE: Reproduce and verify the OpenVAS normalisation bug entirely locally, with zero network calls.
# — This does NOT touch Supabase in any way 
# — It only runs the parser and normaliser against the sample XM

import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parents[1]))

from connectors.openvas import parse_openvas_file   # turns raw XML into a list of plain dicts
from normalisers.openvas import OpenVASNormalizer    # turns each dict into a validated Finding object

# Path is relative to apps/api 
raw = parse_openvas_file("../../sample-data/openvas/openvas.xml")
print(f"Parsed {len(raw)} raw findings from the sample file")

# Track how many findings make it through normalisation successfully
# vs how many raise an exception, so we get a clear pass/fail count
# instead of just a wall of stack traces.
normaliser = OpenVASNormalizer()
ok = 0
failed = 0

for f in raw:
    try:
        # This is the line that currently crashes — normalize() builds
        # a Finding object, and the raw_payload field is where the bug lives.
        finding = normaliser.normalize(f)
        ok += 1
    except Exception as e:
        failed += 1
        # Only print the full error once — if all 143 findings fail
        # for the same reason, we don't need to see it 143 times.
        if failed == 1:
            print(f"\nFirst failure (type: {type(e).__name__}):\n{e}\n")

# Final summary — this is the number that tells us whether the fix worked.
# Before the fix: ok=0, failed=143 (or whatever the current sample size is).
# After the fix: ok should equal the total parsed count, failed=0.
print(f"\nNormalised OK: {ok}   Failed: {failed}")