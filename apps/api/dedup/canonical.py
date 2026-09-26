from uuid import UUID, uuid4

from schemas.finding import Finding


def classify_findings(supabase, findings: list[Finding]) -> list[Finding]:
    """Set canonical flags and references using matching persisted fingerprints."""
    fingerprints = list(
        dict.fromkeys(finding.fingerprint for finding in findings if finding.fingerprint)
    )
    existing_by_fingerprint: dict[str, list[dict]] = {}

    if fingerprints:
        response = (
            supabase.table("findings")
            .select("finding_id,fingerprint,is_canonical,canonical_finding_id")
            .in_("fingerprint", fingerprints)
            .execute()
        )
        for row in response.data or []:
            fingerprint = row.get("fingerprint")
            if fingerprint:
                existing_by_fingerprint.setdefault(fingerprint, []).append(row)

    canonical_by_fingerprint: dict[str, UUID] = {}
    for fingerprint, rows in existing_by_fingerprint.items():
        canonical = next((row for row in rows if row.get("is_canonical")), None)
        canonical_id = (
            canonical.get("finding_id")
            if canonical is not None
            else next(
                (
                    row.get("canonical_finding_id")
                    for row in rows
                    if row.get("canonical_finding_id")
                ),
                None,
            )
        )
        if canonical_id is None and rows:
            canonical_id = rows[0].get("finding_id")
        if canonical_id:
            canonical_by_fingerprint[fingerprint] = UUID(str(canonical_id))

    for finding in findings:
        fingerprint = finding.fingerprint
        if not fingerprint:
            finding.is_canonical = True
            finding.canonical_finding_id = None
            continue

        canonical_id = canonical_by_fingerprint.get(fingerprint)
        if canonical_id is None:
            # Normalizers provide each finding's UUID; persistence keeps this ID
            # so duplicates in this batch can point to the first canonical row.
            if finding.finding_id is None:
                finding.finding_id = uuid4()
            canonical_id = finding.finding_id
            canonical_by_fingerprint[fingerprint] = canonical_id
            finding.is_canonical = True
            finding.canonical_finding_id = None
        else:
            finding.is_canonical = False
            finding.canonical_finding_id = canonical_id

    return findings