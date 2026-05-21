-- Adds unique constraint to the findings table to ensure that the combination of source_scanner, scan_id, and source_finding_id is unique.
-- To be used for deduplication of findings from the same source scanner and scan
alter table findings
add constraint findings_natural_key_unique
unique nulls not distinct (source_scanner, scan_id, source_finding_id);