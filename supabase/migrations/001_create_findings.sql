create extension if not exists pgcrypto; -- extension so we can generate uuids

drop table if exists findings cascade;

-- Creates the "findings" table which will store the results of our security scans
create table findings (
    finding_id uuid primary key default gen_random_uuid(),

    -- Source info (scanner name, finding id from the scanner, and the scan id this finding belongs to)
    source_scanner text not null,
    source_finding_id text,
    scan_id text,

    -- Vulnerability info (title, description, category, CVE and CWE ids)
    title text not null,
    description text,
    vulnerability_category text,
    cve_ids text[] not null default '{}',
    cwe_ids text[] not null default '{}',

    -- Severity info
    severity_level text not null,
    severity_score numeric(3,1), -- CVSS score with one decimal place

    -- Target info (host affected vulnerability, URL, port, and protocol)
    target_host text,
    target_url text,
    target_port integer,
    target_protocol text,

    -- Scanner-specific data (JSONB format)
    evidence jsonb not null default '{}'::jsonb,
    remediation jsonb not null default '{}'::jsonb,
    metadata jsonb not null default '{}'::jsonb,
    raw_payload jsonb not null default '{}'::jsonb, -- original raw scanner data

    created_at timestamp with time zone not null default now(),
    updated_at timestamp with time zone not null default now(),

    constraint severity_level_check check(
        severity_level in (
            'critical',
            'high',
            'medium',
            'low',
            'informational' --lowest severity level
        )
    ),

    constraint target_protocol_check check(
        target_protocol is null or target_protocol in (
            'tcp',
            'udp',
            'http',
            'https'
        )
    )
    constraint findings_source_unique 
    unique(source_scanner, scan_id, source_finding_id)
);

-- Indexes for efficient querying
create index findings_source_scanner_idx on findings(source_scanner);

create index findings_scan_id_idx on findings(scan_id);

create index findings_severity_level_idx on findings(severity_level);

create index findings_target_host_idx on findings(target_host);

create index findings_vulnerability_category_idx on findings(vulnerability_category);

create index findings_created_at_idx on findings(created_at desc);

create index findings_cve_ids_gin_idx on findings using gin(cve_ids); -- GIN is a special index for querying of CVE IDs

create index findings_cwe_ids_gin_idx on findings using gin(cwe_ids);

-- create index findings_source_lookup_idx on findings(source_scanner, scan_id, source_finding_id);
-- alter table findings add constraint findings_source_unique unique(source_scanner, scan_id, source_finding_id);


-- Function
-- This function will be used to automatically update the "updated_at" column whenever a record is updated
create or replace function update_updated_at_column()
returns trigger as $$
begin
    new.updated_at = now();
    return new;
end;
$$ language plpgsql;

-- Trigger
create trigger update_findings_updated_at
before update on findings
for each row
execute function update_updated_at_column();

alter table findings
add column fingerprint text;

alter table findings
add column is_canonical boolean not null default true;

alter table findings
add column canonical_finding_id uuid references findings(finding_id);
