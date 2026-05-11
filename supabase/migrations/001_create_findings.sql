create extension if not exists pgcrypto;

create table findings (
  finding_id uuid primary key default gen_random_uuid(),

  source jsonb not null,
  vulnerability jsonb not null,
  severity jsonb not null,
  target jsonb not null,

  evidence jsonb not null default '{}'::jsonb,

  remediation jsonb not null,

  metadata jsonb not null default '{}'::jsonb,

  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create index findings_scan_id_idx
on findings ((source->>'scan_id'));

create index findings_scanner_idx
on findings ((source->>'scanner'));

create index findings_severity_idx
on findings ((severity->>'level'));

create index findings_host_idx
on findings ((target->>'host'));

create index findings_category_idx
on findings ((vulnerability->>'category'));

alter table findings
add constraint severity_level_check
check (
  severity->>'level' in (
    'critical',
    'high',
    'medium',
    'low',
    'informational'
  )
);

alter table findings
add constraint protocol_check
check (
  target->>'protocol' in (
    'tcp',
    'udp',
    'http',
    'https'
  )
);

create or replace function update_updated_at_column()
returns trigger as $$
begin
  new.updated_at = now();
  return new;
end;
$$ language plpgsql;

create trigger update_findings_updated_at
before update on findings
for each row
execute function update_updated_at_column();