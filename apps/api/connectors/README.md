# Connector Walkthrough - Ayoub

Connectors ingest findings from external security tools, and convert their native export formats into a raw findings structure.

Connector layout should make use of common components and:

- Read tool-specific files or API responses
- Parse input safely
- Extract the relevant fields
- Preserve other fields where useful
- Return raw findings before normalisation, deduplication, or scoring
- Log failiures.

## Structure

```text
connectors/
├── openvas.py
├── zap.py
└── README.md
```

## OpenVAS connector

```python
parse_openvas_file(file_path: str) -> list[dict]
```

Accepts path to an OpenVas XML export, returns a list of extracted vuln findings.

I think this is local-only so far, would need to be migrated to be compatible w/ api

### XML

Exports are XML. Parsing uses:

```python
from defusedxml.ElementTree import parse as safe_parse
```

The standard xml module is used for logging, and the raw field.

### Extracted Fields

| Output field    | OpenVAS XML source          | Notes                                                 |
| --------------- | --------------------------- | ----------------------------------------------------- |
| `source`        | Set in code                 | Always `"openvas"`                                    |
| `raw_id`        | `<result><id>`              | Original OpenVAS result identifier                    |
| `host`          | `<result><host>`            | Hostname or address reported by OpenVAS               |
| `ip`            | `<result><host>`            | Currently identical to `host`                         |
| `port`          | `<result><port>`            | Extracted as an integer from values such as `443/tcp` |
| `protocol`      | `<result><port>`            | Extracted from values such as `443/tcp`               |
| `title`         | `<result><name>`            | Vulnerability/finding name                            |
| `description`   | `<result><description>`     | OpenVAS finding description                           |
| `severity`      | `<result><severity>`        | Raw severity value from the export                    |
| `threat`        | `<result><threat>`          | OpenVAS threat label                                  |
| `cvss_score`    | `<result><severity>`        | Currently converted to `float` where possible         |
| `cvss_vector`   | `<cvss_base_vector>`        | CVSS base vector where available                      |
| `cve`           | `<ref type="cve" id="...">` | List because a finding can have multiple CVEs         |
| `references`    | `<ref type="url" id="...">` | List of URL references                                |
| `nvt`           | `<oid>`                     | OpenVAS NVT/OID identifier                            |
| `solution`      | `<solution>`                | Suggested remediation                                 |
| `solution_type` | `<solution><type>`          | Remediation type                                      |
| `qod`           | `<qod><value>`              | Quality of Detection score                            |
| `raw`           | Serialised `<result>` XML   | Retained for traceability and debugging               |

### Processing stages

```text
OpenVAS XML export
      ↓
openvas.py connector
      ↓
Raw finding dictionaries
      ↓
Normalisation
      ↓
Deduplication
      ↓
Contextual risk prioritisation
      ↓
Database/API
```
