# Rsky

Rsky is a proof of concept for processing and managing security vulnerability findings.

The current working feature focuses on **OpenVAS report ingestion**: reading OpenVAS XML reports, extracting relevant vulnerability information, converting findings into a common data format, and saving them to a Supabase database.

This README explains how to set up and test the OpenVAS feature.

## Current Status

| Component                                         | Status                                                  |
| ------------------------------------------------- | ------------------------------------------------------- |
| OpenVAS XML parsing                               | Implemented and tested                                  |
| Finding normalisation                             | Implemented and tested                                  |
| Supabase persistence                              | Verified against the live database on 27 September 2026 |
| Automated OpenVAS tests                           | Test suite available                                    |
| Dedicated validation layer                        | Not yet implemented                                     |
| Deduplication                                     | Not yet implemented                                     |
| Frontend dashboard                                | Not included in the current scope                       |
| Contextual risk prioritisation and AI/ML features | Not included in the current scope                       |

## How the OpenVAS Feature Works

The ingestion workflow is:

1. **Input:** An exported OpenVAS XML report.
2. **Parsing:** The connector extracts individual scan results and their relevant fields.
3. **Normalisation:** The results are converted into Rsky's shared `Finding` model.
4. **Persistence:** Normalised findings can be stored in the Supabase `findings` table.

Extracted information includes finding titles, descriptions, severity, affected hosts, ports, protocols, CVE identifiers, and the original XML evidence.

## Prerequisites

Before running the feature, ensure you have:

* Python installed.
* Access to the Rsky repository.
* The dependencies listed in `apps/api/requirements.txt`.
* The supplied OpenVAS sample report in `apps/api/sample-data/openvas/openvas.xml`.
* Supabase credentials and the required environment configuration for database testing.

The commands below assume you are running them from the `apps/api` directory.

## Setup

### 1. Navigate to the backend

From the repository root, run:

```bash
cd apps/api
```

### 2. Create and activate a virtual environment

Create the environment if one does not already exist:

```bash
python -m venv venv
```

On Windows PowerShell:

```powershell
.\venv\Scripts\Activate.ps1
```

On macOS or Linux:

```bash
source venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

The requirements include `defusedxml`, which is used by the OpenVAS connector.

## Run and Test the OpenVAS Feature

### Test 1: Local parsing and normalisation

Run:

```bash
python scripts/local_openvas_test.py
```

This processes the supplied sample report locally. It does not connect to Supabase.

**Expected result:**

* 151 raw findings parsed.
* 151 findings successfully normalised.
* 0 failures.

This verifies that the sample XML can be processed into Rsky's standard finding format.

### Test 2: Automated regression tests

Run:

```bash
pytest tests/test_openvas.py -v
```

**Expected result:** 6 tests pass.

These tests check the OpenVAS processing logic against the implemented test cases.

### Test 3: Database integration

Run:

```bash
python scripts/smoke_test_db.py
```

This script tests database operations, including inserting and retrieving findings, upsert behaviour, and inserting an OpenVAS finding into Supabase.

**Previously recorded result:** On 27 September 2026, all three sections of the database smoke test passed against the live database, and the temporary test records were cleaned up.

**Important:** This script writes to the configured database and attempts to delete its test records afterwards. Before running it, verify the database configuration and confirm `CLEANUP_AFTER_TEST = True`. Use an authorised test environment wherever possible.

## Test Results and Coverage

The OpenVAS connector was tested against the representative report at:

`sample-data/openvas/openvas.xml`

The implementation handles several input variations, including:

* Results without a numeric port.
* Findings whose original XML evidence must be preserved.
* Detection results that lack a standard finding title.
* Non-standard protocol labels that cannot be represented by the shared finding schema.

The current test results demonstrate successful processing of the supplied sample, but other OpenVAS report formats and scanner versions have not yet been verified.

## Known Limitations

The current implementation has the following limitations:

* **Validation:** There is no dedicated validation layer beyond the existing Pydantic model checks.
* **Deduplication:** The full deduplication logic has not been implemented; only a scaffold exists.
* **Frontend:** A user-facing dashboard is not part of the current working scope.
* **Risk prioritisation:** The planned contextual ranking and explainability functionality is not complete.
* **AI/ML:** The planned machine-learning and AI-assisted enrichment features are not included in the current implementation.

## Project Structure

Relevant files for the OpenVAS feature:

```text
apps/api/
├── connectors/
│   └── openvas.py
├── normalisers/
│   └── openvas.py
├── schemas/
│   └── finding.py
├── db/
│   └── findings_repo.py
├── scripts/
│   ├── local_openvas_test.py
│   └── smoke_test_db.py
├── tests/
│   └── test_openvas.py
├── sample-data/
│   └── openvas/
│       └── openvas.xml
└── requirements.txt
```

* `connectors/openvas.py` reads the OpenVAS XML report.
* `normalisers/openvas.py` converts extracted results into the shared finding model.
* `schemas/finding.py` defines the common finding structure.
* `db/findings_repo.py` provides database persistence operations.
* `scripts/local_openvas_test.py` runs the local processing check.
* `scripts/smoke_test_db.py` verifies database operations.
* `tests/test_openvas.py` contains automated regression tests.

## Troubleshooting

**The local test cannot find the sample file**

Run commands from `apps/api` and verify that `sample-data/openvas/openvas.xml` exists.

**Dependency or import errors**

Activate the project's virtual environment and install the requirements again.

**Database errors involving missing columns or credentials**

Check the configured Supabase credentials and confirm that the database schema matches the application's migrations. Do not apply database changes blindly to a shared or production database.

**Automated tests fail**

Review the reported test failure and compare the current implementation with the expected behaviour documented in the OpenVAS connector guide.

## Contributing

1. Create a feature branch.
2. Make changes within the relevant component.
3. Run the OpenVAS regression tests.
4. Run the local processing test.
5. If database behaviour changes, run the appropriate database tests against an authorised test environment.
6. Commit and communicate changes that affect shared code or other contributors' work.

## License

See the repository's `LICENSE` file for licensing terms.
