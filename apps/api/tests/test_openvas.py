from connectors.openvas import parse_openvas_file


findings = parse_openvas_file(
    "sample-data/openvas/openvas.xml"
)

with open(
    "openvas_findings.txt",
    "w",
    encoding="utf-8",
) as output_file:
    print(
        f"Number of findings: {len(findings)}",
        file=output_file,
    )

    for finding in findings:
        print(
            finding.model_dump(),
            file=output_file,
        )