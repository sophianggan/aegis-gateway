# Security policy

## Reporting

Please report suspected vulnerabilities privately through GitHub Security Advisories for
this repository. Include a minimal reproduction with synthetic data, the affected version,
and expected impact. Do not include live credentials or regulated records.

## Supported versions

Until the first stable release, security fixes are applied to the latest commit on `main`.

## Design expectations

Security changes should include a regression case in `tests/redteam` or a focused unit or
integration test. Pull requests must pass static analysis, the standard suite, the
adversarial gate, dependency audit, and container build.

