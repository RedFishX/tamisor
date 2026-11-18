# Changelog

Format inspired by [Keep a Changelog](https://keepachangelog.com/en/1.1.0/). Versions follow semantic versioning;
before 1.0, a minor version may change behaviour.

## 0.1.0 — 2026-11-15

First version published under the name **Tamisor** (formerly FortiScope, then Shadowline). The repository is
distributed under the AGPL-3.0-or-later license, with a contributor agreement (CLA).

### Analysis
- Permissive rules, rules shadowed by an earlier rule (full or partial overlap) and rules without logging, with a
  remediation plan, a CLI command example and a reference to the Fortinet documentation.
- Import of a FortiGate configuration export (`show full-configuration`) or a CSV export from the console.
- Nested address and service groups, services by protocol and ports, VDOMs and IPv4/IPv6 analysed separately.
- Configuration score, priorities and finding families; overview per VDOM.
- Filter by usage count (hit count), findings acknowledged locally.

### Application
- Meeting mode: board of policies to discuss, full-screen session, keyboard decisions, minutes in Markdown or
  printable HTML.
- Comparison of two audits (added, modified and removed policies).
- Exports: findings CSV, standalone HTML report, remediation CLI commands.
- Interface in French and English; WCAG 2.2 AA accessibility target.
- Files are analysed in the browser (Web Worker) and are never transmitted.

### Continuous integration
- `tamisor` command: SARIF 2.1.0 and JSON reports, failure threshold, acknowledgements, comparison baseline.
  Exit codes: 0 success, 1 blocking findings, 2 usage or import error.
- Docker images `ghcr.io/redfishx/tamisor` (application) and `ghcr.io/redfishx/tamisor-cli` (CI command),
  published with every version.

### Extensions
- Neutral extension points (`registerEdition`) to host an edition that restricts or extends the application:
  locked features, checks before import and after analysis, banner, toolbar entry, additional export actions.
  With no edition registered, the application is complete.

### Changes from the pre-releases
- Renaming: the `fortiscope` command becomes `tamisor`. Preferences saved under `fortiscope-*` and
  `shadowline-*` are picked up automatically into `tamisor-*`.
- References to the CIS FortiGate benchmark were removed.
- Pre-releases published under the name Shadowline are no longer maintained.
