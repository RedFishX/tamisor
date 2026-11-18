# Tamisor

A local tool that helps audit FortiGate policies. It flags highly permissive rules, rules entirely shadowed by an earlier rule, and rules without logging.

Each finding comes with a contextualized remediation plan, a CLI example to adapt and a link to the official Fortinet documentation. The recommendations follow, among others, the FortiOS policy matching criteria, their evaluation order and the principle of restricting sources, destinations and services.

> Independent tool for FortiGate®, not affiliated with Fortinet, Inc. FortiGate and FortiOS are trademarks of Fortinet.

## Deploying with Docker

```bash
docker compose up -d          # builds the image and serves the app on http://localhost:8080
PORT=9000 docker compose up -d   # another port
```

The image only contains static files served by nginx (non-root user, read-only file system, strict CSP headers
with `connect-src 'self'`). The analysis runs in the browser: no configuration is ever sent to the container,
which also rejects any request body.

Images are published on every push to `main` (`edge` tag) and on every version (`v*`, with the version number and
`latest`): `ghcr.io/redfishx/tamisor` (the app) and `ghcr.io/redfishx/tamisor-cli` (the CI command):

```bash
docker run --rm -v "$PWD:/work" ghcr.io/redfishx/tamisor-cli firewalls/fw-siege.conf --sarif tamisor.sarif
```

## Development

```bash
npm install
npm run dev
```

Then open `http://127.0.0.1:5173` and drop a `.conf` or `.txt` CLI export, or a `.csv` policy export.

To produce a usable export from the FortiGate CLI:

```text
show full-configuration
```

The configuration is analysed exclusively in the browser. It is not sent to any server.

The theme button in the header switches between light and dark. The preference is stored locally; without a saved preference, Tamisor follows the system theme.

CSV exports with a comma or semicolon separator are recognised. The usual FortiGate headers are accepted, including `Policy ID`, `Name`, `From`, `To`, `Source`, `Destination`, `Schedule`, `Service`, `Action`, `NAT`, `Security Profiles`, `Log Traffic` and `Status`. GUI exports that use a combined `Policy` column formatted as `Name (ID)` and section rows are also supported.

The Critical alerts, Permissive rules and Shadowed rules counters filter the findings directly. Click the active counter a second time to show all results again.

The risk profile can be set to Standard or Strict. A finding's detail mostly presents a business matrix for each element of the rule: interfaces, sources, destinations, services, schedule, action, NAT, security profiles and logging. Each row shows a low, medium or high level, the value concerned and an operational justification, without exposing the scoring formula.

The "Hit count" filter groups policies by usage band (never, low, medium, high). It is only available with a CSV export that contains the `Hit Count` column. Findings can be acknowledged locally and restored with the `Show acknowledged` option. A second configuration can be selected with `Compare` to count added, modified and removed policies. CSV exports can also provide `Hit Count` and `Last Used`.

The `Export` menu groups the findings CSV, the interactive HTML report and the CLI commands. The standalone report reuses Tamisor's visual language, lets you search and filter findings, expand their detail and print cleanly. The CLI export gathers the remediation commands separately, to be reviewed and adapted before applying them.

From a finding's detail, the Markdown documentation action opens a sheet dedicated to the selected policy, ready to copy. It explains its traffic direction, its criteria, its usage statistics and all of its findings with their recommendations. No file is downloaded.

The CLI examples are suggestions, not commands to apply blindly. Back up the configuration, check the counters and the Policy Match, then test every change on a controlled scope.

## Meeting mode

The "Meeting" tab prepares and runs the team review of the rules. Each kanban card represents a policy and gathers all of its findings. The columns are: To discuss, Delete, Modify, Keep and Postpone.

- **Preparation**: the board fills itself with every policy that has at least one open finding (findings on unreferenced objects are excluded). A policy whose findings are all acknowledged leaves the board, unless its card has already been worked on (note, decision). The "To discuss" column is arranged in collapsible groups: Proposed: delete, Proposed: modify, Proposed: keep, No proposal. Dragging a card from one group to another changes the proposal. Within each group, policies are sorted by ascending hit count, then by severity; "Sort by priority" restores this order after manual moves. The meeting follows this order. Cards show the hit count and each accepts a note.
- **Meeting**: "Start the meeting" opens a full-screen sheet. On the left, the agenda lists policies by proposal with their state (✓ decided, ↷ postponed, ● in progress) and their hit count; a click opens the chosen policy. In the centre, the prepared proposal is coloured (red delete, amber modify, green keep) with the usage argument and the preparation note, then the flow (interfaces, addresses, service) and the findings. At the bottom, an always-visible decision bar gathers the buttons, the justification and the due date. Decisions are made with `D`, `M`, `K`, `P`, and `←`/`→` change policy. On the board, a card moves by drag and drop or with the `1` to `5` keys.
- **Minutes**: they are produced as Markdown (to copy or download) or as printable HTML, with policies grouped by decision.

The board is saved in the browser's `localStorage`, per file name. After a new import, a policy that no longer exists stays on the board and is flagged there. "Reset the board" clears notes and decisions and rebuilds the board from the open findings.

## Compliance and history

Each finding shows the requirements of the relevant frameworks (PCI-DSS v4.0, ANSSI), in the detail, the CSV export, the HTML report and the Markdown documentation. The mapping is indicative.

After each import, the overall score and the counters (never the content of the configuration) are saved in IndexedDB, in the browser. The audit history panel shows the evolution per file name.

## Detection

- A rule is permissive when at least two significant dimensions are global (`all`, `ALL` or `any`).
- A rule is shadowed when an active `accept` rule placed before it fully covers its interfaces, addresses, services and schedules. The evidence details each dimension compared. Services are modelled by protocol, destination ports and source ports. TCP, UDP and SCTP remain distinct; ICMP and ICMP6 use their types and codes; `IP` services use their protocol number; nested groups are expanded recursively. An unknown service only covers another by explicit identity, and only `ALL` in the earlier rule covers all services.
- A rule has a partial overlap when its address and service space intersects an earlier rule without being entirely covered.
- Address and service groups are expanded recursively.
- IPv4 subnets, IP ranges and the port ranges of custom services are compared by their real bounds.
- VDOMs are analysed independently to avoid identifier collisions and false shadowing between contexts.
- IPv4 and IPv6 policies are analysed separately, including the global values `all_ipv4` and `all_ipv6`.
- Policies with a strictly equivalent scope are distinguished from rules that are merely shadowed.
- VIPs published from all sources are flagged; the IP pools and Internet Services associated with policies are kept in the analysis.
- Disabled rules are excluded from the findings.

The analysis remains deliberately conservative for dynamic objects and NAT features that cannot be resolved from the policy table alone.

## Continuous integration (SARIF / JSON)

Tamisor can audit a versioned configuration on every merge request. The `tamisor` command produces a **SARIF 2.1.0** report (shown by GitHub code scanning, and read by Azure DevOps, SonarQube or DefectDojo) and a Tamisor-specific **JSON** report, then fails the job if findings exceed a threshold. Both formats are also available in the app, under the Export menu.

```bash
npm run build:cli            # produces dist-cli/tamisor.mjs: a single file, Node 20 or later, no dependency
node dist-cli/tamisor.mjs firewalls/fw-siege.conf \
  --sarif tamisor.sarif --json tamisor.json \
  --fail-on high \
  --acknowledgements tamisor-acknowledgements.json \
  --baseline baseline.json
```

| Option | Purpose |
| --- | --- |
| `--fail-on` | Severity from which an open finding fails the job: `critical`, `high` (default), `medium`, `low` or `none`. |
| `--acknowledgements` | Acknowledgements exported from the app: these findings do not block and appear as *suppressions* in the SARIF. An acknowledgement whose review date has passed no longer protects. |
| `--baseline` | JSON report of the target branch: only new findings block (`new` / `unchanged` state in the SARIF). Missing file: analysis without a reference. |
| `--source-uri` | Path of the file in the repository, used in the reports. |
| `--lang` | Language of the findings, `fr` (default) or `en`. |

Exit codes: `0` threshold respected, `1` blocking findings, `2` usage or import error. The summary printed in the log lists the blocking findings with `file:line`.

Each finding of a CLI export points to the `edit` line of the policy or object concerned (VDOM and IPv6 included); a CSV export points to the file without a line. The finding identifier serves as the SARIF fingerprint: the same finding is tracked from one analysis to the next.

Two ready-to-adapt examples are provided in `examples/ci/`: `gitlab-ci.yml` and `github-code-scanning.yml`. They recompute the baseline from the target branch's file (`git show`), so a merge request only fails on the findings it introduces, and they do not block the main branch (reports only). GitLab does not display SARIF in the merge request: the reports are published there as artifacts.

## Language

The interface is available in French and English. Findings, recommendations, compliance mappings, exports and the meeting minutes are translated too. On first launch, the language follows the browser's; the `EN` / `FR` button in the top bar changes it and remembers it.

Changing language reloads the page. The file being analysed is handed to the tab's `sessionStorage` for the duration of the reload, then erased as soon as it is read back and re-analysed in the new language. If the file is too large for this storage, the app warns that it will need to be imported again.

Finding identifiers do not depend on the language: acknowledgements and the meeting board remain valid from one language to the other. Texts entered by the user (meeting title, notes, justifications) are not translated.

## Accessibility

The app targets WCAG 2.2 AA:

- **Keyboard**: skip link to the content, keyboard tabs (`←`/`→`, `Home`/`End`), shortcuts in the findings list (`/`, `J`/`K`, `A`, `C`), meeting cards moved with `1` to `5` as an alternative to drag and drop, meeting decisions from the keyboard (`S`/`M`/`C`/`R` in French, `D`/`M`/`K`/`P` in English). Dialogs are modal and return focus to the originating element.
- **Screen readers**: document language declared, landmarks (`main`, named regions), dialogs named by their title, an `aria-live` region that announces the end of an analysis, the number of findings after a filter, a card move and each meeting decision.
- **Readability**: contrast of at least 4.5:1 in light and dark themes, layout without horizontal scrolling down to 320 px wide, animations disabled if the system asks to reduce motion.

The audit was done with axe-core (WCAG 2.0 to 2.2 A/AA rules and best practices) on every view and every dialog, in both themes and both languages, with no remaining violation, then completed with a keyboard walkthrough. `src/presentation/accessibility.test.ts` protects these fixes against regressions. A test with a real screen reader (NVDA, VoiceOver) is still recommended before a wide release.

## Verification

```bash
npm test
npm run build
```

## Editions

Tamisor follows an "open core" model, like Grafana or GitLab: this repository contains the complete tool, and a
paid hosted service, developed separately, funds the project.

**What stays in the open source edition.** Everything a person auditing a firewall needs: analysis, findings and
remediations, meeting mode and minutes, exports (CSV, HTML, CLI commands, SARIF, JSON), configuration comparison,
local history and the CI command. Self-hosted, it has no file size limit specific to the demo, no quota and no
locked feature.

**What the hosted service adds.** What it takes to work as a team or without installing anything: ready-to-use
hosting, and features that serve an organisation rather than a single user, such as shared history and
acknowledgements, tracking several firewalls over time or reports branded for a consultancy. This code is not
published here.

**Our commitments.**

- A feature published in this repository is never removed from it to become paid.
- The limits of the online demo (file size, number of analyses per day, reserved features) only apply to that
  demo, never to the open source edition.
- The analysis runs in the browser in both editions: your configuration files are not sent to any server.
- Fixes and improvements to the analyser are published here, not reserved for the hosted service.

## License

Tamisor is free software distributed under the [GNU AGPL-3.0-or-later](LICENSE). If you offer a modified version
to users over a network, you must give them access to its source code. Third-party components and their licenses
are listed in [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md). Contributions are accepted under the [CLA](CLA.md)
(see [CONTRIBUTING.md](CONTRIBUTING.md)).

The tool helps with auditing but does not guarantee that the findings are exhaustive: it is provided "as is",
without warranty (sections 15 and 16 of the license).
