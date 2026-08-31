# Changelog

All notable changes to MooseAlto are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project uses [Semantic Versioning](https://semver.org/).

## [1.6] - 2026-08-31
### Added
- outbound_icmp_to_unrestricted_destination: outbound rule permits ICMP-family traffic (App-ID ping, icmp, ipv6-icmp, or traceroute, or a Service object literally named icmp as a fallback) to an unrestricted destination (any, or effectively any via the RFC1918 idiom). ICMP is often overlooked by inspection compared to TCP/UDP traffic; data can be encoded in echo/payload fields to exfiltrate data or maintain a covert C2 channel. Not flagged when the destination is scoped to specific, known hosts.

## [1.5] - 2026-08-28
### Added
- Report tables now scroll horizontally within their own container instead of widening the whole page, with native touch-swipe support on modern mobile browsers (no extra code needed for that part, overflow-x: auto handles it).
- Source and Destination columns are truncated with an ellipsis by default and show the full value on hover via a native tooltip, so a cell listing many negated ranges or individually-enumerated addresses no longer forces the whole table wide enough to bury the Type/Detail columns behind a wall of scrolling.
- All table columns are now resizable by dragging a handle on the right edge of each header, starting from the browser's own content-based width. Works with both mouse and touch.
### Fixed
- oversized_address_list now counts how many tokens the rule author actually wrote in Source/Destination (e.g. two group names), not how many individual addresses those resolve to after -AddressObjectsCsv/-AddressGroupsCsv expansion. A rule referencing a couple of well-organized, clearly-named groups isn't the same audit concern as one with dozens of individual addresses pasted directly into the field, even if the resolved count comes out the same. The pre-resolution count is captured on each rule before resolution overwrites the address list.

## [1.4] - 2026-08-27

### Added
- all_rfc1918_effectively_private: an address field listing all three private RFC1918 ranges positively together (e.g. 10.0.0.0/8;172.16.0.0/12;192.168.0.0/16), functionally equivalent to "any private address" even though no token literally says "any" and none of them is individually broad. The mirror case of negated_rfc1918_effectively_public, and not caught by broad_internal_exposure, which only looks for a field that's entirely empty/"any," not one whose listed values happen to add up to the same thing.
### Fixed
- internet_exposed_any_field, broad_internal_exposure, unrestricted_access_to_critical_zone/_egress_from_critical_zone, and the temporary-tag broad/narrow classification now recognize a negated- or positive-RFC1918 address field as "effectively any" for their own dimension-counting and severity-escalation logic, not just a literal empty/"any" field.

## [1.3] - 2026-08-24
### Added
- Created and Modified columns on the Algorithmic-based Findings table, Internet Exposure Inventory, and findings CSV export, shown only when the source CSV actually has them.
### Changed
- Report visual refresh: warm color palette, refined severity row styling, stat cards with a subtle accent border and shadow, and amber-toned section dividers.

## [1.2] - 2026-08-22
### Added
- rule_name_action_mismatch: flags a rule whose name suggests it denies/blocks traffic (contains a token like "deny", "block", "drop") but is actually configured to allow it, or vice versa (a name suggesting "allow"/"permit" on a rule that's actually deny/drop). A rule renamed or toggled without the other catching up is easy to miss on a quick read and easy to trust incorrectly. Matched by exact token, not substring; rules whose name contains both a deny-style and an allow-style token are skipped as ambiguous rather than guessed at.
### Fixed
- The double-quote-wrap CSV repair now applies iteratively instead of once. The repair now loops until the line no longer matches the wrapped signature, capped at 5 passes, with a second check (a minimum count of "" pairs in the line) to avoid misfiring on a normal, unwrapped CSV that happens to start with a short quoted field (this could be fired depending on witch device the export is done from).

## [1.1] - 2026-08-21
### Added
- oversized_address_list: flags a rule listing more than -MaxAddressListSize (default 25) individual addresses in source or destination. A large enumerated address list is just as hard to audit as an unrestricted one, even though nothing in it literally says "any".
- no_logging_enabled: flags an allow rule with no evidence of logging in the Options field. Only runs when the Options column both exists and has been confirmed to carry logging information somewhere in the ruleset, to avoid false positives on export types that don't include this detail at all.
- New -MaxAddressListSize parameter (default 25).
- CompareTo <path>: compares the current run's findings against a previous run's findings CSV, matched by (rule name, finding type). Adds a Comparison column to the Algorithmic-based Findings table (New / Resolved / Still present, color-coded), plus summary stat cards. Findings resolved since the previous run (no longer present now) are added as their own rows sourced from the previous CSV, sorted into the table by severity alongside everything else rather than shown separately.
- Four more Rule Statistics tables/charts: most common finding types (which check fires most often, not just which severity), the rules generating the most findings, most common tags (plus a count of rules with no tags at all), and an App-ID vs port-based vs fully-open pie chart for allow rules.

## [1.0] - 2026-08-20

### Added

- Initial release.
