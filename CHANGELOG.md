# Changelog

All notable changes to MooseAlto are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project uses [Semantic Versioning](https://semver.org/).

## [1.9] - 2026-09-09
### Added
- A fourth chart in Rule Statistics: allow rules by internal-only vs internet-touching (either direction), a simpler two-way split of the same classification the existing four-way Direction chart already used, so "how much of this ruleset is even internet-relevant" doesn't require mentally adding three of that chart's four slices together.
### Fixed
- The Direction chart's internet classification now uses the same Test-SideIsInternet logic as the rest of the tool (the zone="any" weaker-evidence handling, the private-address override, etc.).

## [1.8] - 2026-09-07
### Added
- Port 80 (HTTP) added to the risky-port list, marked cleartext like FTP/Telnet/etc. Previously absent entirely, not just excluded from the cleartext subset.
- MITRE ATT&CK tagging: when the optional Gemini step runs, findings that clearly correspond to a well-known technique get tagged with its ID, name, and tactic in a new column, shown only when at least one finding has been tagged. The model is instructed to skip a finding rather than force a speculative or overly generic tag.
- Interactive setup now ends with a review-and-edit loop once the guided question sequence completes: every parameter is listed with its current value, and typing a number or a parameter name (by either, case-insensitive) lets you change just that one setting and come back to the list, instead of having to restart the whole wizard to fix one answer. Press Enter with no changes to proceed.
- Large rulesets that produce enough findings to risk exceeding Gemini's free-tier input-token quota are now automatically split into multiple smaller batches, sent one after another, with results merged afterward. A console note explains when this kicks in. Batches are spaced more than 60 seconds apart, since the quota that matters is cumulative per minute, not per request. Sending several comfortably-sized batches only a few seconds apart can still trip the same quota this batching exists to avoid.
### Changed
- The Suggested Fix column now only appears when the optional Gemini step actually runs.
### Fixed
- Direction classification (Test-SideIsInternet) no longer treats a rule as internet-facing purely because its zone is "any" if the address field on that same side is exclusively a specific, plain private IP/CIDR - PAN-OS matches zone and address together on a rule, not either alone.
- The same zone="any" issue fixed earlier for direction classification (Test-SideIsInternet) was also present, independently, in three places that compute their own "which dimensions are open" list without going through that function: unrestricted_access_to_critical_zone, unrestricted_egress_from_critical_zone, and internet_exposed_any_field. All three were counting a zone field as unrestricted just because it said "any", even when the address field on that same side was a specific, bounded subnet that would have narrowed the actual matched traffic considerably. Fixed the same way: a zone="any" signal only counts as open when the address on that side doesn't already narrow it down.

## [1.7] - 2026-08-31
### Added
- Suggested Fix column on the Algorithmic-based Findings table, shown whenever at least one finding has one. Filled in automatically (no AI needed) for finding types with an obvious, context-free next step: disabled_rule_present / rule_usage_unused / stale_last_hit (candidates for removal, confirm with the rule owner), duplicate_rule / shadowed_rule (remove, covered by an earlier rule), and temporary_tag_but_broad_rule / temporary_tag_still_present (confirm still needed, remove tag or rule if not). When the optional Gemini step runs, the same prompt also asks for a plausible App-ID guess specifically for any_any_any_allow, outbound_defined_dest_any_app, and port_based_rule_missing_app_id findings, based on the rule's name, its Tags (if included), and any port already visible in the finding text. AI guesses are clearly prefixed "AI guess (verify):" and are never applied automatically; a finding is left without one if there's no real hint in the name/ tags/port to go on rather than guessing something generic. Applying a suggestion (deterministic or AI) rebuilds the report from the already-computed findings, no re-detection involved.
- Table columns on the Findings and Inventory tables can now be dragged to a new position by their header label (distinct from the resize handle on the right edge of each header). Moving a column reorders it consistently across the header, the filter row, and every data row, so filtering keeps working correctly regardless of column order. Works with both mouse and touch.
### Fixed
- internet_exposed_any_field no longer counts Application left as "any" as an open dimension when Service is pinned to a specific port (e.g. tcp/8080). That combination is a port-based rule, not a wide-open one, and was already its own finding (port_based_rule_missing_app_id); counting it here too overstated how open the rule actually was. Application still counts normally when Service is also effectively any.
- outbound_defined_dest_any_app had the same issue as the fix above, and is fixed the same way: Application left as "any" only counts as unrestricted when Service is also effectively any, not when Service is pinned to a specific port.
- The same Application/Service issue as the two fixes above was also present in five more places, found by systematically re-checking every spot that looks at whether Application is "any": unrestricted_access_to_critical_zone, unrestricted_egress_from_critical_zone, temporary_tag_but_broad_rule (which was also missing a Service check entirely, not just misapplying one), broad_internal_exposure (which used a plain null check on Service instead of the shared effectively-any helper, missing the application-default-with-no-app edge case too), and missing_explicit_intrazone_internet_deny (the mirror situation: a Deny rule with Application=any but Service pinned to one port doesn't actually block all traffic between the zone and itself, so it shouldn't count as satisfying the "explicit deny" requirement either). All five fixed the same way, reusing the shared Service-effectively-any check.
- Direction classification (Test-SideIsInternet, which most findings key off of) no longer treats a rule as internet-facing purely because its zone is "any" if the address field on that same side is exclusively a specific, plain private IP/CIDR. PAN-OS matches zone and address together on a rule, not either alone, so a rule scoped to zone="any" but a concrete private host (e.g. 10.5.5.10/32) can never actually be reached from internet, no matter how broad the zone field looks by itself. A specifically-named internet zone (e.g. Untrust) is unaffected by this and still counts as before; so does any address that's public, negated, a range, or an unresolved object name, only an unambiguous, exclusively-private plain IP/CIDR overrides the zone="any" signal.
- inbound_risky_application / outbound_risky_application / internal_risky_application now also check the Service field for a risky application name, not just Application. Real, especially older, rulebases sometimes use a custom-named Service object literally named after the protocol instead of, or alongside, App-ID (e.g. a Service named "smtp") - a pre-App-ID naming convention that was previously invisible to these checks entirely, since Service was only ever scanned for port numbers. Also matches a name with a port or other suffix appended to it (e.g. "smtp-25", "SMTP_Relay_25"), by checking each sub-token split the same way rule names are tokenized elsewhere in this file, not just an exact whole-field match.

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
