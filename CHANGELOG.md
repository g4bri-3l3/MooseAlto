# Changelog

All notable changes to MooseAlto are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project uses [Semantic Versioning](https://semver.org/).

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
