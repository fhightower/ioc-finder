# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/).

## [7.3.0] - UNRELEASED

### Changed

- To speed URL parsing, we no longer parse URLs with `userinfo "@"` in the authority (see [URL syntax guide for more details](https://en.wikipedia.org/wiki/URL#Syntax))
  - Our reasoning is that userinfo is rarely present
  - If you have concerns about this change or would like to see it added back in (it could be optionally enabled), please raise an issue

## [7.2.4] - 2022.08.25

### Fixed

- URL boundary to better respect the conventions of human language regarding quotation marks and parentheses ([#130](https://github.com/fhightower/ioc-finder/issues/130))

## [7.2.3] - 2022.07.14

### Fixed

- Update required version of [ioc-fanger](https://github.com/ioc-fang/ioc-fanger) which fixes issues with non-http(s) URL schemes ([#255](https://github.com/fhightower/ioc-finder/issues/255))

## [7.2.2] - 2022.07.08

### Fixed

- Poorly designed grammars which were SIGNIFICANTLY slowing down this project ([#250](https://github.com/fhightower/ioc-finder/pull/250))
  - **🎉 This update improves mean run-times by [≈70%](https://github.com/fhightower/ioc-finder/pull/253/files#diff-8e67b346e4b32f0cd637dbd271c16ab649c05fdf6aa7fe443cc85c0d8ca6ad07R149)!**
  - Thanks to @ptmcg for his contribution!

## [7.2.1] - 2022.07.05

### Fixed

- Removed duplicative function calls

## [7.2.0] - 2022.06.20

### Changed

- *Possible breaking change:* Update required pyparsing version to [v3](https://github.com/pyparsing/pyparsing/blob/966d6fded149c6c11993746b0d72166bc04e4504/CHANGES#L49)
  - Although there are no public API changes associated with this version, this may be a breaking change if you are using ioc-finder and have pyparsing pinned to a version less than v3
  - I've chosen to release this as a new minor version b/c I think requirement version updates w/ no API changes and no system requirement changes constitute a minor version change
- Updated parsing of Google Analytics Tracker IDs so that matched must be all lower-cased or all upper-cased (e.g. `ua-...` and `UA-...` will be matched, but `uA-...` will not)  (this makes the parsing consistent with how Google Adsense Publisher IDs are parsed)

## [7.1.0] - 2022.06.13

### Added

- `included_ioc_types` option to only parse specified IOC types ([#218](https://github.com/fhightower/ioc-finder/issues/218))

### Changed

- Imphashes are no longer parsed as md5s even when `parse_imphashes` is False ([#231](https://github.com/fhightower/ioc-finder/issues/231))
- Authentihashes are no longer parsed as sha256s even when `parse_authentihashes` is False ([#231](https://github.com/fhightower/ioc-finder/issues/231))

## [7.0.0] - 2022.05.27

### Added

- Support for Python 3.10 ([#188](https://github.com/fhightower/ioc-finder/issues/188))

### Removed

- Phone number parsing ([#155](https://github.com/fhightower/ioc-finder/issues/155))
- Support for Python 3.6 ([#187](https://github.com/fhightower/ioc-finder/issues/187))

## [6.0.1] - 2021.06.09

### Fixed

- ASN grammar improved reduce false positives by not matching on lower-case `"as "` ([#136](https://github.com/fhightower/ioc-finder/issues/136))

## [6.0.0] - 2021.05.20

### Changed

- Made all boolean arguments keyword-only arguments ([#108](https://github.com/fhightower/ioc-finder/issues/108))
- Converting data from lists to tuples ([#110](https://github.com/fhightower/ioc-finder/issues/110))
- Made `_prepare_text` function public (`prepare_text`) ([#114](https://github.com/fhightower/ioc-finder/issues/114))
- Renamed `no_urls_without_schemes` to `parse_urls_without_scheme` ([#109](https://github.com/fhightower/ioc-finder/issues/109))
- Moved from MIT License to [GNU Lesser General Public License v3.0](https://choosealicense.com/licenses/lgpl-3.0/) ([#113](https://github.com/fhightower/ioc-finder/issues/113))

### Fixed

- Unquoting URLs appropriately ([#104](https://github.com/fhightower/ioc-finder/issues/104))
- Pinned specific [ioc-fanger](https://github.com/ioc-fang/ioc-fanger) version (this prevents an error where ioc-fanger was removing a URL in the query parameter of another URL - see [#104](https://github.com/fhightower/ioc-finder/issues/104))

## [5.0.3] - 2021.04.09

### Fixed

- Unquoting URLs appropriately ([#104](https://github.com/fhightower/ioc-finder/issues/104))
- Pinned specific [ioc-fanger](https://github.com/ioc-fang/ioc-fanger) version (this prevents an error where ioc-fanger was removing a URL in the query parameter of another URL - see [#104](https://github.com/fhightower/ioc-finder/issues/104))

## [5.0.2] - 2021.04.02

### Changed

- [Improved URL grammar](https://github.com/fhightower/ioc-finder/commit/e3025c1a578663f693e7aa7947ac56e577dde0e9)

### Fixed

- Updating library such that CIDR ranges are not detected as URLs when `parse_urls_without_scheme=True` (see [#91](https://github.com/fhightower/ioc-finder/issues/91))
- Parse observables from URL path when `parse_domain_from_url=False` and `parse_from_url_path=True` (see [#90](https://github.com/fhightower/ioc-finder/issues/90))

## [5.0.1] - 2021.01.11

### Changed

- Improved word boundary (specifically of MAC address and IP address grammars)

## [5.0.0] - 2020.09.25

### Removed

- Concurrency (through the use of concurrent.futures)

## [4.0.2] - 2020.09.18

### Added

- Added parsing Monero addresses (see #94)

### Changed

- Simplifying `_remove_url_paths` (a function used behind the scenes by the ioc finder - see #70)
- Created a function to update top level domains (see #10)
- Updating top level domains (which are used in grammars to find network observables)

## [4.0.1] - 2020.09.11

### Changed

- You can now ingest text using the cli. For example, this now works: `cat foo.text | ioc-finder`.
- We now have 100% code coverage!!!
- Adding more keywords so this package is easier to find in pypi

## [4.0.0] - 2020.09.09

### Changed

- We are now parsing observables from URL paths by default (see https://github.com/fhightower/ioc-finder/issues/87). If you would like to disable this functionality, you may do so by setting the `parse_from_url_path` keyword argument to `False` when calling the `find_iocs` function (e.g. `parse_from_url_path=False`).

## <= 3.1.2 - 2020.08.29

The change log was added for version 3.1.2
