# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/).

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
