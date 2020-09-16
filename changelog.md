# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to [Semantic Versioning](https://semver.org/).

## [4.0.2] - 2020.09.17

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
