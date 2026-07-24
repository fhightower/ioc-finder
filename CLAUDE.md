# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

uv-managed project; Python 3.10+ required.

- `uv sync --locked --group dev` — install deps (also `make init` / `make install`).
- `uv run pytest` — run the suite. `pytest.ini_options` adds `-n auto` (xdist) and coverage with a high `--cov-fail-under` threshold (see `pyproject.toml`), so coverage regressions fail the run. Also `make test`.
- `uv run pytest tests/test_ioc_finder.py::test_name` — single test (or `uv run pytest tests/test_ioc_finder.py` for one module).
- `./docker/lint.sh` — the canonical lint step: `ruff check --fix`, `ruff format`, then (when `CONTEXT=ci`) asserts nothing changed, then `mypy`, then `ruff check`. CI runs this; `make lint` runs the ruff+mypy subset.
- `uv run python scripts/find_hotspots.py` — profile which `parse_*` helper is slowest on the benchmark texts; run before and after tuning any parser. `tests/benchmarks.py` is the pytest-benchmark suite, gated two ways in CI: `benchmark_regression` benchmarks the PR's own base commit in the same job and fails on `median:25%` (this is the gate that catches a regression *you* introduced), while `build_multi_os` compares against the checked-in `.benchmarks/` baselines, which are absolute, per-OS, refreshed by hand, and therefore only good for spotting cumulative drift. Note that both invoke pytest as `pytest -c "."`, which deliberately fails to resolve a config file so the `-n auto --cov` addopts don't apply — xdist disables pytest-benchmark outright and coverage would swamp the timings.

## Architecture

The package finds indicators of compromise (URLs, IPs, hashes, domains, ATT&CK IDs, …) in free text.

**`ioc_finder/ioc_finder.py`** — the main module.
- `find_iocs(text, included_ioc_types=..., excluded_ioc_types=..., **options)` is the entry point. It calls `prepare_text()` (which runs `ioc_fanger.fang()` to normalize defanged IOCs first), then runs each requested `parse_*` helper, returning a dict keyed by IOC type. `SUPPORTED_IOC_TYPES` / `DEFAULT_IOC_TYPES` define the set. `cli_find_iocs` is the `ioc-finder` click CLI.
- There is one `parse_*` helper per IOC type (`parse_urls`, `parse_domain_names`, `parse_md5s`, `parse_cves`, `parse_email_addresses`, the `parse_*_attack_*` family, …), all re-exported from `ioc_finder/__init__.py`.
- **Order matters in `find_iocs`**: after a "containing" IOC is matched, its substructure is stripped from the working text via the `_remove_*` helpers (e.g. `_remove_url_domain_name`, `_remove_url_paths`, `_remove_xmpp_local_part`) so a URL's host isn't also reported as a bare domain.

**`ioc_finder/ioc_grammars.py`** — the pyparsing grammars (`domain_name`, `complete_email_address`, `url`, `ipv6_address`, …) that are the *precise* validators. Some grammars are reused as sub-grammars (e.g. `domain_name` inside email/url/xmpp).

**`ioc_finder/data.py`** — large static data tables (TLD set, ATT&CK technique/tactic/mitigation IDs, etc.) consumed by the grammars and parsers.

**Performance pattern (important — see the long comments in `ioc_finder.py`):** running a pyparsing grammar at every offset is expensive, so `ioc_finder.py` defines cheap "candidate-span" regexes (`_DOMAIN_CANDIDATE_RE`, `_EMAIL_CANDIDATE_RE`, `_IPV4_CANDIDATE_RE`, `_MD5_CANDIDATE_RE`, `_CVE_CANDIDATE_RE`, `_URL_MARKER_RE`, …). `_scan_candidates` / `_scan_validated` / `_scan_url_candidates` locate plausible spans with the regex and then apply the grammar (or a pure-Python validator like `_is_valid_ipv6`) only there. **These regexes are deliberate supersets of what their grammar accepts and must stay in sync with the grammar's word-boundary rules** — the comments spell out which `ioc_grammars` construct each mirrors. Exceptions: the md5/sha1/sha256/sha512 candidate regexes are *exact* mirrors used as the sole validators (no pyparsing pass — see `_scan_hash_candidates`), and the IPv4/CIDR candidates are validated by pure-Python `_normalized_ipv4`; when editing any of these, keep the regex, the still-live grammar (md5/sha256 remain embedded in imphash/authentihash), and the Python validator in lockstep. Candidate regexes must use ASCII `[0-9]`, not `\d` — a Unicode-aware `\d` plus `int()` fabricates IOCs the grammars rejected. `parse_domain_names` consults `ioc_grammars.TLD_SET` directly so its fast path and the `domain_name` grammar can't disagree on what counts as a TLD.

Grammars are module-level / shared; `tests/test_concurrency.py` guards against state leakage.

## Conventions

- Lint/format is enforced (`ruff`, `mypy`) — run `./docker/lint.sh` before pushing; CI fails if it would change files.
- Tests are organized by area (`test_find_iocs.py`, `test_parsing_functions.py`, `test_urls.py`, `test_edge_cases.py`, `test_with_hypothesis.py`, …) plus `find_iocs_cases/` data-driven cases. Add tests with new IOC support.
- `dependency_update_review_process.md` documents how Dependabot PRs are triaged (notably: bump the version *floor*, don't just widen the range). `ai_developer_guidelines.md` / `ai_manager_guidelines.md` / `ai_reviewer_guidelines.md` describe the multi-agent dev workflow.
- When opening a PR, add a `Fixes #n` line to the body referencing the issue it closes.

## Hooks

`.claude/settings.json` configures a `PostToolUse` hook on `Write|Edit` that runs `./docker/lint.sh` whenever an `ioc_finder/*.py` or `tests/*.py` file is edited, and **blocks the turn (exit 2, lint output fed back) if it fails** — so a `ruff`/`mypy` failure has to be fixed before continuing.
