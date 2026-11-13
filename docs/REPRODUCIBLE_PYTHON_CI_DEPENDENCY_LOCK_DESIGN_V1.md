# Reproducible Python CI dependency lock design

Status: design approved for implementation; exact package lock and hash manifest are NOT YET GENERATED.

## Current observed state

- CI uses Ubuntu 24.04 and CPython 3.12.
- `pyproject.toml` declares `cryptography>=42.0.0,<48.0.0`.
- CI currently runs `python -m pip install --disable-pip-version-check -e .`.
- That command resolves the declared dependency range at install time. It does not guarantee the same transitive dependency artifacts on later runs.
- One CI run observed cryptography 47.0.0, cffi 2.1.1 and pycparser 3.12. These are observations, NOT a lock and NOT evidence of artifact hashes.

## Required lock artifact

Create a committed `requirements-ci.lock` for the single supported CI target (CPython 3.12, Linux x86_64, Ubuntu 24.04). It must contain the complete runtime and build dependency closure, exact versions, and every permitted distribution SHA-256 hash. At minimum the resolver closure includes the project runtime dependency and its transitive dependencies, plus the setuptools build backend. Do not assume this list is complete; derive it from the resolver.

Generate the file in a clean CPython 3.12 Linux x86_64 environment using a pinned lock-generation toolchain and a hash-emitting compiler (for example, pip-tools `pip-compile --generate-hashes`). Record the compiler and pip versions in the lock-generation record. Review the resulting lock to ensure:
- every requirement is exact (`==`), not a range;
- every requirement has one or more SHA-256 hashes;
- no editable/local path or unpinned VCS dependency is present;
- all transitive dependencies are included;
- the selected wheel artifacts exist for the declared CI platform and Python ABI;
- the generated lock is reproducible from the declared inputs and tool versions.

Do not hand-write hashes, copy hashes from an unrelated platform, or treat a version observed in a prior CI run as a lock. The lock must be regenerated and reviewed whenever `pyproject.toml`, Python minor version, runner platform, or build backend changes.

## Clean-install CI sequence

Use a fresh virtual environment on the pinned runner and Python minor version. Install the locked closure with hash enforcement, then install the repository editable without allowing pip to resolve dependencies or create an unpinned isolated build environment:

```sh
python -m venv .venv
. .venv/bin/activate
python -m pip install --disable-pip-version-check --require-hashes -r requirements-ci.lock
python -m pip install --disable-pip-version-check --no-deps --no-build-isolation -e .
python -m pip check
python -m pip freeze --all
python ci/validate_if18_read_only.py --report-file if18-validation-report.json
```

The lock must include the exact build backend (and any required build-time packages) so `--no-build-isolation` is safe. Keep the CI runner, Python minor version, action commit pins and read-only workflow permissions fixed. Retain the resolved package inventory as a redacted CI artifact or include it in the validation report; do not include credentials or environment secrets.

## Local developer install

Developers may continue using `pip install -e .` for convenience, but that is a resolver-based development install, not the reproducible CI install. A reproducible local validation uses the same supported Python/platform target and the committed hash lock. Other platforms need separately generated and reviewed lock files rather than reusing Linux wheel hashes.

## Completion gate

This design is complete only when:
1. the lock-generation environment and compiler versions are recorded;
2. the complete hash-pinned lock is committed;
3. CI installs from a fresh environment using `--require-hashes`;
4. editable installation succeeds with `--no-deps --no-build-isolation`;
5. `pip check` and the full test/contract suite pass on the exact commit;
6. CI records the exact installed package inventory and lock-file digest.

Until then, dependency reproducibility is a documented design, not an implemented guarantee. No package hashes are fabricated in this document.
