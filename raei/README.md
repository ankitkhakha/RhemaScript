# RAEI Local Evidence Ledger Prototype

Python standard library only. This prototype records learning units, assessment outcomes and a SHA-256 hash-chained event history. It does not certify competence or grant production authority.

Run from the repository root:

```sh
python -m unittest discover -s tests -v
python -m raei.ledger --ledger demo.json init
python -m raei.ledger --ledger demo.json add-unit CS-01 "Computer science foundations"
python -m raei.ledger --ledger demo.json assess CS-01 3 tests/test_ledger.py::test_verified_pass_and_prerequisite
python -m raei.ledger --ledger demo.json report
```

Only a score of at least 3 with a verified evidence reference can pass a unit. Prerequisites must already be passed. Passed units cannot be overwritten. The event chain detects edits to prior events. Evidence references are asserted by the operator and must be independently inspected. This prototype is local and deterministic.
