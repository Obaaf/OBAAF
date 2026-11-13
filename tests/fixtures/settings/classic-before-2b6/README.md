# A snapshot written before slice 2b.6

`snapshot.json` was written by OBAAF at commit `53eceb4` of the `flagship` branch, the code before slice 2b.6, from the hand-written recording `admin-token` with no ruleset in force on `main` and a classic protection rule whose answer has every field of the two examples in GitHub's REST reference ("Get branch protection" and "Update branch protection", read on 2026-11-13). It is `REFERENCE_CLASSIC` in `tests/test_settings_rule_types.py`.

It exists so that a test can compare a snapshot an earlier version wrote, which has no `other_fields`, with one this version takes of the same settings. It is not GitHub's answer for any repository.
