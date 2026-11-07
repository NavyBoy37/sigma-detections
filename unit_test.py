"""
unit_test.py - two kinds of tests:
  1. the rule engine itself (modifiers, conditions, validation)
  2. every rule in rules/ against tests/<rule name>.json, which holds events
     the rule MUST catch and look-alike benign events it MUST NOT catch
    python unit_test.py

No test framework needed, a failed assert prints which test broke and the run
exits non-zero.
"""

import json
import os
import sys
import traceback

import sigma_functions

RULES_FOLDER = "rules"
TESTS_FOLDER = "tests"


def make_rule(detection, logsource=None):
    return {"title": "t", "logsource": logsource or {"product": "windows"}, "detection": detection}


# ------------------------------------------------------------ value matching
def test_modifiers():
    event = {"CommandLine": "C:\\Windows\\System32\\cmd.exe /c whoami"}
    assert sigma_functions.selection_matches(event, {"CommandLine|contains": "WHOAMI"})
    assert sigma_functions.selection_matches(event, {"CommandLine|startswith": "c:\\windows"})
    assert sigma_functions.selection_matches(event, {"CommandLine|endswith": "whoami"})
    assert sigma_functions.selection_matches(event, {"CommandLine|re": r"cmd\.exe\s+/c"})
    assert not sigma_functions.selection_matches(event, {"CommandLine|contains": "powershell"})


def test_list_is_or_and_all_is_and():
    event = {"CommandLine": "vssadmin delete shadows"}
    assert sigma_functions.selection_matches(event, {"CommandLine|contains": ["nope", "shadows"]})
    assert sigma_functions.selection_matches(event, {"CommandLine|contains|all": ["delete", "shadows"]})
    assert not sigma_functions.selection_matches(event, {"CommandLine|contains|all": ["delete", "nope"]})


def test_fields_in_a_selection_are_and():
    event = {"Image": "C:\\x\\certutil.exe", "CommandLine": "certutil -hashfile a"}
    assert not sigma_functions.selection_matches(
        event, {"Image|endswith": "\\certutil.exe", "CommandLine|contains": "urlcache"})


def test_list_of_maps_is_or():
    event = {"OriginalFileName": "CertUtil.exe", "Image": "C:\\Users\\Public\\renamed.exe"}
    selection = [{"Image|endswith": "\\certutil.exe"}, {"OriginalFileName": "CertUtil.exe"}]
    assert sigma_functions.selection_matches(event, selection)


def test_plain_value_wildcards_and_numbers():
    assert sigma_functions.selection_matches({"Image": "C:\\Tools\\psexec64.exe"}, {"Image": "*\\psexec*.exe"})
    assert sigma_functions.selection_matches({"EventID": 1102}, {"EventID": 1102})
    assert sigma_functions.selection_matches({"EventID": "1102"}, {"EventID": 1102})


def test_missing_field_never_matches():
    assert not sigma_functions.selection_matches({}, {"CommandLine|contains": "x"})


# ---------------------------------------------------------------- conditions
def test_condition_logic():
    selections = {"a": {}, "b": {}, "filter": {}}
    results = {"a": True, "b": False, "filter": True}
    assert sigma_functions.evaluate_condition("a or b", selections, results)
    assert not sigma_functions.evaluate_condition("a and b", selections, results)
    assert not sigma_functions.evaluate_condition("a and not filter", selections, results)
    assert sigma_functions.evaluate_condition("(a or b) and filter", selections, results)
    # and binds tighter than or
    assert sigma_functions.evaluate_condition("b and a or filter", selections, results)


def test_condition_quantifiers():
    selections = {"sel_one": {}, "sel_two": {}, "filter": {}}
    results = {"sel_one": True, "sel_two": False, "filter": False}
    assert sigma_functions.evaluate_condition("1 of sel_*", selections, results)
    assert not sigma_functions.evaluate_condition("all of sel_*", selections, results)
    assert sigma_functions.evaluate_condition("1 of them", selections, results)


def test_bad_conditions_raise():
    selections = {"a": {}}
    for bad in ["a and", "(a", "b", "a a", "1 of x*"]:
        try:
            sigma_functions.evaluate_condition(bad, selections, {})
        except ValueError:
            continue
        raise AssertionError("should have rejected: " + bad)


def test_logsource_applies():
    rule = make_rule({"s": {}, "condition": "s"}, {"product": "windows", "category": "process_creation"})
    assert sigma_functions.logsource_applies(rule, {"logsource": {"product": "windows", "category": "process_creation"}})
    assert not sigma_functions.logsource_applies(rule, {"logsource": {"product": "linux", "category": "process_creation"}})


# ---------------------------------------------------------------- validation
def test_validate_catches_problems():
    rule = {"title": "x", "id": "not-a-uuid", "status": "test", "description": "d", "author": "a",
            "date": "2026-01-01", "logsource": {}, "level": "spicy", "tags": ["attack.execution"],
            "falsepositives": [], "detection": {"s": {}, "condition": "s and missing"}}
    problems = " | ".join(sigma_functions.validate_rule(rule))
    assert "UUID" in problems
    assert "level" in problems
    assert "technique tag" in problems
    assert "bad condition" in problems


def test_every_rule_is_valid():
    for rule in sigma_functions.load_rules(RULES_FOLDER):
        problems = sigma_functions.validate_rule(rule)
        assert not problems, rule["_path"] + ": " + "; ".join(problems)


def test_rule_ids_are_unique():
    ids = [rule["id"] for rule in sigma_functions.load_rules(RULES_FOLDER)]
    assert len(ids) == len(set(ids))


# ------------------------------------------------------- per-rule test cases
def test_every_rule_has_test_cases():
    for rule in sigma_functions.load_rules(RULES_FOLDER):
        name = os.path.splitext(os.path.basename(rule["_path"]))[0]
        assert os.path.exists(os.path.join(TESTS_FOLDER, name + ".json")), "no tests for " + name


def test_rules_against_their_cases():
    for rule in sigma_functions.load_rules(RULES_FOLDER):
        name = os.path.splitext(os.path.basename(rule["_path"]))[0]
        with open(os.path.join(TESTS_FOLDER, name + ".json"), encoding="utf-8") as case_file:
            cases = json.load(case_file)
        assert cases["match"] and cases["nomatch"], name + " needs both match and nomatch cases"

        for event in cases["match"]:
            assert sigma_functions.logsource_applies(rule, event) and sigma_functions.rule_matches(rule, event), \
                f"{name} MISSED: {event.get('CommandLine') or event}"
        for event in cases["nomatch"]:
            fired = sigma_functions.logsource_applies(rule, event) and sigma_functions.rule_matches(rule, event)
            assert not fired, f"{name} FALSE POSITIVE: {event.get('CommandLine') or event}"


def test_hunt_sample_hits_each_rule_once():
    rules = sigma_functions.load_rules(RULES_FOLDER)
    with open("sample_events/mixed_events.json", encoding="utf-8") as event_file:
        events = json.load(event_file)
    titles = [rule["title"] for rule, _ in sigma_functions.hunt(rules, events)]
    assert sorted(titles) == sorted(rule["title"] for rule in rules)


# ------------------------------------------------------------------- runner
def run_tests():
    tests = [(name, fn) for name, fn in sorted(globals().items()) if name.startswith("test_") and callable(fn)]
    failed = 0
    for name, test in tests:
        try:
            test()
            print("PASS  " + name)
        except Exception:
            failed += 1
            print("FAIL  " + name)
            traceback.print_exc()
    print(f"\n{len(tests) - failed}/{len(tests)} passed")
    return failed


if __name__ == "__main__":
    sys.exit(1 if run_tests() else 0)
