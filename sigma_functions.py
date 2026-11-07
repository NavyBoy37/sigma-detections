"""
sigma_functions.py - a small Sigma rule engine. Loads rule YAML, checks it's
well formed, and decides whether a log event (a plain dict) matches.

Supports the parts of the Sigma spec these rules use:
  field modifiers  |contains |startswith |endswith |re |all
  value lists      OR'd together (AND'd with |all)
  selections       a map (every field must match) or a list of maps (any)
  conditions       and / or / not / ( ) / 1 of x* / all of x* / 1 of them
"""

import fnmatch
import os
import re
import sys

import yaml

REQUIRED_FIELDS = ["title", "id", "status", "description", "author", "date",
                   "logsource", "detection", "level", "tags", "falsepositives"]
LEVELS = ["informational", "low", "medium", "high", "critical"]
STATUSES = ["experimental", "test", "stable"]
UUID_PATTERN = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")


# ------------------------------------------------------------------ loading
def load_rule(path):
    with open(path, encoding="utf-8") as rule_file:
        rule = yaml.safe_load(rule_file)
    rule["_path"] = path
    return rule


def load_rules(folder):
    rules = []
    for root, _, files in os.walk(folder):
        for name in sorted(files):
            if name.endswith((".yml", ".yaml")):
                rules.append(load_rule(os.path.join(root, name)))
    rules.sort(key=lambda r: r["_path"])
    return rules


# --------------------------------------------------------------- validation
def validate_rule(rule):
    """Returns a list of problems. Empty list = rule is good."""
    problems = []
    for field in REQUIRED_FIELDS:
        if field not in rule:
            problems.append("missing field: " + field)
    if problems:
        return problems

    if not UUID_PATTERN.match(str(rule["id"])):
        problems.append("id is not a lowercase UUID")
    if rule["level"] not in LEVELS:
        problems.append("level must be one of " + ", ".join(LEVELS))
    if rule["status"] not in STATUSES:
        problems.append("status must be one of " + ", ".join(STATUSES))
    if not any(re.match(r"^attack\.t\d{4}(\.\d{3})?$", tag) for tag in rule["tags"]):
        problems.append("needs at least one attack.tXXXX technique tag")

    detection = rule["detection"]
    if "condition" not in detection:
        problems.append("detection has no condition")
    else:
        try:
            selections = {k: v for k, v in detection.items() if k != "condition"}
            evaluate_condition(detection["condition"], selections, {})
        except ValueError as error:
            problems.append("bad condition: " + str(error))
    return problems


# ----------------------------------------------------------- value matching
def _value_matches(event_value, expected, modifiers):
    if event_value is None:
        return expected is None
    if expected is None:
        return False

    actual = str(event_value)
    wanted = str(expected)
    if "re" in modifiers:
        return re.search(wanted, actual) is not None

    # Sigma string matching is case-insensitive
    actual, wanted = actual.lower(), wanted.lower()
    if "contains" in modifiers:
        return wanted in actual
    if "startswith" in modifiers:
        return actual.startswith(wanted)
    if "endswith" in modifiers:
        return actual.endswith(wanted)
    # plain values may use * and ? wildcards
    if "*" in wanted or "?" in wanted:
        return fnmatch.fnmatchcase(actual, wanted)
    return actual == wanted


def _field_matches(event, field_spec, expected):
    field, *modifiers = field_spec.split("|")
    event_value = event.get(field)
    values = expected if isinstance(expected, list) else [expected]
    results = [_value_matches(event_value, value, modifiers) for value in values]
    return all(results) if "all" in modifiers else any(results)


def selection_matches(event, selection):
    if isinstance(selection, list):
        # a list of maps = any one of them; a list of strings = keyword search
        if all(isinstance(item, dict) for item in selection):
            return any(selection_matches(event, item) for item in selection)
        text = " ".join(str(v) for v in event.values()).lower()
        return any(str(keyword).lower() in text for keyword in selection)
    return all(_field_matches(event, field, expected) for field, expected in selection.items())


# ------------------------------------------------------- condition parsing
# Tiny recursive descent parser. Each function takes the token list and a
# position, and returns (result, new_position).
#   expression := term ("or" term)*
#   term       := factor ("and" factor)*
#   factor     := "not" factor | "(" expression ")" | quantifier | name
def tokenize(condition):
    return re.findall(r"\(|\)|[\w*]+", condition)


def _names_for(pattern, selections):
    if pattern == "them":
        return list(selections)
    names = [name for name in selections if fnmatch.fnmatchcase(name, pattern)]
    if not names:
        raise ValueError(f"'{pattern}' matches no selection")
    return names


def _parse_factor(tokens, pos, selections, results):
    if pos >= len(tokens):
        raise ValueError("condition ended early")
    token = tokens[pos]

    if token == "not":
        value, pos = _parse_factor(tokens, pos + 1, selections, results)
        return not value, pos

    if token == "(":
        value, pos = _parse_expression(tokens, pos + 1, selections, results)
        if pos >= len(tokens) or tokens[pos] != ")":
            raise ValueError("missing )")
        return value, pos + 1

    if token in ("1", "all") and pos + 2 < len(tokens) and tokens[pos + 1] == "of":
        names = _names_for(tokens[pos + 2], selections)
        values = [results.get(name, False) for name in names]
        return (any(values) if token == "1" else all(values)), pos + 3

    if token not in selections:
        raise ValueError(f"unknown selection '{token}'")
    return results.get(token, False), pos + 1


def _parse_term(tokens, pos, selections, results):
    value, pos = _parse_factor(tokens, pos, selections, results)
    while pos < len(tokens) and tokens[pos] == "and":
        right, pos = _parse_factor(tokens, pos + 1, selections, results)
        value = value and right
    return value, pos


def _parse_expression(tokens, pos, selections, results):
    value, pos = _parse_term(tokens, pos, selections, results)
    while pos < len(tokens) and tokens[pos] == "or":
        right, pos = _parse_term(tokens, pos + 1, selections, results)
        value = value or right
    return value, pos


def evaluate_condition(condition, selections, results):
    tokens = tokenize(condition)
    value, pos = _parse_expression(tokens, 0, selections, results)
    if pos != len(tokens):
        raise ValueError(f"unexpected '{tokens[pos]}'")
    return value


# ----------------------------------------------------------------- matching
def logsource_applies(rule, event):
    """An event applies if every logsource key the rule names matches the event's."""
    event_source = event.get("logsource", {})
    return all(event_source.get(key) == value for key, value in rule["logsource"].items())


def rule_matches(rule, event):
    detection = rule["detection"]
    selections = {name: body for name, body in detection.items() if name != "condition"}
    results = {name: selection_matches(event, body) for name, body in selections.items()}
    return evaluate_condition(detection["condition"], selections, results)


def hunt(rules, events):
    """Every (rule, event) pair that fires."""
    hits = []
    for event in events:
        for rule in rules:
            if logsource_applies(rule, event) and rule_matches(rule, event):
                hits.append((rule, event))
    return hits


def exit_if_invalid(rules):
    bad = 0
    for rule in rules:
        for problem in validate_rule(rule):
            print(f"{rule['_path']}: {problem}")
            bad += 1
    if bad:
        sys.exit(1)
