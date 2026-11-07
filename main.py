"""
main.py - validate the rules, or hunt through a file of events with them.
    python main.py --validate
    python main.py sample_events/mixed_events.json
"""

import argparse
import json
import sys

import sigma_functions

RULES_FOLDER = "rules"


def get_args():
    parser = argparse.ArgumentParser(description="Validate Sigma rules and run them against JSON events.")
    parser.add_argument("events", nargs="?", help="JSON list of events, each with a 'logsource' field")
    parser.add_argument("--rules", default=RULES_FOLDER, help="folder of .yml rules (default: rules)")
    parser.add_argument("--validate", action="store_true", help="only check the rules are well formed")
    return parser.parse_args()


def run():
    args = get_args()

    # 1. load and sanity check every rule
    rules = sigma_functions.load_rules(args.rules)
    print(f"Loaded {len(rules)} rule(s) from {args.rules}/")
    sigma_functions.exit_if_invalid(rules)
    print("All rules valid.")
    if args.validate or not args.events:
        return

    # 2. load events
    with open(args.events, encoding="utf-8-sig") as event_file:
        events = json.load(event_file)
    print(f"Hunting through {len(events)} event(s)...")

    # 3. report every hit
    hits = sigma_functions.hunt(rules, events)
    print()
    for rule, event in hits:
        what = event.get("CommandLine") or event.get("TargetObject") or f"EventID {event.get('EventID')}"
        print(f"[{rule['level'].upper():<8}] {rule['title']}")
        print(f"           {what}")
    print()
    print(f"{len(hits)} hit(s).")
    sys.exit(2 if hits else 0)


if __name__ == "__main__":
    run()
