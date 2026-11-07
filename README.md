# sigma-detections

![tests](https://github.com/NavyBoy37/sigma-detections/actions/workflows/tests.yml/badge.svg)

## Purpose

Detection rules written in [Sigma](https://github.com/SigmaHQ/sigma), the
vendor-neutral format that converts to Splunk, Elastic, Sentinel and the rest.
Every rule ships with test events: attacks it **must** catch, and look-alike
normal activity it **must not**. CI runs both on every push, so a rule that
starts missing things or firing on noise fails the build.

The rules are my own, written from the ATT&CK technique descriptions. For
production-grade coverage, use the SigmaHQ repo. This repo is about showing the
process: pick a technique, find the artifact it leaves behind, write the
logic, then prove it against both malicious and benign samples.

## Rules

| Rule | Level | ATT&CK | Log source |
|---|---|---|---|
| [LSASS dumped with comsvcs.dll MiniDump](rules/windows/process_creation/proc_creation_win_lsass_dump_comsvcs.yml) | Critical | [T1003.001](https://attack.mitre.org/techniques/T1003/001/) | Process creation |
| [Volume shadow copies deleted](rules/windows/process_creation/proc_creation_win_shadow_copy_deletion.yml) | Critical | [T1490](https://attack.mitre.org/techniques/T1490/) | Process creation |
| [PowerShell encoded command](rules/windows/process_creation/proc_creation_win_powershell_encoded_command.yml) | High | [T1059.001](https://attack.mitre.org/techniques/T1059/001/) | Process creation |
| [Certutil downloading a file](rules/windows/process_creation/proc_creation_win_certutil_download.yml) | High | [T1105](https://attack.mitre.org/techniques/T1105/) | Process creation |
| [Security event log cleared](rules/windows/builtin/win_security_log_cleared.yml) | High | [T1070.001](https://attack.mitre.org/techniques/T1070/001/) | Security 1102 |
| [Scheduled task from a user-writable folder](rules/windows/process_creation/proc_creation_win_schtasks_user_writable_path.yml) | Medium | [T1053.005](https://attack.mitre.org/techniques/T1053/005/) | Process creation |
| [Run key pointing at a user-writable folder](rules/windows/registry/registry_set_win_run_key_user_writable.yml) | Medium | [T1547.001](https://attack.mitre.org/techniques/T1547/001/) | Sysmon 13 |
| [Account added to Administrators / RDP Users](rules/windows/builtin/win_user_added_to_admin_group.yml) | Medium | [T1098.007](https://attack.mitre.org/techniques/T1098/007/) | Security 4732 |
| [Download piped into a shell](rules/linux/process_creation/proc_creation_lnx_download_piped_to_shell.yml) | Medium | [T1059.004](https://attack.mitre.org/techniques/T1059/004/) | Linux process creation |

Each rule's `description` says why the behavior matters, and its
`falsepositives` says what will trip it in a real environment and how to tune it.

## How the testing works

```
rules/windows/.../proc_creation_win_certutil_download.yml
tests/proc_creation_win_certutil_download.json
    "match":   certutil -urlcache -split -f http://...        <- must fire
               renamed certutil (OriginalFileName) + -verifyctl <- must fire
    "nomatch": certutil -hashfile setup.exe SHA256            <- must stay quiet
               certutil -urlcache *   (no URL, just listing)  <- must stay quiet
```

`unit_test.py` loads every rule and its test file. It fails if a rule misses a
`match` event, fires on a `nomatch` event, is missing a required field, has a
bad UUID or condition, or has no ATT&CK technique tag.

The negative cases are the interesting part. They're the commands an admin
actually runs (`vssadmin list shadows`, `powershell -File backup.ps1`,
`curl ... | jq`, the OneDrive updater's scheduled task) that a careless rule
would flag.

## The engine

`sigma_functions.py` is a small Sigma evaluator I wrote so the tests don't need
a SIEM. It's plain functions with a little recursive-descent parser for
conditions, and it supports the parts of the spec these rules use:

- field modifiers `|contains`, `|startswith`, `|endswith`, `|re`, `|all`
- value lists (OR), lists of maps (OR), fields within a map (AND)
- `*` / `?` wildcards, case-insensitive matching
- conditions with `and`, `or`, `not`, parentheses, `1 of sel_*`, `all of sel_*`, `1 of them`

It does **not** cover the whole spec (no aggregations, correlations, `|base64offset`,
`|cidr` and so on). For real deployments, convert the rules with
[pySigma / sigma-cli](https://github.com/SigmaHQ/pySigma).

## Files

| Path | Purpose |
|---|---|
| `rules/` | The Sigma rules, by product and log category |
| `tests/` | One JSON file per rule: `match` and `nomatch` events |
| `sample_events/mixed_events.json` | One malicious + one benign event per rule, for trying a hunt |
| `sigma_functions.py` | Rule loading, validation, matching |
| `main.py` | `--validate` the rules, or hunt through an events file |
| `unit_test.py` | Engine tests + every rule against its cases |

## Run

```bash
pip install -r requirements.txt
python unit_test.py
python main.py --validate
python main.py sample_events/mixed_events.json
```

```
Hunting through 18 event(s)...

[CRITICAL] LSASS Memory Dumped With comsvcs.dll MiniDump
           rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump 624 C:\Temp\out.dmp full
[HIGH    ] PowerShell Launched With an Encoded Command
           powershell.exe -NoP -W Hidden -EncodedCommand SQBFAFgAIAAoAE4AZQB3AC0A...
[CRITICAL] Volume Shadow Copies Deleted
           vssadmin.exe Delete Shadows /All /Quiet
...
9 hit(s).
```

9 malicious events hit, 9 benign ones don't. `main.py` exits with code 2 when
anything fires, so it can gate a pipeline.

All sample events are made up. IPs come from the RFC 5737 documentation ranges
and the user and host names are fake.
