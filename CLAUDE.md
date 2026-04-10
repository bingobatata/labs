# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

A collection of standalone Python 3 security/pentest utility scripts. No shared library, no build system — each script is self-contained.

## Scripts

- **portscanner.py** — Two-stage port scanner. Stage 1: async TCP-connect sweep (all 65535 ports by default). Stage 2: hands open ports to `nmap` for service/version/script detection. Requires `nmap` in PATH for stage 2.
- **ldapsearch_parse.py** — Parses raw `ldapsearch` output from stdin and prints a formatted table of AD users (sAMAccountName, displayName, description). Supports base64-encoded LDIF attributes and both comment- and blank-line-separated entries. Use `-w` for wordlist-only output.

## Running

```bash
# Port scanner
python portscanner.py <target> [--ports 1-65535] [--concurrency 2000] [--timeout 1.0] [--nmap-args "-sV -sC -Pn -T4"]

# LDAP parser (reads from stdin)
ldapsearch ... | python ldapsearch_parse.py
```

## Testing

```bash
# Run all tests
python check_scripts.py

# Run tests for a single script
python -m pytest test_ldapsearch_parse.py -v
python -m pytest test_portscanner.py -v
```

- **check_scripts.py** — Syntax-checks all `.py` files and runs all `test_*.py` suites. Also triggered automatically via a Claude Code PostToolUse hook whenever a `.py` file in this directory is edited.
- **hook_check.py** — Wrapper that reads Claude Code hook JSON from stdin and conditionally runs `check_scripts.py` only for edits to `labs/*.py` files.

## Dependencies

Python 3 standard library only. No pip packages. `pytest` for running tests. `nmap` is an optional external dependency for `portscanner.py` stage 2.
