# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

A collection of standalone Python 3 security/pentest utility scripts. No shared library, no build system, no tests — each script is self-contained.

## Scripts

- **portscanner.py** — Two-stage port scanner. Stage 1: async TCP-connect sweep (all 65535 ports by default). Stage 2: hands open ports to `nmap` for service/version/script detection. Requires `nmap` in PATH for stage 2.
- **ldapsearch_parse.py** — Parses raw `ldapsearch` output from stdin and prints a formatted table of AD users (sAMAccountName, displayName, description).

## Running

```bash
# Port scanner
python portscanner.py <target> [--ports 1-65535] [--concurrency 2000] [--timeout 1.0] [--nmap-args "-sV -sC -Pn -T4"]

# LDAP parser (reads from stdin)
ldapsearch ... | python ldapsearch_parse.py
```

## Dependencies

Python 3 standard library only. No pip packages. `nmap` is an optional external dependency for `portscanner.py` stage 2.
