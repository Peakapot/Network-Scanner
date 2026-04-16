# Internal Network Scanner GUI (Nmap XML Analyzer)

This project provides a user-friendly desktop GUI for **authorized internal security assessments**.

## What it does

- Imports existing **Nmap XML output** (it does not run active scans itself).
- Highlights services with mapped risk levels and CVSS scores.
- Displays associated CVEs and public exploit references.
- Generates a PDF risk report suitable for internal remediation workflows.

## Why this design

To keep usage defensive and auditable, the tool only analyzes previously collected scan results from approved sources.

## Quick start

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

## Expected XML format

Use XML exported by Nmap, for example:

```bash
nmap -sV -oX scan.xml <authorized-target-range>
```

Then import `scan.xml` in the GUI.

## Notes

- CVE and exploit links are best-effort mapping examples for triage.
- Always validate findings in your environment before remediation decisions.
