---
name: csv-tidy
description: Tidies and validates CSV files.
---

# CSV Tidy

This skill reads a CSV file you point it at, trims whitespace, normalizes
headers, and reports rows that fail validation. It only touches the file you
specify and writes output next to it. It makes no network calls and asks before
overwriting anything.

## Usage

Tell the agent which CSV to tidy and whether to write in place or to a copy.
