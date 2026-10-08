"""plaso's PE events as TSV, one line per event, sorted.

    python3 -I plaso_tsv.py pe.jsonl pe-written.jsonl > plaso.tsv

Columns: file name, data type, timestamp description, seconds since 1970,
then for pe_coff:file the PE type, import hash, section names (the raw 8
bytes, NUL written \\0, joined by |) and export DLL name; for
pe_coff:dll_import the DLL name and whether it is delay-loaded.
"""

import json
import sys


def columns(event):
    file_name = event["pathspec"]["location"].rsplit("/", 1)[-1]
    common = [
        file_name,
        event["data_type"],
        event["timestamp_desc"],
        str(event["timestamp"] // 1_000_000),
    ]
    if event["data_type"] == "pe_coff:file":
        sections = "|".join(name.replace("\0", "\\0") for name in event["section_names"])
        return common + [
            event["pe_type"],
            event.get("imphash", ""),
            sections,
            event.get("export_dll_name", ""),
        ]
    if event["data_type"] == "pe_coff:dll_import":
        return common + [event["name"], str(event["delayed_import"]).lower()]
    raise SystemExit(f"unexpected data type {event['data_type']}")


lines = []
for path in sys.argv[1:]:
    with open(path, encoding="utf-8") as events:
        lines.extend("\t".join(columns(json.loads(line))) for line in events if line.strip())
for line in sorted(lines):
    print(line)
