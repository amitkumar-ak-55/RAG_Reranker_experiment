from __future__ import annotations

import csv
import io
import json


def csv_report(rows: list[dict[str, object]]) -> str:
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=list(rows[0]) if rows else ["arm"])
    writer.writeheader()
    writer.writerows(rows)
    return output.getvalue()


def json_manifest(data: object) -> str:
    return json.dumps(data, indent=2, default=str)
