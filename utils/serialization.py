import json


def canonical_json_str(data: dict) -> str:
    """String version of canonical JSON — for logging/display only."""
    return json.dumps(data, sort_keys=True, separators=(',', ':'))
