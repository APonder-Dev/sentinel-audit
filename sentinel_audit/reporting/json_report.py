import json
from pathlib import Path

def save_json_report(data: dict, output_path: str) -> None:
    """Saves the collected data as a JSON report."""
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", encoding="utf-8") as file:
        json.dump(data, file, indent=4)