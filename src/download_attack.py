import json
import requests
from pathlib import Path

URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
OUT = Path("data/attack/enterprise-attack.json")


def download():
    OUT.parent.mkdir(parents=True, exist_ok=True)
    if OUT.exists():
        print("Already downloaded.")
        return
    print("Downloading (around 40-50 MB, please wait)...")
    r = requests.get(URL, timeout=120)
    r.raise_for_status()
    OUT.write_bytes(r.content)
    print("Saved to", OUT)


def load_techniques():
    with open(OUT, encoding="utf-8") as f:
        bundle = json.load(f)

    techniques = []
    for obj in bundle["objects"]:
        if obj.get("type") != "attack-pattern":
            continue
        if obj.get("revoked") or obj.get("x_mitre_deprecated"):
            continue
        tid = next(
            (r["external_id"] for r in obj.get("external_references", [])
             if r.get("source_name") == "mitre-attack"),
            None,
        )
        techniques.append({
            "id": tid,
            "name": obj["name"],
            "description": obj.get("description", ""),
        })
    return techniques


if __name__ == "__main__":
    download()
    techs = load_techniques()
    print(f"Loaded {len(techs)} techniques")
    for t in techs[:5]:
        print(t["id"], "-", t["name"])
        print("   ", t["description"][:150].replace("\n", " "), "...")