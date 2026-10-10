import re
import sys
import json
import time
import chromadb
from google import genai
from google.genai import types, errors
from embed_store import search, DB_PATH
from retriever import retrieve_for_alert
from mapping import ATTACK_MAP

MODELS = ["gemini-3.1-flash-lite", "gemini-flash-latest"]   # tried in order
client = genai.Client()

SYSTEM_PROMPT = """You are a SOC analyst assistant. You write incident response reports.
Rules:
- Use ONLY the numbered context sources provided. Do not use outside knowledge.
- Cite sources inline like [1] or [2][5]. Only cite a source if it directly states the claim or
  recommendation. Never cite a page just because its topic is nearby.
- Every step or bullet in "Immediate Containment Steps", "Eradication and Recovery" and
  "Evidence to Preserve" must end with a citation. If a useful step is not supported by any source,
  you may include it, but it must end with "(general practice, unsourced)".
- If the sources do not cover a section at all, write "Not covered by the retrieved sources".
- The alert comes from an ML detector. Call it a suspected or detected attack, never a confirmed compromise.
- Do not invent IP addresses, hostnames, counts, or other details that are not in the alert.
- Sources tagged PRIMARY are mapped from the detector class: put them under "Likely ATT&CK Technique(s)".
  Sources tagged RELATED go under "Related Techniques (lower confidence)". For each, say whether it is a
  more specific sub-technique of the primary or just a similar technique, and do not claim it applies.
- Be proportionate. If nothing in the alert shows compromise, say so. In "Eradication and Recovery"
  use two short lists: "Hardening (applies regardless)" for preventive steps such as account policies or
  closing unneeded ports, and "If compromise is confirmed" for clean-up steps.
- Base recommendations on what the alert actually shows. If the attack comes from many sources,
  do not make blocking individual source IPs the main step.
- Severity: report the detector's severity and confidence exactly as given. Do not raise or justify them
  beyond what the sources say, and tell the analyst to validate the severity.
- Do not put citations in the Severity Assessment unless a source directly discusses severity.
- The CISA IR Playbook is written for US federal civilian agencies. Do not recommend reporting to or
  coordinating with CISA, OMB, or other US federal bodies unless the alert says the organization
  is a US federal agency.
- Evidence to Preserve must fit the attack type: prefer the logs and data that would show this specific
  attack (for example flow logs and packet captures for floods, authentication logs for login attacks).
  Mention full forensic imaging only if compromise is suspected.
- If there are no RELATED sources, write "None" under "Related Techniques (lower confidence)".
- Host isolation, forensic imaging, and chain-of-custody paperwork are for suspected or confirmed
  compromise. When the alert shows only a suspected attack, do not make them first-line steps: put them
  at the end as a conditional step beginning "If investigation finds signs of compromise,".
  Do not include chain of custody unless legal action is mentioned or compromise is confirmed.
- If the alert is an access attempt (brute force, web attack), the first containment step must be to
  determine whether any attempt succeeded. If no source covers this, add it and mark it
  (general practice, unsourced).
- Be concise and practical."""

REPORT_FORMAT = """Write the report with exactly these sections:
## Summary
## Likely ATT&CK Technique(s)
## Related Techniques (lower confidence)
## Severity Assessment
## Immediate Containment Steps (prioritized)
## Eradication and Recovery
## Evidence to Preserve"""

# one query per response phase, so each section has sources to draw from
PLAYBOOK_QUERIES = {
    "containment": "containment strategy and key containment activities to isolate and block",
    "eradication-recovery": "eradication and recovery actions to restore systems to normal operation",
    "evidence": "collect and preserve evidence logs chain of custody forensic",
}


def short_source(name):
    return "NIST SP 800-61r2" if "nist" in name.lower() else "CISA IR Playbook"


def get_mitigations(tech_ids, limit=10):
    col = chromadb.PersistentClient(path=DB_PATH).get_collection("mitigations")
    out = []
    for tid in tech_ids:
        res = col.get(where={"technique_id": tid})
        out.extend(zip(res["metadatas"], res["documents"]))
    return out[:limit]


def build_sources(alert):
    attack_type = alert["attack_type"]
    primary_ids = ATTACK_MAP.get(attack_type, {}).get("techniques", [])
    sources = []

    # 1) what the attack is (ATT&CK), tagged primary / sub-technique; lookalikes are skipped
    for meta, doc, dist, how in retrieve_for_alert(attack_type, k=4):
        tid = meta["technique_id"]
        if how == "mapped":
            tag = "PRIMARY (mapped from detector class)"
        elif any(tid.startswith(p + ".") for p in primary_ids):
            tag = "RELATED (more specific sub-technique of a primary technique)"
        else:
            continue   # skip lookalike techniques; they were mostly noise
        sources.append({"label": f'MITRE ATT&CK {tid} - {meta["name"]} [{tag}]', "text": doc})

    # 2) attack-specific mitigations
    for meta, doc in get_mitigations(primary_ids):
        sources.append({
            "label": f'MITRE ATT&CK mitigation {meta["mitigation_id"]} '
                     f'({meta["mitigation_name"]}) for {meta["technique_id"]}',
            "text": doc,
        })

    # 3) general response process (NIST / CISA), one query per phase
    for phase, q in PLAYBOOK_QUERIES.items():
        for meta, doc, dist in search(q, k=2, collection="playbooks"):
            sources.append({
                "label": f'{short_source(meta["source"])} (PDF p.{meta["page"]}) [playbook: {phase}]',
                "text": doc,
            })

    # 4) attack-specific evidence: which logs/data to collect for this kind of attack
    for meta, doc, dist in search(f"collect network logs and connection data to investigate {attack_type}",
                                  k=2, collection="playbooks"):
        sources.append({
            "label": f'{short_source(meta["source"])} (PDF p.{meta["page"]}) [playbook: attack-specific evidence]',
            "text": doc,
        })

    # remove duplicates
    seen, unique = set(), []
    for s in sources:
        if s["text"] not in seen:
            seen.add(s["text"])
            unique.append(s)
    return unique


def call_llm(prompt, retries=3, system=SYSTEM_PROMPT):
    config = types.GenerateContentConfig(system_instruction=system, temperature=0.2)
    for model in MODELS:
        for attempt in range(retries):
            try:
                resp = client.models.generate_content(model=model, contents=prompt, config=config)
                print(f"[model used: {model}]")
                return resp.text
            except errors.APIError as e:
                code = getattr(e, "code", None)
                if code == 404:          # model name not available, try the next one
                    break
                if code in (429, 500, 503, 504):
                    wait = 5 * (attempt + 1)
                    print(f"{model}: error {code}, retrying in {wait}s...")
                    time.sleep(wait)
                else:
                    raise
    raise RuntimeError("All models are busy right now. Try again in a few minutes.")


def generate_report(alert):
    if alert.get("attack_type") == "Normal Traffic":
        return "No incident: this traffic was classified as Normal Traffic, so no report is needed.", []
    sources = build_sources(alert)
    context = "\n\n".join(
        f'[{i}] {s["label"]}\n{s["text"][:1200]}' for i, s in enumerate(sources, start=1)
    )
    prompt = (
        f"ALERT (JSON):\n{json.dumps(alert, indent=2)}\n\n"
        f"CONTEXT SOURCES:\n{context}\n\n{REPORT_FORMAT}"
    )
    return call_llm(prompt), sources


def check_citations(report, n_sources):
    cited = sorted({int(x) for x in re.findall(r"\[(\d+)\]", report)})
    invalid = [c for c in cited if c < 1 or c > n_sources]
    return cited, invalid


def uncited_lines(report):
    """Steps in the action sections that carry no citation and are not marked unsourced."""
    checked = ("containment", "eradication", "evidence")
    section, out = "", []
    for line in report.splitlines():
        s = line.strip()
        if s.startswith("## "):
            section = s.lower()
            continue
        if not any(k in section for k in checked):
            continue
        if s.endswith((":", ":**")):
            continue
        if re.match(r"^(\*|-|\d+\.)\s", s) and not re.search(r"\[\d+\]", s) \
                and "unsourced" not in s.lower():
            out.append(s[:110])
    return out


def sample_alert(attack_type):
    alert = {
        "attack_type": attack_type,
        "confidence": 0.97,
        "severity": "High",
        "source_ip": "203.0.113.45",
        "destination_ip": "10.0.0.12",
        "timestamp": "2026-10-05T14:32:10Z",
        "detector": "Random Forest (supervised)",
    }
    if attack_type in ("DDoS", "DoS"):
        del alert["source_ip"]
        alert["distinct_source_ips"] = 1250
        alert["top_source_ips_sample"] = ["203.0.113.45", "198.51.100.17", "192.0.2.88"]
    return alert


if __name__ == "__main__":
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    show = "--show" in sys.argv
    attack = args[0] if args else "Port Scanning"

    alert = sample_alert(attack)
    report, sources = generate_report(alert)
    print(report)

    print("\n" + "=" * 60 + "\nSOURCES")
    for i, s in enumerate(sources, start=1):
        print(f"[{i}] {s['label']}")
        if show:
            print("     ", s["text"][:600].replace("\n", " "), "\n")

    cited, invalid = check_citations(report, len(sources))
    print("\nCitations used:", cited)
    print("Invalid citation numbers:", invalid if invalid else "none")
    unused = [i for i in range(1, len(sources) + 1) if i not in cited]
    print("Sources given but never cited:", unused if unused else "none")
    bare = uncited_lines(report)
    print("Action steps with no citation:", "none" if not bare else "")
    for b in bare:
        print("   -", b)