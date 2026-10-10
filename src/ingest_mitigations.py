import json
import chromadb
from download_attack import OUT
from embed_store import model, clean, DB_PATH

COLLECTION = "mitigations"


def load_mitigation_pairs():
    with open(OUT, encoding="utf-8") as f:
        objs = json.load(f)["objects"]

    def active(o):
        return not (o.get("revoked") or o.get("x_mitre_deprecated"))

    def ext_id(o):
        return next((r["external_id"] for r in o.get("external_references", [])
                     if r.get("source_name") == "mitre-attack"), None)

    techniques = {o["id"]: (ext_id(o), o["name"])
                  for o in objs if o.get("type") == "attack-pattern" and active(o)}
    mitigations = {o["id"]: (ext_id(o), o["name"])
                   for o in objs if o.get("type") == "course-of-action" and active(o)}

    pairs = []
    for o in objs:
        if o.get("type") != "relationship" or o.get("relationship_type") != "mitigates":
            continue
        if not active(o):
            continue
        if o["source_ref"] in mitigations and o["target_ref"] in techniques:
            tid, tname = techniques[o["target_ref"]]
            mid, mname = mitigations[o["source_ref"]]
            desc = clean(o.get("description", ""))
            if tid and desc:
                pairs.append((tid, tname, mid, mname, desc))
    return pairs


def build():
    client = chromadb.PersistentClient(path=DB_PATH)
    try:
        client.delete_collection(COLLECTION)
    except Exception:
        pass
    col = client.create_collection(COLLECTION, metadata={"hnsw:space": "cosine"})

    ids, docs, metas = [], [], []
    for n, (tid, tname, mid, mname, desc) in enumerate(load_mitigation_pairs()):
        ids.append(f"{tid}_{mid}_{n}")
        docs.append(f"{tid} - {tname} | Mitigation: {mname} ({mid}): {desc}")
        metas.append({"source": "MITRE ATT&CK Mitigation", "technique_id": tid,
                      "technique_name": tname, "mitigation_id": mid,
                      "mitigation_name": mname})

    print(f"Embedding {len(docs)} mitigation entries...")
    for i in range(0, len(docs), 256):
        col.add(
            ids=ids[i:i + 256],
            documents=docs[i:i + 256],
            embeddings=model.encode(docs[i:i + 256]).tolist(),
            metadatas=metas[i:i + 256],
        )
    print("Done. Stored", col.count(), "entries.")
    return col


if __name__ == "__main__":
    col = build()
    for tid in ["T1498", "T1110", "T1046"]:
        res = col.get(where={"technique_id": tid})
        print(f"\n{tid}: {len(res['ids'])} mitigations")
        for m, d in zip(res["metadatas"], res["documents"]):
            print(f'  - {m["mitigation_name"]} ({m["mitigation_id"]})')
            print("      ", d.split("):", 1)[-1].strip()[:140])