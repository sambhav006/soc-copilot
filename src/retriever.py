import chromadb
from embed_store import search, DB_PATH, COLLECTION
from mapping import ATTACK_MAP


def get_technique_chunks(tid):
    col = chromadb.PersistentClient(path=DB_PATH).get_collection(COLLECTION)
    res = col.get(where={"technique_id": tid})
    return list(zip(res["metadatas"], res["documents"]))


def retrieve_for_alert(attack_type, k=3):
    info = ATTACK_MAP.get(attack_type)
    results, seen = [], set()

    if info:
        for tid in info["techniques"]:
            for meta, doc in get_technique_chunks(tid)[:1]:
                results.append((meta, doc, 0.0, "mapped"))
                seen.add(doc)
        query = info["query"]
    else:
        query = attack_type

    for meta, doc, dist in search(query, k=k):
        if doc not in seen:
            results.append((meta, doc, dist, "semantic"))
            seen.add(doc)
    return results


if __name__ == "__main__":
    for a in ["PortScan", "SSH-Patator", "DDoS"]:
        print("\nALERT:", a)
        for meta, doc, dist, how in retrieve_for_alert(a):
            print(f'  [{how}] {meta["technique_id"]} - {meta["name"]}  (distance {dist:.3f})')