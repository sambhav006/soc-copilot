import sys
import json
from pathlib import Path
from embed_store import search

QUESTIONS = Path("eval/test_questions.json")
K = 3


def search_unique(query, collection, k=3):
    """Like search(), but keeps only the best chunk per technique / mitigation / page."""
    results = search(query, k=k * 4, collection=collection)
    seen, out = set(), []
    for m, d, dist in results:
        if "mitigation_id" in m:
            key = (m["mitigation_id"], m["technique_id"])
        elif "technique_id" in m:
            key = m["technique_id"]
        else:
            key = (m["source"], m["page"])
        if key in seen:
            continue
        seen.add(key)
        out.append((m, d, dist))
        if len(out) == k:
            break
    return out


def first_hit_rank(q, metas):
    """Rank (1-based) of the first retrieved chunk that counts as correct, else None."""
    for rank, m in enumerate(metas, start=1):
        if q["collection"] == "attack":
            ok = m.get("technique_id") in q["expected"]
        elif q["collection"] == "mitigations":
            ok = m.get("mitigation_id") in q["expected"]
        else:  # playbooks
            ok = any(e["source"] in m["source"].lower() and m["page"] in e["pages"]
                     for e in q["expected"])
        if ok:
            return rank
    return None


def describe(m):
    if "mitigation_id" in m:
        return f'{m["mitigation_id"]} ({m["technique_id"]})'
    if "technique_id" in m:
        return m["technique_id"]
    return f'{m["source"][:4]} p.{m["page"]}'


if __name__ == "__main__":
    dedupe = "--dedupe" in sys.argv
    print("MODE:", "deduplicated (best chunk per technique/page)" if dedupe else "plain top-3 chunks")

    questions = json.loads(QUESTIONS.read_text(encoding="utf-8"))
    stats = {}
    misses = []

    for q in questions:
        if dedupe:
            results = search_unique(q["query"], q["collection"], k=K)
        else:
            results = search(q["query"], k=K, collection=q["collection"])
        metas = [m for m, d, dist in results]
        rank = first_hit_rank(q, metas)
        s = stats.setdefault(q["collection"], {"n": 0, "hit1": 0, "hitk": 0, "rr": 0.0})
        s["n"] += 1
        if rank:
            s["hitk"] += 1
            s["rr"] += 1 / rank
            if rank == 1:
                s["hit1"] += 1
        else:
            misses.append((q, [describe(m) for m in metas]))
        print(f'Q{q["id"]:>2} [{q["collection"]:<11}] {"HIT (rank " + str(rank) + ")" if rank else "MISS":<12} {q["query"][:60]}')

    print("\n" + "=" * 60)
    print(f'{"collection":<12} {"n":>3} {"hit@1":>7} {"hit@3":>7} {"MRR":>6}')
    tot = {"n": 0, "hit1": 0, "hitk": 0, "rr": 0.0}
    for coll, s in stats.items():
        print(f'{coll:<12} {s["n"]:>3} {s["hit1"]/s["n"]:>7.0%} {s["hitk"]/s["n"]:>7.0%} {s["rr"]/s["n"]:>6.2f}')
        for key in tot:
            tot[key] += s[key]
    print(f'{"overall":<12} {tot["n"]:>3} {tot["hit1"]/tot["n"]:>7.0%} {tot["hitk"]/tot["n"]:>7.0%} {tot["rr"]/tot["n"]:>6.2f}')

    if misses:
        print("\nMISSES (what was retrieved instead):")
        for q, got in misses:
            print(f'  Q{q["id"]} "{q["query"][:55]}" expected {q["expected"]} got {got}')
        # CI gate: exit with an error if retrieval quality drops below the threshold
    if "--min-hit3" in sys.argv:
        threshold = float(sys.argv[sys.argv.index("--min-hit3") + 1])
        score = tot["hitk"] / tot["n"]
        if score < threshold:
            print(f"FAIL: hit@3 {score:.0%} is below the threshold of {threshold:.0%}")
            sys.exit(1)
        print(f"PASS: hit@3 {score:.0%} >= {threshold:.0%}")