import re
from pathlib import Path
import chromadb
from pypdf import PdfReader
from embed_store import model, chunk_text, search, DB_PATH

PLAYBOOK_DIR = Path("data/playbooks")
COLLECTION = "playbooks"

# pages >= this number are skipped (appendices, scenarios, glossary, etc.)
SKIP_FROM = {
    "nist.sp.800-61r2.pdf": 62,
    "Federal_Government_Cybersecurity_Incident_and_Vulnerability_Response_Playbooks_508C.pdf": 39,
}


def build():
    client = chromadb.PersistentClient(path=DB_PATH)
    try:
        client.delete_collection(COLLECTION)
    except Exception:
        pass
    col = client.create_collection(COLLECTION, metadata={"hnsw:space": "cosine"})

    ids, docs, metas = [], [], []
    for pdf in sorted(PLAYBOOK_DIR.glob("*.pdf")):
        reader = PdfReader(str(pdf))
        print("Reading", pdf.name, f"({len(reader.pages)} pages)")
        for pno, page in enumerate(reader.pages, start=1):
            if pno >= SKIP_FROM.get(pdf.name, 10**6):
                break
            text = re.sub(r"\s+", " ", page.extract_text() or "").strip()
            if len(text) < 200 or text.count("?") > 4:   # skip near-empty and question-list pages
                continue
            for i, ch in enumerate(chunk_text(text, 1200, 150)):
                ids.append(f"{pdf.stem}_p{pno}_{i}")
                docs.append(ch)
                metas.append({"source": pdf.name, "page": pno})

    if not docs:
        print("No PDFs found in", PLAYBOOK_DIR)
        return

    print(f"Embedding {len(docs)} chunks...")
    for i in range(0, len(docs), 256):
        col.add(
            ids=ids[i:i + 256],
            documents=docs[i:i + 256],
            embeddings=model.encode(docs[i:i + 256]).tolist(),
            metadatas=metas[i:i + 256],
        )
    print("Done. Stored", col.count(), "chunks.")


if __name__ == "__main__":
    build()
    tests = [
        "how to contain a denial of service attack",
        "preserve evidence during incident response",
        "steps after detecting brute force login attempts",
    ]
    for q in tests:
        print("\nQUERY:", q)
        for meta, doc, dist in search(q, k=3, collection=COLLECTION):
            print(f'  {meta["source"]} p.{meta["page"]} (distance {dist:.3f})')
            print("    ", doc[:150])