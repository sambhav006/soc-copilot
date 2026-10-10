import re
import chromadb
from sentence_transformers import SentenceTransformer
from download_attack import load_techniques

DB_PATH = "chroma_db"
COLLECTION = "attack"
MODEL_NAME = "all-MiniLM-L6-v2"
CHUNK_SIZE = 1200   # characters
OVERLAP = 150

model = SentenceTransformer(MODEL_NAME)


def clean(text):
    text = re.sub(r"\(Citation:[^)]*\)", "", text)       # remove (Citation: ...)
    text = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", text)  # [text](url) -> text
    return re.sub(r"\s+", " ", text).strip()


def chunk_text(text, size=CHUNK_SIZE, overlap=OVERLAP):
    chunks, start = [], 0
    while start < len(text):
        chunks.append(text[start:start + size])
        start += size - overlap
    return chunks


def build_index():
    client = chromadb.PersistentClient(path=DB_PATH)
    try:
        client.delete_collection(COLLECTION)   # rebuild from scratch
    except Exception:
        pass
    col = client.create_collection(COLLECTION, metadata={"hnsw:space": "cosine"})

    ids, docs, metas = [], [], []
    for t in load_techniques():
        if not t["id"]:
            continue
        body = clean(t["description"])
        for i, ch in enumerate(chunk_text(body)):
            # put the ID and name in every chunk so it stays searchable
            docs.append(f'{t["id"]} - {t["name"]}: {ch}')
            ids.append(f'{t["id"]}_{i}')
            metas.append({"source": "MITRE ATT&CK", "technique_id": t["id"], "name": t["name"]})

    print(f"Embedding {len(docs)} chunks...")
    for i in range(0, len(docs), 256):
        batch = docs[i:i + 256]
        embs = model.encode(batch).tolist()
        col.add(ids=ids[i:i + 256], documents=batch,
                embeddings=embs, metadatas=metas[i:i + 256])
    print("Done. Stored", col.count(), "chunks.")


def search(query, k=3, collection=COLLECTION):
    client = chromadb.PersistentClient(path=DB_PATH)
    col = client.get_collection(collection)
    emb = model.encode([query]).tolist()
    res = col.query(query_embeddings=emb, n_results=k)
    return list(zip(res["metadatas"][0], res["documents"][0], res["distances"][0]))


if __name__ == "__main__":
    build_index()
    for q in ["port scan", "brute force SSH password guessing", "denial of service flooding network"]:
        print("\nQUERY:", q)
        for meta, doc, dist in search(q):
            print(f'  {meta["technique_id"]} - {meta["name"]}  (distance {dist:.3f})')