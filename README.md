# SOC Copilot

An LLM + RAG assistant that turns ML-detected attack alerts into cited incident response reports.
It is the response layer for my [DFIR detection project](https://github.com/sambhav006/AI-DFIR-Tool): the detector classifies
network traffic, and SOC Copilot explains the alert and recommends what to do, with a source for every step.

**Live demo:** https://soc-copilot-sambhav.streamlit.app/  (free hosting: the app sleeps when idle, so the first load may take a minute)

![screenshot](docs/screenshot.png)

## What it does

1. Takes an alert (JSON with an `attack_type`, severity, confidence, IPs, timestamp).
2. Maps the detector's class to a MITRE ATT&CK technique (`src/mapping.py`).
3. Retrieves context from three ChromaDB collections:
   - **attack** (1,088 chunks): ATT&CK technique descriptions
   - **mitigations** (1,448 chunks): ATT&CK mitigation entries, one per technique and mitigation pair
   - **playbooks** (295 chunks): NIST SP 800-61 Rev. 2 and the CISA Incident & Vulnerability Response Playbooks
4. Asks Gemini to write a structured report using only the numbered sources, with inline citations.
5. Runs automatic checks on the output (citation numbers exist, action steps have a citation or an explicit
   "unsourced" label), and shows every source the model was given.
6. Supports follow-up questions with fresh retrieval.

## Architecture

```
alert JSON -> class-to-technique mapping -> retrieval (attack + mitigations + playbooks)
           -> Gemini (rules: cite, stay proportionate, label unsourced steps)
           -> report + citation checks -> follow-up chat
```

Embeddings: `all-MiniLM-L6-v2` (sentence-transformers). Vector store: ChromaDB. UI: Streamlit.

## Design decisions

- **Deterministic mapping on top of semantic search.** Semantic search alone returned port knocking and
  vulnerability scanning for the query "port scan", missing T1046. The mapping supplies the main technique;
  search only adds more specific sub-techniques.
- **Technique-specific mitigations as a separate collection**, because the NIST and CISA documents describe
  response phases in general and say nothing attack-specific.
- **Proportionate responses.** Early reports told analysts to isolate hosts and forensically image them for a
  simple port scan. The prompt now separates "hardening that applies regardless" from "if compromise is
  confirmed", and keeps isolation and imaging conditional.
- **Unsourced steps are labelled** "(general practice, unsourced)" instead of being given a fake citation.

## Evaluation

Retrieval only, on 30 hand-written queries (`eval/test_questions.json`; run `python src/evaluate.py`):

| Collection | n | hit@1 | hit@3 | MRR |
|---|---|---|---|---|
| ATT&CK techniques | 14 | 57% | 79% | 0.67 |
| Mitigations | 8 | 88% | 100% | 0.94 |
| Playbooks | 8 | 88% | 100% | 0.92 |
| **Overall** | 30 | 73% | 90% | 0.81 |

With deduplication of repeated chunks (`--dedupe`): overall hit@3 93%, MRR 0.82. That change recovered one
of three misses, so treat it as a small effect.

Caveats:
- I wrote the questions after seeing some retrieval results, so they are easier than an independent test.
- Two expected answers (Q7, Q28) were corrected after the first run. The score before the correction was
  hit@3 83%.
- A held-out set written without looking at the results is [NOT YET RUN / RESULT: ...].

## Known limitations

- Short or ambiguous queries retrieve poorly ("port scan"), and similar sub-techniques get confused
  (password spraying vs. password guessing).
- The citation check verifies that citations exist and that action steps carry one. It does **not** verify that the
  source supports the claim. Manual audit: [RESULT, e.g. "checked N citations in 3 reports; X were supported"].
- NIST and CISA playbooks are generic response frameworks (the CISA one is written for US federal agencies).
- The class-to-technique mapping involves judgment (for example, "Brute Force" covers both FTP and SSH guessing).
- Tested on synthetic sample alerts, not live output from the detector.
- NIST SP 800-61 Rev. 2 has been withdrawn and superseded by Rev. 3; Rev. 2 is used here.
- The demo uses a shared free-tier Gemini key with a per-session request cap. Do not paste real incident data.
  Reports are AI-generated and need analyst review.

## Run locally

```bash
pip install -r requirements.txt
export GEMINI_API_KEY=your_key        # Windows: set GEMINI_API_KEY=your_key
streamlit run app.py
```

The prebuilt `chroma_db/` is included. To rebuild it from scratch:

```bash
python src/download_attack.py        # downloads ATT&CK (about 40 MB)
python src/embed_store.py
python src/ingest_mitigations.py
python src/ingest_playbooks.py       # reads the PDFs in data/playbooks
```

## Data sources and attribution

- MITRE ATT&CK(R) Enterprise, (c) The MITRE Corporation, used under MITRE's ATT&CK terms of use.
- NIST SP 800-61 Rev. 2, Computer Security Incident Handling Guide.
- CISA, Cybersecurity Incident & Vulnerability Response Playbooks (TLP:CLEAR).