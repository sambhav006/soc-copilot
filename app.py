import json
import os
import sys
import streamlit as st

st.set_page_config(page_title="SOC Copilot", page_icon="🛡️", layout="wide")

# On Streamlit Community Cloud the key is stored in Secrets; locally it comes from the environment.
try:
    if "GEMINI_API_KEY" in st.secrets:
        os.environ["GEMINI_API_KEY"] = st.secrets["GEMINI_API_KEY"]
except Exception:
    pass

if not os.environ.get("GEMINI_API_KEY"):
    st.error("GEMINI_API_KEY is not set. Add it to your environment (local) or to Secrets (hosted).")
    st.stop()

sys.path.insert(0, "src")

from generate import generate_report, call_llm, check_citations, uncited_lines, sample_alert
from embed_store import search
from mapping import ATTACK_MAP

MAX_CALLS = 20   # requests per visitor session, to protect the shared free-tier API key
LIMIT_MSG = "Session limit reached. Refresh the page to start a new session."
st.session_state.setdefault("calls", 0)

FOLLOWUP_SYSTEM = """You are a SOC analyst assistant answering a follow-up question about an incident.
Rules:
- Use ONLY the numbered context sources provided. Do not use outside knowledge.
- Cite sources inline like [1] or [2][5], and only when the source directly states the claim.
- If the sources do not cover the question, say "Not covered by the retrieved sources."
- The alert comes from an ML detector, so never describe it as a confirmed compromise.
- Do not invent details that are not in the alert or the sources.
- Be concise and practical."""


def source_label(meta):
    if "mitigation_id" in meta:
        return (f'MITRE ATT&CK mitigation {meta["mitigation_id"]} '
                f'({meta["mitigation_name"]}) for {meta["technique_id"]}')
    if "technique_id" in meta:
        return f'MITRE ATT&CK {meta["technique_id"]} - {meta["name"]}'
    name = "NIST SP 800-61r2" if "nist" in meta["source"].lower() else "CISA IR Playbook"
    return f'{name} (PDF p.{meta["page"]})'


def answer_followup(question, alert, sources, history):
    all_sources = list(sources)
    seen = {s["text"] for s in all_sources}
    for coll in ("attack", "mitigations", "playbooks"):
        for meta, doc, dist in search(question, k=2, collection=coll):
            if doc not in seen:
                seen.add(doc)
                all_sources.append({"label": source_label(meta), "text": doc})

    context = "\n\n".join(
        f'[{i}] {s["label"]}\n{s["text"][:1200]}' for i, s in enumerate(all_sources, start=1)
    )
    convo = "\n".join(f'{m["role"].upper()}: {m["content"]}' for m in history[-4:])
    prompt = (
        f"ALERT (JSON):\n{json.dumps(alert, indent=2)}\n\n"
        f"CONTEXT SOURCES:\n{context}\n\n"
        f"RECENT CONVERSATION:\n{convo}\n\n"
        f"QUESTION: {question}"
    )
    return call_llm(prompt, system=FOLLOWUP_SYSTEM), all_sources


# ---------- sidebar ----------
st.sidebar.title("🛡️ SOC Copilot")
st.sidebar.write("Turns ML-detected attack alerts into cited incident response reports "
                 "using MITRE ATT&CK, ATT&CK mitigations, and NIST/CISA playbooks.")
attack_choice = st.sidebar.selectbox("Sample alert type", list(ATTACK_MAP.keys()))

if "alert_text" not in st.session_state:
    st.session_state["alert_text"] = json.dumps(sample_alert("Port Scanning"), indent=2)
if st.sidebar.button("Load sample alert"):
    st.session_state["alert_text"] = json.dumps(sample_alert(attack_choice), indent=2)

counter_box = st.sidebar.empty()
st.sidebar.info("Demo project. Uses a shared free-tier Gemini key, so do not paste real or sensitive "
                "incident data. Reports are AI-generated and need analyst review.")

# ---------- main ----------
st.title("SOC Copilot")
st.caption("Paste an alert from your detector, or load a sample, then generate a report.")

alert_text = st.text_area("Alert JSON (needs an \"attack_type\" field)", key="alert_text", height=260)

if st.button("Generate report", type="primary"):
    if st.session_state["calls"] >= MAX_CALLS:
        st.warning(LIMIT_MSG)
    else:
        try:
            alert = json.loads(alert_text)
            if "attack_type" not in alert:
                raise ValueError("missing attack_type")
        except Exception:
            st.error("Please provide valid JSON that includes an \"attack_type\" field.")
        else:
            st.session_state["calls"] += 1
            with st.spinner("Retrieving sources and writing the report..."):
                try:
                    report, sources = generate_report(alert)
                except Exception as e:
                    st.error(f"Could not generate the report: {e}")
                else:
                    st.session_state.update(alert=alert, report=report, sources=sources, chat=[])

if "report" in st.session_state:
    report, sources = st.session_state["report"], st.session_state["sources"]
    st.divider()
    st.markdown(report)

    cited, invalid = check_citations(report, len(sources))
    bare = uncited_lines(report)
    with st.expander("Citation checks"):
        st.write("Citation numbers used:", cited)
        st.write("Invalid citation numbers:", invalid if invalid else "none")
        st.write("Action steps without a citation:", bare if bare else "none")
        st.caption("These checks confirm that citations exist and point to real sources. "
                   "They do not prove the source supports the claim, so review them.")

    with st.expander("Sources the model was given"):
        for i, s in enumerate(sources, start=1):
            st.markdown(f"**[{i}] {s['label']}**")
            st.caption(s["text"][:700])

    st.divider()
    st.subheader("Ask a follow-up")
    for m in st.session_state["chat"]:
        with st.chat_message(m["role"]):
            st.markdown(m["content"])
            if m.get("srcs"):
                with st.expander("Sources used for this answer"):
                    for i, s in enumerate(m["srcs"], start=1):
                        st.markdown(f"**[{i}]** {s['label']}")

    q = st.chat_input("e.g. What else should I check for this attack?")
    if q:
        if st.session_state["calls"] >= MAX_CALLS:
            st.warning(LIMIT_MSG)
        else:
            st.session_state["calls"] += 1
            with st.chat_message("user"):
                st.markdown(q)
            history = list(st.session_state["chat"])
            st.session_state["chat"].append({"role": "user", "content": q})
            with st.chat_message("assistant"):
                with st.spinner("Searching sources..."):
                    try:
                        ans, srcs = answer_followup(q, st.session_state["alert"], sources, history)
                    except Exception as e:
                        ans, srcs = f"Could not answer right now: {e}", []
                st.markdown(ans)
                if srcs:
                    with st.expander("Sources used for this answer"):
                        for i, s in enumerate(srcs, start=1):
                            st.markdown(f"**[{i}]** {s['label']}")
            st.session_state["chat"].append({"role": "assistant", "content": ans, "srcs": srcs})
counter_box.caption(f"Requests used this session: {st.session_state['calls']} / {MAX_CALLS}")