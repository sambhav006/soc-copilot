import os
import sys

os.environ.setdefault("GEMINI_API_KEY", "dummy-key-for-tests")   # no real API calls are made
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from generate import check_citations, uncited_lines
from mapping import ATTACK_MAP


def test_invalid_citation_is_flagged():
    cited, invalid = check_citations("Do X [1]. Do Y [9].", 3)
    assert cited == [1, 9]
    assert invalid == [9]


def test_step_without_citation_is_flagged():
    report = "## Immediate Containment Steps\n* Block the IP [1]\n* Reboot the server\n"
    assert uncited_lines(report) == ["* Reboot the server"]


def test_unsourced_label_is_allowed():
    report = "## Evidence to Preserve\n* Keep logs (general practice, unsourced)\n"
    assert uncited_lines(report) == []


def test_every_class_maps_to_a_technique():
    for name, info in ATTACK_MAP.items():
        assert info["techniques"], name
        assert all(t.startswith("T") for t in info["techniques"]), name


def test_port_scanning_maps_to_t1046():
    from retriever import retrieve_for_alert
    results = retrieve_for_alert("Port Scanning", k=2)
    assert results[0][0]["technique_id"] == "T1046"
    assert results[0][3] == "mapped"