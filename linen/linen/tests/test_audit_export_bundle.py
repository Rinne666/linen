from __future__ import annotations

import hashlib
import io
import json
import zipfile
from xml.etree import ElementTree as ET

from click.testing import CliRunner

from linen.cli import main
from linen.server.graph_export import render_graph_svg
from test_server_api import client, _create_project


def test_partial_audit_bundle_preserves_graph_and_checksums(client):
    pid = client.post("/projects", json={"title": "Partial audit", "origin": "source",
                                         "audit_mode": "scope"}).json()["project"]["id"]
    intent = client.post(f"/projects/{pid}/intents", json={
        "from": ["origin"], "description": '<script>alert("x")</script> & input',
        "creator": "reasoner",
    }).json()
    response = client.get(f"/projects/{pid}/export?format=bundle")
    assert response.status_code == 200
    assert response.headers["content-type"] == "application/zip"
    with zipfile.ZipFile(io.BytesIO(response.content)) as archive:
        assert set(archive.namelist()) == {
            "report.md", "summary.md", "graph.svg", "snapshot.json", "findings.sarif", "manifest.json",
        }
        manifest = json.loads(archive.read("manifest.json"))
        snapshot = json.loads(archive.read("snapshot.json"))
        assert manifest["project"] == snapshot["project"]
        assert manifest["project"]["status"] == "active"
        assert manifest["completion_gate"]["ready"] is False
        for name, expected in manifest["files"].items():
            data = archive.read(name)
            assert hashlib.sha256(data).hexdigest() == expected["sha256"]
            assert len(data) == expected["bytes"]
        svg = ET.fromstring(archive.read("graph.svg"))
        ns = {"s": "http://www.w3.org/2000/svg"}
        assert not svg.findall(".//s:script", ns)
        assert {node.attrib["data-id"] for node in svg.findall("s:g", ns)} == {"origin", "goal", intent["id"]}
        assert any("input" in title.text for title in svg.findall("s:path/s:title", ns))
        assert "In progress" in archive.read("report.md").decode()
        assert str(snapshot["project"]["graph_revision"]) in "".join(svg.itertext())
    standalone = client.get(f"/projects/{pid}/export?format=svg")
    assert standalone.headers["content-type"].startswith("image/svg+xml")
    assert "sandbox" in standalone.headers["content-security-policy"]
    assert standalone.text == render_graph_svg(snapshot)
    assert client.get("/projects/missing/export?format=bundle").status_code == 404


def test_svg_preserves_cycles_disconnected_nodes_and_node_kinds():
    data = {"project": {"id": "p", "title": "审计 & <图>", "status": "stopped",
                         "graph_revision": 1, "source_generation": 2, "plan_revision": 1},
            "facts": [{"id": "same", "description": "循环\x00\ufffe"}, {"id": "alone", "description": "Detached"}],
            "intents": [{"id": "same", "from": ["same"], "to": "same", "description": "cyclic task"}]}
    result = render_graph_svg(data)
    assert render_graph_svg(data) == result
    tree = ET.fromstring(result)
    groups = tree.findall("{http://www.w3.org/2000/svg}g")
    assert {(node.attrib["data-kind"], node.attrib["data-id"]) for node in groups} == {
        ("fact", "same"), ("fact", "alone"), ("intent", "same"),
    }
    assert "审计 & <图>" in "".join(tree.itertext())
    assert "\x00" not in result
    assert "\ufffe" not in result


def test_review_annotations_do_not_collapse_the_causal_graph():
    data = {"project": {"id": "p", "title": "Audit", "status": "active",
                         "graph_revision": 1, "source_generation": 1, "plan_revision": 1},
            "facts": [{"id": "a"}, {"id": "b"}, {"id": "c"}],
            "intents": [{"id": "i", "from": ["a"], "to": "b"},
                        {"id": "j", "from": ["b"], "to": "c"}],
            "reviews": [{"id": "r", "fact_id": "b", "verdict": "VALID"}],
            "graph_edges": [{"source_kind": "review", "source_id": "r", "target_kind": "fact",
                             "target_id": "b", "relation_type": "confirms"}]}
    root = ET.fromstring(render_graph_svg(data))
    ns = "{http://www.w3.org/2000/svg}"
    positions = {node.attrib["data-id"]: float(node.find(ns + "rect").attrib["x"])
                 for node in root.findall(ns + "g")}
    assert positions["a"] < positions["b"] < positions["c"]
    assert positions["r"] > positions["b"]
    assert not any("fact:b → review:r" in (title.text or "") for title in root.iter(ns + "title"))


def test_proof_cycles_keep_downstream_summary_separate():
    from linen.server.graph_export import _causal_layers

    keys = {("fact", name) for name in ("origin", "candidate", "proof", "summary", "goal")}
    edges = {(("fact", left), ("fact", right), "supports") for left, right in (
        ("origin", "candidate"), ("candidate", "proof"), ("proof", "candidate"),
        ("proof", "summary"), ("summary", "goal"),
    )}
    layers = _causal_layers(keys, edges)
    assert layers["fact", "origin"] < layers["fact", "candidate"]
    assert layers["fact", "candidate"] == layers["fact", "proof"]
    assert layers["fact", "proof"] < layers["fact", "summary"] < layers["fact", "goal"]


def test_zero_finding_reports_preserve_unresolved_source_leads(client):
    pid = _create_project(client)
    intent = client.post(f"/projects/{pid}/intents", json={
        "from": ["origin"], "description": "synthesize source results", "creator": "dispatcher.audit",
    }).json()
    evidence = "coverage_complete: false\nresidual_gaps: 1\n- Unresolved SQL injection lead: private token exposure at app.py:5"
    concluded = client.post(f"/projects/{pid}/intents/{intent['id']}/conclude", json={
        "worker": "dispatcher.audit", "description": "0 confirmed; 1 unresolved source lead",
        "type": "audit_summary", "evidence": evidence,
    })
    assert concluded.status_code == 200, concluded.text
    for format in ("summary", "report"):
        report = client.get(f"/projects/{pid}/export?format={format}")
        assert report.status_code == 200
        assert "Unresolved SQL injection lead: private token exposure at app.py:5" in report.text
        assert "coverage_complete: false" in report.text
    assert "Progress Report" in report.text
    next_intent = client.post(f"/projects/{pid}/intents", json={
        "from": [concluded.json()["fact"]["id"]], "description": "refresh synthesis", "creator": "dispatcher.audit",
    }).json()
    updated = client.post(f"/projects/{pid}/intents/{next_intent['id']}/conclude", json={
        "worker": "dispatcher.audit", "description": "Current candidate is tracked",
        "type": "audit_summary", "evidence": "residual_gaps: 0",
    })
    assert updated.status_code == 200
    latest = client.get(f"/projects/{pid}/export?format=summary").text
    assert "Current candidate is tracked" in latest
    assert "Unresolved SQL injection lead" not in latest


def test_bundle_refreshes_expired_leases_only_once(client, monkeypatch):
    from linen.server.routers import export

    pid = _create_project(client)
    original = export.expire_reason_leases
    calls = []

    def expire(conn, project_id):
        calls.append(project_id)
        original(conn, project_id)

    monkeypatch.setattr(export, "expire_reason_leases", expire)
    assert client.get(f"/projects/{pid}/export?format=bundle").status_code == 200
    assert calls == [pid]


def test_cli_export_checks_integrity_before_replacing_existing_output(client, monkeypatch, tmp_path):
    pid = _create_project(client)
    response = client.get(f"/projects/{pid}/export?format=bundle")

    def fetch(url, **kwargs):
        assert url.endswith(f"/projects/{pid}/export")
        assert kwargs["params"] == {"format": "bundle"}
        return response

    monkeypatch.setattr("linen.cli.requests.get", fetch)
    output = tmp_path / "results/audit.zip"
    args = ["audit-export", "--project-id", pid, "--output", str(output)]
    result = CliRunner().invoke(main, args)
    assert result.exit_code == 0, result.output
    assert output.read_bytes() == response.content
    original = output.read_bytes()
    corrupted = io.BytesIO()
    with zipfile.ZipFile(io.BytesIO(original)) as source, zipfile.ZipFile(corrupted, "w") as target:
        for name in source.namelist():
            target.writestr(name, b"corrupted" if name == "graph.svg" else source.read(name))
    response._content = corrupted.getvalue()
    result = CliRunner().invoke(main, args)
    assert result.exit_code != 0
    assert "integrity check failed: graph.svg" in result.output
    assert output.read_bytes() == original
    assert not list(output.parent.glob(".linen-export-*"))
