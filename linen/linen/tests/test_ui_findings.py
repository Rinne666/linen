from pathlib import Path


HTML_PATH = Path(__file__).parents[2] / "src" / "linen" / "server" / "static" / "index.html"


def html() -> str:
    return HTML_PATH.read_text(encoding="utf-8")


def test_vulnerability_trace_detail_uses_saved_proof_and_citations() -> None:
    source = html()

    assert "this.findingEvidenceFact(fact)?.proof?.claim_kind === 'vulnerability_trace'" in source
    assert "this.findingEvidenceFact(fact)?.proof?.attributes?.trace" in source
    assert "this.findingEvidenceFact(fact)?.proof?.attributes?.endpoint_id" in source
    assert "fact?.proof?.attributes?.candidate_outcome" in source
    assert "Confirmed candidate" in source
    assert "formatEndpointId(vulnerabilityEndpoint(selectedFactRecord()))" in source
    assert "step.symbol" in source
    assert "`${step.file}:${step.line}`" in source
    assert "step.observation" in source
    assert 'x-text="formatTraceRelation(step.relation)"' in source
    assert "`Relation · ${formatTraceRelation(step.relation)}`" not in source
    assert "entry: 'ENTRY'" in source
    assert "reaches: 'REACHES'" in source
    assert "return labels[value] || value;" in source
    assert "factEvidenceCitations(selectedFactRecord())" in source
    assert "citation.code" in source


def test_null_endpoint_is_hidden_without_placeholder() -> None:
    source = html()

    assert '<template x-if="vulnerabilityEndpoint(selectedFactRecord())">' in source
    assert "typeof endpoint === 'string' && endpoint.trim() ? endpoint.trim() : ''" in source
    assert "Unknown endpoint" not in source


def test_legacy_fact_keeps_plain_evidence_display() -> None:
    source = html()

    assert '!isVulnerabilityTraceFact(selectedFactRecord()) && selectedFactRecord().evidence' in source
    assert 'x-text="selectedFactRecord().evidence"' in source


def test_frontend_has_no_bootstrap_specific_ui_or_graph_semantics() -> None:
    assert "bootstrap" not in html().lower()


def test_findings_defaults_to_user_list_and_keeps_graph_entry() -> None:
    source = html()

    assert "findingsMode: 'list'" in source
    assert "if (view === 'findings') this.findingsMode = 'list';" in source
    assert "primaryFindingFacts()" in source
    assert "View graph" in source
    assert "showFindingsGraph()" in source
    assert "findingsGraphFocus()" in source


def test_primary_finding_identity_uses_semantic_type_and_promotion_edges() -> None:
    source = html()
    start = source.index("isPrimaryFindingFact(fact)")
    end = source.index("primaryFindingFacts()", start)
    predicate = source[start:end]

    assert "['candidate_finding', 'confirmed_finding'].includes(semantic)" in predicate
    assert "!this.promotedFindingIds().has(fact.id)" in predicate
    assert "promotedFindingIds()" in source
    assert "edge.relation_type === 'promotes_to'" in source


def test_candidate_disposition_is_not_a_product_finding() -> None:
    source = html()
    assert "findingContextTypes()" in source
    assert "isFindingContextFact(fact)" in source


def test_current_summary_reuses_focus_priority_and_existing_work_data() -> None:
    source = html()
    start = source.index("currentSummary() {")
    end = source.index("currentGraphFocus()", start)
    summary = source[start:end]

    assert "const focused = this.currentFocusIntents();" in summary
    assert "this.intentError" in summary
    assert "intent.action || intent.type" in source
    assert "intent.target" in source
    assert "No active work" in summary
    assert "Audit completed" in summary
    assert "work item${queuedCount === 1 ? '' : 's'} queued" in summary
    assert "fetch(" not in summary


def test_primary_status_and_current_summary_explain_next_owner() -> None:
    source = html()

    start = source.index("projectPrimaryStatus() {")
    end = source.index("executionStatusDotClass()", start)
    status = source[start:end]
    assert "Action required" in status
    assert "Audit blocked" in status
    assert "Audit in progress" in status
    assert "The system will continue automatically" in status
    assert "technicalConfirmationCandidates()" in status

    summary_start = source.index("currentSummary() {")
    summary_end = source.index("currentGraphFocus()", summary_start)
    summary = source[summary_start:summary_end]
    assert "nextMode" in summary
    assert "user_action" in summary
    assert "automatic" in summary
    assert "actionTarget" in summary
    assert "findingSummaryLabel()" in source
    assert "candidate${candidates === 1 ? '' : 's'} ·" in source


def test_confirmed_finding_reuses_candidate_evidence_and_findings_are_the_default_audit_view() -> None:
    source = html()
    assert "findingEvidenceFact(fact)" in source
    assert "fact.proof?.attributes?.candidate_id" in source
    assert "this.graphView = 'findings';" in source
    assert "this.project.project.audit_mode !== 'none'" in source
    assert '>Completion</button>' in source
