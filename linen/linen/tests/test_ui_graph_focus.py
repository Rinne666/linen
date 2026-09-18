from pathlib import Path


HTML_PATH = Path(__file__).parents[2] / "src" / "linen" / "server" / "static" / "index.html"


def test_graph_defaults_to_current_and_exposes_four_projection_views() -> None:
    html = HTML_PATH.read_text(encoding="utf-8")

    assert "graphView: 'current'" in html
    assert "setGraphView('current')" in html
    assert "setGraphView('findings')" in html
    assert "setGraphView('full')" in html
    assert "setGraphView('list')" in html
    assert 'aria-label="Show current execution focus"' in html
    assert 'aria-label="Show full blackboard map"' in html


def test_current_projection_has_priority_order_and_non_empty_anchor_fallback() -> None:
    html = HTML_PATH.read_text(encoding="utf-8")

    current_start = html.index("currentFocusIntents()")
    current_end = html.index("currentGraphFocus()", current_start)
    current_logic = html[current_start:current_end]
    assert "const running = open.filter(intent => Boolean(intent.worker));" in current_logic
    assert "['blocked', 'transient'].includes(error?.classification)" in current_logic
    assert "const queued = open.filter(intent => !intent.worker).slice(0, 3);" in current_logic
    assert "currentGraphFocus()" in html
    assert "for (const anchor of ['origin', 'goal'])" in html
    assert ".filter(fact => this.isCurrentFallbackFact(fact)).slice(-4)" in html
    assert "if (!nodeIds.size)" in html


def test_full_map_keeps_existing_filters_and_projection_is_client_side() -> None:
    html = HTML_PATH.read_text(encoding="utf-8")

    assert "x-show=\"graphView === 'full'\" x-model=\"graphKindFilter\"" in html
    assert "x-show=\"graphView === 'full'\" x-model=\"graphStateFilter\"" in html
    assert "graphFactMatchesKind(fact)" in html
    assert "graphIntentMatchesFilters(intent)" in html
    assert "const findingsFocus = this.graphView === 'findings' ? this.findingsGraphFocus() : null;" in html
    assert "const filterVisible = this.graphView !== 'full'" in html
    assert "node.toggleClass('filtered-out', !visible);" in html


def test_current_focus_uses_static_emphasis_and_avoids_continuous_pulse() -> None:
    html = HTML_PATH.read_text(encoding="utf-8")

    assert "node.current-focus" in html
    assert "node.current-primary" in html
    assert "node.current-context" in html
    assert "edge:not(.current-edge):not(.focus)" in html
    assert "if (this.graphView === 'current')" in html
    assert "node.removeScratch('_pulseActive');" in html
