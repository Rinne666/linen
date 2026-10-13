"""Deterministic, standalone SVG of recorded facts, intents and reviews."""
from __future__ import annotations

from collections import defaultdict, deque
import re
import unicodedata
from xml.etree import ElementTree as ET


def render_graph_svg(snapshot: dict) -> str:
    """Render persisted relationships without a browser or a layout service.

    Node identities include their kind. Cycles and disconnected historical
    nodes remain visible; they must never prevent exporting a partial audit.
    All model-provided labels are XML text, never markup or URLs.
    """
    nodes: dict[tuple[str, str], dict] = {}
    for key, kind in (("facts", "fact"), ("intents", "intent"), ("reviews", "review")):
        for item in snapshot.get(key, []):
            nodes[kind, item["id"]] = item
    edges: set[tuple[tuple[str, str], tuple[str, str], str]] = set()

    def connect(source: tuple[str, str], target: tuple[str, str], relation: str) -> None:
        if source in nodes and target in nodes:
            edges.add((source, target, relation))

    for item in snapshot.get("intents", []):
        for source in item.get("from", []):
            connect(("fact", source), ("intent", item["id"]), "input")
        if item.get("to"):
            connect(("intent", item["id"]), ("fact", item["to"]), "result")
    for edge in snapshot.get("graph_edges", []):
        connect((edge["source_kind"], edge["source_id"]),
                (edge["target_kind"], edge["target_id"]), edge["relation_type"])
    for item in snapshot.get("reviews", []):
        source, target = ("review", item["id"]), ("fact", item["fact_id"])
        if not any(left == source and right == target for left, right, _ in edges):
            connect(source, target, "reviews")

    layers = _causal_layers(set(nodes), edges)
    # Reviews annotate their subject; their backwards confirmation edges are
    # not causal cycles and should not collapse the entire graph into one lane.
    for key, item in nodes.items():
        if key[0] == "review":
            layers[key] = layers.get(("fact", item["fact_id"]), -1) + 1
    lanes: dict[int, list] = defaultdict(list)
    for key in sorted(nodes):
        lanes[layers[key]].append(key)
    width = max(960, 64 + len(lanes) * 316)
    height = max(360, 192 + max((len(lane) for lane in lanes.values()), default=0) * 120)
    svg = ET.Element("svg", {"xmlns": "http://www.w3.org/2000/svg", "width": str(width),
                            "height": str(height), "viewBox": f"0 0 {width} {height}",
                            "role": "img", "aria-labelledby": "graph-title graph-desc"})

    def element(parent, tag: str, attrs: dict | None = None, text: object | None = None):
        node = ET.SubElement(parent, tag, {k: str(v) for k, v in (attrs or {}).items()})
        if text is not None:
            node.text = re.sub(r"[^\x09\x0a\x0d\x20-\ud7ff\ue000-\ufffd\U00010000-\U0010ffff]", "", str(text))
        return node

    project = snapshot["project"]
    heading = f"{project['title']} — Audit evidence graph"
    metadata = (f"{project['id']} · {project['status']} · revision {project['graph_revision']} · "
                f"source {project['source_generation']} · plan {project['plan_revision']} · "
                f"{len(nodes)} nodes / {len(edges)} edges")
    element(svg, "title", {"id": "graph-title"}, heading)
    element(svg, "desc", {"id": "graph-desc"}, metadata + ". Arrows represent recorded relationships, not confirmation.")
    defs = element(svg, "defs")
    marker = element(defs, "marker", {"id": "arrow", "viewBox": "0 0 10 10", "refX": 9,
                                     "refY": 5, "markerWidth": 6, "markerHeight": 6, "orient": "auto"})
    element(marker, "path", {"d": "M 0 0 L 10 5 L 0 10 z", "fill": "#94a3b8"})
    element(svg, "rect", {"width": width, "height": height, "fill": "#f8fafc"})
    text_attrs = {"font-family": "system-ui, sans-serif", "fill": "#0f172a"}
    element(svg, "text", {**text_attrs, "x": 32, "y": 38, "font-size": 22, "font-weight": 600},
            _label_lines(heading, max(40, (width - 64) // 13), 1)[0])
    element(svg, "text", {**text_attrs, "x": 32, "y": 66, "font-size": 12}, metadata)
    positions = {key: (32 + layer * 316, 104 + row * 120)
                 for layer, lane in sorted(lanes.items()) for row, key in enumerate(lane)}
    for source, target, relation in sorted(edges):
        x1, y1 = positions[source]
        x2, y2 = positions[target]
        if x2 > x1:
            x1 += 252
            y1 += 42
            y2 += 42
            mid = (x1 + x2) / 2
            path = f"M{x1},{y1} C{mid},{y1} {mid},{y2} {x2},{y2}"
        else:
            x1 += 252
            x2 += 252
            y1 += 28
            y2 += 56
            bend = max(x1, x2) + 38
            path = f"M{x1},{y1} C{bend},{y1} {bend},{y2} {x2},{y2}"
        link = element(svg, "path", {"d": path, "fill": "none", "stroke": "#94a3b8",
                                      "stroke-width": 1.3, "marker-end": "url(#arrow)"})
        element(link, "title", text=f"{source[0]}:{source[1]} → {target[0]}:{target[1]} · {relation}")
    for key, item in sorted(nodes.items()):
        kind, identifier = key
        x, y = positions[key]
        status = item.get("status") or item.get("verdict") or ("concluded" if item.get("concluded_at") else "pending")
        semantic = item.get("semantic_type") or item.get("type") or kind
        color = "#64748b"
        if kind == "review":
            color = "#7c3aed"
        elif semantic == "confirmed_finding":
            color = "#15803d"
        elif semantic == "candidate_finding":
            color = "#b45309"
        elif status in {"false_positive", "rejected", "invalidated"}:
            color = "#be123c"
        elif kind == "fact":
            color = "#0369a1"
        label = item.get("display_title") or item.get("description") or item.get("summary") or identifier
        group = element(svg, "g", {"data-kind": kind, "data-id": identifier})
        element(group, "title", text=f"{identifier} · {semantic} · {status}\n{label}")
        element(group, "rect", {"x": x, "y": y, "width": 252, "height": 88, "rx": 6,
                                 "fill": "#fff", "stroke": color, "stroke-width": 1.5})
        element(group, "text", {**text_attrs, "x": x + 12, "y": y + 19, "font-size": 11, "fill": color},
                f"{identifier} · {status}"[:38])
        for line_number, line in enumerate(_label_lines(label, 32, 2)):
            element(group, "text", {**text_attrs, "x": x + 12, "y": y + 41 + line_number * 16, "font-size": 12}, line)
        element(group, "text", {**text_attrs, "x": x + 12, "y": y + 77, "font-size": 10, "fill": "#64748b"},
                ("historical · " if item.get("legacy") else "") + str(semantic)[:32])
    element(svg, "text", {**text_attrs, "x": 32, "y": height - 32, "font-size": 12},
            "Blue: evidence · Amber: candidate · Green: confirmed finding · Purple: review · Grey: task / pending")
    return ET.tostring(svg, encoding="unicode", xml_declaration=True)


def _causal_layers(keys: set[tuple[str, str]], edges: set[tuple]) -> dict[tuple[str, str], int]:
    """Condense strongly connected components before laying out the DAG.

    Proof relations can point both ways. A cyclic proof cluster must not pull
    every downstream summary into its lane. Iterative DFS also handles long
    audit histories without hitting Python's recursion limit.
    """
    keys = {key for key in keys if key[0] != "review"}
    forward = {key: set() for key in keys}
    backward = {key: set() for key in keys}
    for source, target, _ in edges:
        if source in keys and target in keys:
            forward[source].add(target)
            backward[target].add(source)
    visited, order = set(), []
    for root in sorted(keys):
        stack = [(root, False)]
        while stack:
            key, expanded = stack.pop()
            if expanded:
                order.append(key)
            elif key not in visited:
                visited.add(key)
                stack.append((key, True))
                stack.extend((child, False) for child in sorted(forward[key], reverse=True) if child not in visited)
    components = {}
    component_count = 0
    for root in reversed(order):
        if root in components:
            continue
        stack = [root]
        components[root] = component_count
        while stack:
            for parent in sorted(backward[stack.pop()]):
                if parent not in components:
                    components[parent] = component_count
                    stack.append(parent)
        component_count += 1
    successors = {index: set() for index in range(component_count)}
    incoming = dict.fromkeys(successors, 0)
    for source, children in forward.items():
        for target in children:
            left, right = components[source], components[target]
            if left != right and right not in successors[left]:
                successors[left].add(right)
                incoming[right] += 1
    ready = deque(sorted(index for index, count in incoming.items() if count == 0))
    levels = dict.fromkeys(successors, 0)
    while ready:
        source = ready.popleft()
        for target in sorted(successors[source]):
            levels[target] = max(levels[target], levels[source] + 1)
            incoming[target] -= 1
            if incoming[target] == 0:
                ready.append(target)
    return {key: levels[components[key]] for key in keys}


def _label_lines(value: str, width: int, limit: int) -> list[str]:
    """Bound visual width for Latin and wide CJK source/worker labels."""
    remaining = " ".join(value.split())
    lines = []
    while remaining and len(lines) < limit:
        used = end = 0
        for character in remaining:
            size = 2 if unicodedata.east_asian_width(character) in {"W", "F"} else 1
            if used + size > width:
                break
            used += size
            end += 1
        line, remaining = remaining[:end], remaining[end:]
        if remaining and len(lines) == limit - 1:
            line = line[:-1] + "…"
        lines.append(line)
    return lines or [""]
