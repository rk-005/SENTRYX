"""
SENTRYX — charts.py
All Plotly chart factories. Fixed color formats, no crashes, dark SOC theme.
Every function returns go.Figure or a safe fallback — never raises.
"""
from __future__ import annotations
from collections import Counter
import plotly.graph_objects as go

# ── Design tokens ──────────────────────────────────────────────────────────────
BG      = "rgba(0,0,0,0)"
GRID    = "#0e1a2a"
TEXT    = "#7a9ab8"
BLUE    = "#00eaff"
GREEN   = "#00e676"
YELLOW  = "#ffd60a"
RED     = "#ff3b3b"
FONT    = "Rajdhani, Share Tech Mono, monospace"

_THREAT = {"SAFE": GREEN,  "WARNING": YELLOW, "CRITICAL": RED}
_ACTION = {"ALLOW": GREEN, "MASK": YELLOW,   "BLOCK": RED}

# Pre-built safe rgba strings — avoids all "invalid color" Plotly errors
_FILL = {
    GREEN:  "rgba(0,230,118,0.12)",
    YELLOW: "rgba(255,214,10,0.12)",
    RED:    "rgba(255,59,59,0.12)",
    BLUE:   "rgba(0,234,255,0.07)",
}
_BORDER = {
    GREEN:  "rgba(0,230,118,0.45)",
    YELLOW: "rgba(255,214,10,0.45)",
    RED:    "rgba(255,59,59,0.45)",
    BLUE:   "rgba(0,234,255,0.30)",
}

_LAYOUT = dict(
    paper_bgcolor=BG,
    plot_bgcolor=BG,
    font=dict(family=FONT, color=TEXT, size=12),
    margin=dict(l=6, r=6, t=28, b=6),
    xaxis=dict(showgrid=True,  gridcolor=GRID, zeroline=False,
               tickfont=dict(size=10, family=FONT)),
    yaxis=dict(showgrid=True,  gridcolor=GRID, zeroline=False,
               tickfont=dict(size=10, family=FONT)),
    legend=dict(bgcolor="rgba(0,0,0,0)", font=dict(size=10, family=FONT)),
)


def _title(txt: str) -> dict:
    return dict(text=txt, font=dict(size=11, color=BLUE, family=FONT), x=0.01, y=0.97)


def _empty(title: str = "") -> go.Figure:
    """Safe empty figure — never raises, never shows ugly default."""
    fig = go.Figure()
    fig.add_annotation(
        text="NO DATA YET", x=0.5, y=0.5,
        xref="paper", yref="paper", showarrow=False,
        font=dict(size=13, color="#1e3a5f", family=FONT),
    )
    layout: dict = dict(
        paper_bgcolor=BG,
        plot_bgcolor=BG,
        font=dict(family=FONT, color=TEXT, size=12),
        margin=dict(l=6, r=6, t=28, b=6),
        height=180,
        showlegend=False,
        xaxis=dict(visible=False),
        yaxis=dict(visible=False),
    )
    if title:
        layout["title"] = _title(title)
    fig.update_layout(**layout)
    return fig


# ══════════════════════════════════════════════════════════════════════════════
# 1. RISK GAUGE
# ══════════════════════════════════════════════════════════════════════════════
def risk_gauge(risk_score: float) -> go.Figure:
    try:
        score = float(risk_score)
    except (TypeError, ValueError):
        score = 0.0

    if score >= 70:
        bar_c, label = RED, "CRITICAL"
    elif score >= 40:
        bar_c, label = YELLOW, "WARNING"
    else:
        bar_c, label = GREEN, "SAFE"

    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=score,
        number=dict(font=dict(size=58, color=bar_c, family=FONT), valueformat=".0f"),
        gauge=dict(
            axis=dict(
                range=[0, 100], tickwidth=1, tickcolor=GRID,
                tickfont=dict(color=TEXT, size=9, family=FONT), nticks=6,
            ),
            bar=dict(color=bar_c, thickness=0.2),
            bgcolor="rgba(0,0,0,0)",
            borderwidth=0,
            steps=[
                dict(range=[0,  40], color="rgba(0,230,118,0.05)"),
                dict(range=[40, 70], color="rgba(255,214,10,0.05)"),
                dict(range=[70,100], color="rgba(255,59,59,0.06)"),
            ],
            threshold=dict(
                line=dict(color=bar_c, width=3),
                thickness=0.72, value=score,
            ),
        ),
        title=dict(
            text=(
                f'<span style="font-size:10px;letter-spacing:3px;color:{BLUE}">RISK SCORE</span>'
                f'<br><span style="font-size:10px;color:{bar_c};letter-spacing:2px">{label}</span>'
            ),
            font=dict(family=FONT),
        ),
    ))
    fig.update_layout(
        paper_bgcolor=BG,
        font=dict(family=FONT, color=TEXT),
        margin=dict(l=14, r=14, t=14, b=4),
        height=210,
    )
    return fig


# ══════════════════════════════════════════════════════════════════════════════
# 2. RISK TREND
# ══════════════════════════════════════════════════════════════════════════════
def risk_trend(history: list[dict]) -> go.Figure:
    if not history:
        return _empty("RISK TREND")

    xs = list(range(1, len(history) + 1))
    ys = [float(h.get("risk_score", 0)) for h in history]
    # marker color per point — must be a list of plain hex strings
    mc = [_THREAT.get(str(h.get("threat_level", "SAFE")), BLUE) for h in history]

    fig = go.Figure()
    fig.add_trace(go.Scatter(
        x=xs, y=ys,
        mode="lines+markers",
        line=dict(color=BLUE, width=2),
        fill="tozeroy",
        fillcolor="rgba(0,234,255,0.06)",
        marker=dict(
            color=mc,          # list of hex strings — valid Plotly format
            size=8,
            line=dict(color="#060b14", width=1),
        ),
        hovertemplate="Step %{x} · Risk %{y:.0f}<extra></extra>",
    ))

    # threshold reference lines
    for thr, col, lbl in [(70, RED, "CRITICAL"), (40, YELLOW, "WARNING")]:
        fig.add_hline(
            y=thr, line_dash="dot",
            line=dict(color=col, width=1),
            opacity=0.45,
            annotation_text=lbl,
            annotation_font=dict(size=8, color=col, family=FONT),
            annotation_position="right",
        )

    layout = dict(_LAYOUT)
    layout.update(
        title=_title("RISK TREND"),
        xaxis=dict(showgrid=True, gridcolor=GRID, zeroline=False,
                   tickfont=dict(size=10, family=FONT),
                   title=dict(text="Step", font=dict(size=10, color=TEXT, family=FONT)),
                   dtick=1),
        yaxis=dict(showgrid=True, gridcolor=GRID, zeroline=False,
                   tickfont=dict(size=10, family=FONT),
                   range=[0, 108],
                   title=dict(text="Score", font=dict(size=10, color=TEXT, family=FONT))),
        height=190,
        showlegend=False,
    )
    fig.update_layout(**layout)
    return fig


# ══════════════════════════════════════════════════════════════════════════════
# 3. ACTION DISTRIBUTION
# ══════════════════════════════════════════════════════════════════════════════
def action_distribution(history: list[dict]) -> go.Figure:
    if not history:
        return _empty("ACTIONS")

    actions = ["ALLOW", "MASK", "BLOCK"]
    counts  = Counter(str(h.get("action", "")) for h in history)
    values  = [counts.get(a, 0) for a in actions]
    colors  = [_ACTION.get(a, BLUE) for a in actions]
    fills   = [_FILL.get(c, "rgba(0,234,255,0.07)") for c in colors]

    fig = go.Figure(go.Bar(
        x=actions, y=values,
        marker=dict(
            color=fills,                    # rgba strings — safe
            line=dict(color=colors, width=2),
        ),
        text=values,
        textposition="outside",
        textfont=dict(color=colors, size=14, family=FONT),
        hovertemplate="%{x}: %{y}<extra></extra>",
        width=[0.45, 0.45, 0.45],
    ))
    layout = dict(_LAYOUT)
    layout.update(
        title=_title("ACTIONS"),
        xaxis=dict(showgrid=False, tickfont=dict(size=12, color=TEXT, family=FONT)),
        yaxis=dict(showgrid=True, gridcolor=GRID, zeroline=False,
                   tickfont=dict(size=10, family=FONT),
                   title=dict(text="Count", font=dict(size=10, color=TEXT, family=FONT))),
        height=180,
        bargap=0.38,
    )
    fig.update_layout(**layout)
    return fig


# ══════════════════════════════════════════════════════════════════════════════
# 4. THREAT DONUT
# ══════════════════════════════════════════════════════════════════════════════
def threat_donut(history: list[dict]) -> go.Figure:
    if not history:
        return _empty("THREATS")

    counts = Counter(str(h.get("threat_level", "SAFE")) for h in history)
    labels = list(counts.keys())
    values = list(counts.values())
    colors = [_THREAT.get(l, BLUE) for l in labels]
    fills  = [_FILL.get(c, "rgba(0,234,255,0.07)") for c in colors]

    fig = go.Figure(go.Pie(
        labels=labels,
        values=values,
        marker=dict(
            colors=fills,                   # list of rgba strings — safe
            line=dict(color=colors, width=2),
        ),
        hole=0.62,
        pull=[0.04] * len(labels),
        textinfo="label+percent",
        textfont=dict(size=10, family=FONT, color=TEXT),
        hovertemplate="%{label}: %{value}<extra></extra>",
    ))
    fig.update_layout(
        paper_bgcolor=BG,
        font=dict(family=FONT, color=TEXT),
        title=_title("THREATS"),
        margin=dict(l=0, r=0, t=28, b=0),
        height=185,
        showlegend=False,
    )
    return fig


# ══════════════════════════════════════════════════════════════════════════════
# 5. ENTITY FREQUENCY
# ══════════════════════════════════════════════════════════════════════════════
def entity_frequency(history: list[dict]) -> go.Figure:
    all_ents: list[str] = []
    for h in history or []:
        for e in h.get("detected_entities", []):
            # normalise EntityType.EMAIL → "EMAIL"
            s = str(e)
            if "." in s:
                s = s.split(".")[-1]
            all_ents.append(s)

    if not all_ents:
        return _empty("ENTITIES")

    top    = Counter(all_ents).most_common(7)
    labels = [c[0] for c in top]
    values = [c[1] for c in top]

    fill_red   = "rgba(255,59,59,0.10)"
    border_red = RED

    fig = go.Figure(go.Bar(
        x=values, y=labels,
        orientation="h",
        marker=dict(
            color=fill_red,
            line=dict(color=border_red, width=1.5),
        ),
        text=values,
        textposition="outside",
        textfont=dict(color=border_red, size=12, family=FONT),
        hovertemplate="%{y}: %{x}<extra></extra>",
    ))
    layout = dict(_LAYOUT)
    layout.update(
        title=_title("ENTITY FREQ"),
        xaxis=dict(showgrid=True, gridcolor=GRID, zeroline=False,
                   tickfont=dict(size=10, family=FONT),
                   title=dict(text="Count", font=dict(size=10, color=TEXT, family=FONT))),
        yaxis=dict(showgrid=False, tickfont=dict(size=10, family=FONT, color=TEXT)),
        height=max(160, 40 + len(labels) * 30),
        bargap=0.3,
        showlegend=False,
    )
    fig.update_layout(**layout)
    return fig


# ══════════════════════════════════════════════════════════════════════════════
# 6. MINI KPI SPARKLINE  (optional — used in top stats row)
# ══════════════════════════════════════════════════════════════════════════════
def risk_sparkline(history: list[dict]) -> go.Figure:
    """Tiny inline sparkline for the top KPI strip."""
    if not history:
        return _empty()

    ys = [float(h.get("risk_score", 0)) for h in history]
    xs = list(range(len(ys)))

    last_c = _THREAT.get(str(history[-1].get("threat_level", "SAFE")), BLUE)

    fig = go.Figure(go.Scatter(
        x=xs, y=ys,
        mode="lines",
        line=dict(color=last_c, width=1.5),
        fill="tozeroy",
        fillcolor=_FILL.get(last_c, "rgba(0,234,255,0.07)"),
        hoverinfo="skip",
    ))
    fig.update_layout(
        paper_bgcolor=BG, plot_bgcolor=BG,
        margin=dict(l=0, r=0, t=0, b=0),
        height=48,
        xaxis=dict(visible=False),
        yaxis=dict(visible=False, range=[0, 105]),
        showlegend=False,
    )
    return fig