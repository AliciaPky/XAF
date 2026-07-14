"""Plotly chart builders for the XAF console. Colours come from theme.py so the
charts stay in sync with the rest of the design."""

import plotly.graph_objects as go

from theme import BG, BLUE, CARD, FAINT, LINE, TEXT


def area_chart(x, y, color, y_range, height=220):
    """Filled spline line chart — used for the coverage trend."""
    fig = go.Figure()
    fill = "rgba(79,157,255,0.16)" if color == BLUE else "rgba(248,113,113,0.14)"
    fig.add_trace(go.Scatter(
        x=x, y=y, mode="lines+markers",
        line=dict(color=color, width=2.5, shape="spline"),
        marker=dict(size=7, color=BG, line=dict(color=color, width=2)),
        fill="tozeroy", fillcolor=fill))
    fig.update_layout(
        height=height, margin=dict(l=8, r=8, t=6, b=6),
        paper_bgcolor="rgba(0,0,0,0)", plot_bgcolor="rgba(0,0,0,0)",
        font=dict(family="JetBrains Mono", size=11, color=FAINT), showlegend=False,
    )
    fig.update_yaxes(range=y_range, gridcolor=LINE, zeroline=False)
    fig.update_xaxes(gridcolor="rgba(0,0,0,0)", showticklabels=False)
    return fig


def donut(signatures, total):
    """Attack-type donut. `signatures` is a list of (label, count, pct, colour)."""
    fig = go.Figure(go.Pie(
        labels=[s[0] for s in signatures], values=[s[1] for s in signatures], hole=0.62,
        marker=dict(colors=[s[3] for s in signatures], line=dict(color=CARD, width=2)),
        textinfo="none", sort=False))
    fig.update_layout(
        height=170, margin=dict(l=0, r=0, t=0, b=0),
        paper_bgcolor="rgba(0,0,0,0)", showlegend=False,
        annotations=[dict(text=f"<b>{total}</b><br>TOTAL", x=0.5, y=0.5, showarrow=False,
                          font=dict(family="JetBrains Mono", size=15, color=TEXT))])
    return fig
