"""Threat Dashboard — security posture and self-healing protection at a glance.

Every number here is computed live from the pipeline output via lib.py:
output/parsed_logs.json, output/clustered_attacks.csv, the generator's rule
traces and the operator approval state.
"""

import html
from datetime import date

import pandas as pd
import streamlit as st

import lib
from charts import area_chart, donut
from theme import AMBER, BLUE, FAINT, GREEN, RED, TEAL, VIOLET, page_header

# Family (attack type) -> colour + display label for the donut. Unknown families
# fall back to a rotating palette so a new attack type still renders.
FAMILY_COLORS = {"sqli": BLUE, "xss": GREEN, "ssti": RED}
FAMILY_LABELS = {"sqli": "SQLi", "xss": "XSS", "ssti": "SSTI"}
_CYCLE = [BLUE, GREEN, RED]

# "bypassed" on disk means CRS didn't catch it — show it as UNCAUGHT in the UI.
STATUS_DISPLAY = {"blocked": "BLOCKED", "bypassed": "UNCAUGHT"}


@st.cache_data(ttl=20, show_spinner=False)
def _build_report_pdf() -> bytes:
    """Cached so the download button doesn't rebuild the PDF on every rerun/refresh
    (it refreshes at most every 20s)."""
    import report
    return report.build_pdf_report()


def _pdf_download_button() -> None:
    st.write("")                                   # nudge down to align with the title
    try:
        data = _build_report_pdf()
    except Exception as e:                          # reportlab missing / build error
        st.caption(f"PDF export unavailable: {e}")
        return
    st.download_button("📄  Generate PDF report", data=data,
                       file_name=f"xaf_report_{date.today():%Y%m%d}.pdf",
                       mime="application/pdf", use_container_width=True)


@st.cache_data(ttl=5)
def load_dashboard_data() -> dict:
    """Read every artefact the dashboard needs, once per refresh."""
    df = lib.load_attacks()
    m = lib.attack_metrics(df)
    total = m["total"]

    coverage_pct = round(m["blocked"] / total * 100, 1) if total else 0.0
    bypass_pct   = round(m["bypassed"] / total * 100, 1) if total else 0.0

    n_generated = lib.generated_rules_count()
    n_approved  = lib.approval_counts().get("approved", 0)
    n_deployed  = lib.count_deployed_rules()
    n_clustered = lib.clustered_count(df)

    # coverage trend (cumulative % caught over time)
    cov = lib.coverage_over_time(df)
    cov_x = [str(t) for t in cov["time"].tolist()] if not cov.empty else []
    cov_y = [float(v) for v in cov["coverage"].tolist()] if not cov.empty else []

    # attack-type breakdown for the donut
    bd = lib.attack_type_breakdown(df)
    signatures = []
    for i, (fam, cnt) in enumerate(zip(bd["family"], bd["count"])):
        key = str(fam).lower()
        pct = round(cnt / total * 100, 1) if total else 0.0
        color = FAMILY_COLORS.get(key, _CYCLE[i % len(_CYCLE)])
        signatures.append((FAMILY_LABELS.get(key, str(fam).upper()), int(cnt), pct, color))

    # today's attacks (newest first)
    attacks = []
    if not df.empty:
        ts_col = pd.to_datetime(df.get("timestamp"), errors="coerce")
        today = pd.Timestamp.now().normalize()
        today_df = df[ts_col.dt.normalize() == today].iloc[::-1]
        for _, r in today_df.iterrows():
            ts = pd.to_datetime(r.get("timestamp"), errors="coerce")
            time_str = ts.strftime("%H:%M:%S") if pd.notna(ts) else "--:--:--"
            status = STATUS_DISPLAY.get(str(r.get("status", "")).lower(), "UNKNOWN")
            rid = pd.to_numeric(r.get("rule_id"), errors="coerce")
            rule_id = str(int(rid)) if pd.notna(rid) else "no rule"
            attacks.append((time_str, status, rule_id,
                            str(r.get("uri", "")), str(r.get("payload", ""))))

    return {
        "empty": df.empty,
        "kpis": [
            ("Total Attacks",   str(total),         "detected in current run", BLUE),
            ("Bypass Rate",     f"{bypass_pct}%",   "uncaught by CRS",         RED),
            ("Coverage",        f"{coverage_pct}%", "blocked by CRS",          GREEN),
            ("Active Clusters", str(m["clusters"]), "DBSCAN groups",           TEAL),
            ("Generated Rules", str(n_generated),   "in review queue",         AMBER),
            ("Approved Rules",  str(n_approved),    "ready to deploy",         VIOLET),
        ],
        "pipeline": [
            ("Detected",  total,       BLUE),
            ("Parsed",    total,       TEAL),
            ("Clustered", n_clustered, VIOLET),
            ("Generated", n_generated, AMBER),
            ("Approved",  n_approved,  GREEN),
            ("Deployed",  n_deployed,  GREEN),
        ],
        "signatures": signatures,
        "attacks": attacks,
        "total": total,
        "coverage_pct": coverage_pct,
        "cov_x": cov_x,
        "cov_y": cov_y,
    }


def render() -> None:
    data = load_dashboard_data()

    hcol, bcol = st.columns([3, 1])
    with hcol:
        st.markdown(page_header("Threat Dashboard",
                                "Security posture and self-healing protection at a glance"),
                    unsafe_allow_html=True)
    with bcol:
        _pdf_download_button()

    if data["empty"]:
        st.info("No parsed attacks yet. Run the parser + clustering to populate "
                "`output/parsed_logs.json` / `output/clustered_attacks.csv`, then refresh.")

    # ── KPI row ──
    for col, (label, val, sub, accent) in zip(st.columns(6), data["kpis"]):
        col.markdown(f"""
          <div class="kpi">
            <div style="display:flex;align-items:center;gap:9px;">
              <div style="width:8px;height:8px;border-radius:2px;background:{accent};"></div>
              <div class="kpi-label">{label}</div>
            </div>
            <div class="kpi-value">{val}</div>
            <div class="kpi-sub">{sub}</div>
          </div>
        """, unsafe_allow_html=True)

    st.write("")

    # ── Coverage trend + attack-type donut ──
    c1, c2 = st.columns([1.8, 1])
    with c1:
        with st.container(border=True):
            st.markdown('<div class="h">Coverage Trend</div>'
                        f'<div class="hsub">Cumulative attacks caught by CRS · now {data["coverage_pct"]}%</div>',
                        unsafe_allow_html=True)
            if data["cov_y"]:
                st.plotly_chart(area_chart(data["cov_x"], data["cov_y"], BLUE, [0, 100]),
                                use_container_width=True, config={"displayModeBar": False})
            else:
                st.caption("No timestamped attacks yet.")
    with c2:
        with st.container(border=True):
            st.markdown('<div class="h">Attack Type</div>', unsafe_allow_html=True)
            if data["signatures"]:
                st.plotly_chart(donut(data["signatures"], data["total"]),
                                use_container_width=True, config={"displayModeBar": False})
                for name, count, pct, color in data["signatures"]:
                    st.markdown(f'<div style="display:flex;align-items:center;gap:10px;font-size:12.5px;margin:4px 12px;">'
                                f'<span style="width:9px;height:9px;border-radius:2px;background:{color};"></span>'
                                f'<span style="flex:1;color:#c7cdd8;">{name}</span>'
                                f'<span class="mono" style="color:{FAINT};">{count} · {pct}%</span></div>',
                                unsafe_allow_html=True)
            else:
                st.caption("No attack-type data yet.")

    st.write("")

    # ── Self-healing pipeline ──
    with st.container(border=True):
        st.markdown('<div class="h">Self-Healing Pipeline</div>'
                    '<div class="hsub" style="margin-bottom:10px;">End-to-end AI-powered protection workflow</div>',
                    unsafe_allow_html=True)
        # One flex row so a connector line can bridge each circle to the next
        # (st.columns can't do this — each column is an isolated DOM block).
        steps = data["pipeline"]
        parts = ['<div class="pipeline">']
        for i, (label, count, color) in enumerate(steps):
            parts.append(
                f'<div class="pstep">'
                f'<div class="num" style="border:2px solid {color};color:{color};">{count}</div>'
                f'<div class="plabel">{label}</div></div>')
            if i < len(steps) - 1:
                nxt = steps[i + 1][2]
                parts.append(f'<div class="pline" '
                             f'style="background:linear-gradient(90deg,{color},{nxt});"></div>')
        parts.append("</div>")
        st.markdown("".join(parts), unsafe_allow_html=True)

    st.write("")

    # ── Attacks today ──
    with st.container(border=True):
        today_str = date.today().strftime("%b %d, %Y")
        st.markdown('<div style="display:flex;align-items:baseline;justify-content:space-between;'
                    'margin-bottom:6px;">'
                    '<div class="h">Attacks Today</div>'
                    f'<div class="mono" style="color:{FAINT};font-size:12px;padding:0 12px;">{today_str}</div>'
                    '</div>',
                    unsafe_allow_html=True)
        if data["attacks"]:
            for time, status, rule_id, uri, payload in data["attacks"]:
                blocked = status == "BLOCKED"
                bg = "rgba(52,211,153,.14)" if blocked else "rgba(248,113,113,.14)"
                fg = GREEN if blocked else RED
                meta = rule_id
                # escape attacker-controlled fields — a payload like
                # "<svg onload=alert(2)>" must render as TEXT, not live HTML
                uri_s = html.escape(str(uri))
                payload_s = html.escape(str(payload))
                st.markdown(f"""
                  <div class="att">
                    <span class="badge" style="background:{bg};color:{fg};">{status}</span>
                    <div style="flex:1;min-width:0;">
                      <div class="att-uri">{uri_s}</div>
                      <div class="att-pl">{payload_s}</div>
                    </div>
                    <div class="att-meta">{time}<br>
                      <span style="color:{FAINT};font-size:11px;">{meta}</span></div>
                  </div>
                """, unsafe_allow_html=True)
        else:
            st.caption("No attacks recorded today.")
