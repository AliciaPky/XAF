"""Rule Lab — inspect, test and manage the WAF rules that are LIVE.

Shows every SecRule the WAF actually loads from rules/custom/ (approved generated
rules + analyst-crafted ones), via lib.load_finalized_rules — each with its family
and subgroup-aware functional validation against the captured payloads. The operator
can roll a live rule back (SecRuleRemoveById) or restore it. Rules get here two ways:
approved in Rule Approval, or written in Rule Builder. Uses the shared cluster cards
(ui/cards.py).
"""

import html

import streamlit as st

import cards
import lib
from theme import (AMBER, BLUE, CARD, FAINT, GREEN, LINE, MUTED, RED, TEAL,
                   TEXT, VIOLET, page_header)

CODE = "#0a0d13"

# Family accent colour + display label. The raw family comes from the clustered
# CSV's `family` column (sqli/xss/ssti) via lib.load_finalized_rules.
FAMILY_COLORS = {"SQLi": BLUE, "XSS": GREEN, "SSTI": RED, "Other": MUTED}
FAMILY_DISPLAY = {"sqli": "SQLi", "xss": "XSS", "ssti": "SSTI"}


def _display_family(raw) -> str:
    if not raw:
        return "Other"
    return FAMILY_DISPLAY.get(str(raw).lower(), str(raw).upper())


def _validation_label(item: dict) -> tuple[str, str]:
    """(text, colour) for the card's validation status line."""
    if item["valid"] is True:
        return "PASSED", GREEN
    if item["valid"] is False:
        return "FAILED", RED
    return "NO PAYLOADS", MUTED

_CSS = f"""
<style>
  .rl-card {{ background:{CARD}; border:1px solid #1e2531; border-radius:16px;
      padding:18px 20px; margin-bottom:16px; }}
  .rl-head {{ background:{CARD}; border:1px solid #1e2531; border-radius:16px 16px 0 0;
      border-bottom:1px solid {LINE}; padding:14px 20px;
      display:flex; align-items:center; justify-content:space-between; }}
  .rl-badge {{ font-size:10px; font-weight:600; letter-spacing:.04em; padding:3px 8px;
      border-radius:6px; }}

  /* generated rule code block */
  .rl-code {{ background:{CODE}; border:1px solid #1e2531; border-top:none;
      border-radius:0 0 16px 16px; padding:16px 0; margin-bottom:16px;
      font-family:'JetBrains Mono',monospace; font-size:12.5px; line-height:1.7; }}
  .rl-ln {{ display:flex; gap:16px; padding:1.5px 20px; }}
  .rl-n {{ color:#3d4452; user-select:none; min-width:20px; text-align:right; }}
  .rl-t {{ white-space:pre-wrap; word-break:break-all; }}

  /* payload test rows */
  .rl-test {{ display:flex; align-items:center; gap:14px; padding:12px 20px;
      border-bottom:1px solid #141922; }}
  .rl-p {{ flex:1; min-width:0; font-family:'JetBrains Mono',monospace;
      font-size:12.5px; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }}
  .rl-tbl {{ background:{CARD}; border:1px solid #1e2531; border-top:none;
      border-radius:0 0 16px 16px; }}

  .rl-bar {{ height:8px; border-radius:999px; background:#161c26; overflow:hidden; }}
  .rl-bar > div {{ height:100%; border-radius:999px;
      background:linear-gradient(90deg,{GREEN},{TEAL}); }}
</style>
"""


def _endpoints_by_cluster() -> dict[int, str]:
    """Most-targeted endpoint per cluster (method + path), from the captured
    attacks. Best-effort — empty when the clustered CSV lacks the columns."""
    df = lib.load_attacks()
    out: dict[int, str] = {}
    if df.empty or "cluster" not in df.columns:
        return out
    for cid, grp in df.groupby("cluster"):
        try:
            cid = int(cid)
        except (ValueError, TypeError):
            continue
        uris = grp["uri"].astype(str).str.split("?").str[0]
        uris = uris[uris != ""]
        path = uris.value_counts().index[0] if not uris.empty else ""
        meths = grp["method"].astype(str)
        meths = meths[meths != ""]
        meth = meths.value_counts().index[0] if not meths.empty else ""
        out[cid] = f"{meth} {path}".strip()
    return out


def _state_pill(item: dict) -> tuple[str, str, str]:
    """(label, bg, fg) for the state pill. Everything shown here is a rule the AI
    already finalized and shipped to the WAF, so the meaningful distinction is
    whether it's live or the operator has rolled it back."""
    if item.get("disabled"):
        return "ROLLED BACK", "rgba(251,191,36,.14)", AMBER
    return "LIVE", "rgba(52,211,153,.14)", GREEN


def _code_block(text: str) -> str:
    lines = text.splitlines() or [text]
    rows = []
    for i, ln in enumerate(lines):
        color = FAINT if ln.strip().startswith("#") else "#c7cdd8"
        rows.append(f'<div class="rl-ln"><span class="rl-n">{i + 1:02d}</span>'
                    f'<span class="rl-t" style="color:{color};">{html.escape(ln)}</span></div>')
    return f'<div class="rl-code">{"".join(rows)}</div>'


def render() -> None:
    st.markdown(_CSS, unsafe_allow_html=True)
    st.markdown(cards.card_css("rl_picker"), unsafe_allow_html=True)
    st.markdown(page_header("Rule Lab",
                            "Inspect, test and manage the WAF rules that are live"),
                unsafe_allow_html=True)

    # Only rules actually being enforced — SecRules in rules/custom/ that aren't
    # rolled back. (Rolled-back rules are managed from Rule Approval.)
    rules = [r for r in lib.load_finalized_rules() if not r["disabled"]]
    endpoints = _endpoints_by_cluster()

    for item in rules:
        item["family"] = _display_family(item.get("family"))   # CSV family -> display label
        item["endpoint"] = endpoints.get(item["cluster"], "—")

    # ── empty state ──
    if not rules:
        st.info("No rules are live yet. Approve generated candidates in **Rule Approval**, "
                "or write your own in **Rule Builder** — both deploy into rules/custom/ "
                "and show up here.")
        return

    ids = {r["id"] for r in rules}
    st.session_state.setdefault("rl_sel", rules[0]["id"])
    if st.session_state.rl_sel not in ids:
        st.session_state.rl_sel = rules[0]["id"]

    pick_col, work_col = st.columns([1, 2], gap="medium")

    # ── cluster picker ──
    with pick_col:
        st.markdown('<div class="eyebrow" style="margin:0 0 10px 2px;">ATTACK CLUSTERS</div>',
                    unsafe_allow_html=True)
        with st.container(key="rl_picker"):
            for item in rules:
                cid = item["cluster"]
                with st.container(key=f"rl_picker_card_{item['id']}"):
                    st.markdown(cards.cluster_card_html(
                        head=f"C{cid}" if cid is not None else f"#{item['id']}",
                        family=item["family"],
                        family_color=FAMILY_COLORS.get(item["family"], MUTED),
                        pill=_state_pill(item),
                        subgroup=item.get("subgroup"),
                        line2=_validation_label(item),
                        count=f"{item['scope_size']} payloads",
                        selected=item["id"] == st.session_state.rl_sel,
                    ), unsafe_allow_html=True)
                    if st.button("select", key=f"rl_picker_pick_{item['id']}"):
                        st.session_state.rl_sel = item["id"]
                        st.rerun()

    # ── rule workspace ──
    with work_col:
        item = next(q for q in rules if q["id"] == st.session_state.rl_sel)
        fcolor = FAMILY_COLORS.get(item["family"], MUTED)
        s_txt, s_bg, s_fg = _state_pill(item)
        scope = item["scope"]
        missed = set(item["missed"] or [])
        matched = max(len(scope) - len(missed), 0)
        pct = round(matched / len(scope) * 100) if scope else 0
        n_fp = len(item["false_pos"] or [])
        cluster_lbl = f"Cluster {item['cluster']}" if item["cluster"] is not None else f"Rule {item['id']}"
        if item.get("subgroup"):
            cluster_lbl += f" / {item['subgroup']}"

        # verdict line
        if item["valid"] is True:
            verdict, vcolor = "PASSED", GREEN
        elif item["valid"] is False:
            verdict, vcolor = "FAILED", RED
        else:
            verdict, vcolor = "— no payloads to validate", MUTED

        rid_txt = f"Rule #{item['id']}"

        # summary
        st.markdown(f"""
          <div class="rl-card">
            <div style="display:flex;align-items:center;gap:12px;flex-wrap:wrap;margin-bottom:12px;">
              <span style="width:10px;height:10px;border-radius:3px;background:{fcolor};box-shadow:0 0 10px {fcolor};"></span>
              <span style="font-size:18px;font-weight:600;">{cluster_lbl} · {item['family']}</span>
              <span class="rl-badge" style="background:{s_bg};color:{s_fg};">{s_txt}</span>
              <span style="flex:1;"></span>
              <span class="mono" style="font-size:12px;color:{FAINT};">{rid_txt}</span>
            </div>
            <div style="display:flex;gap:26px;flex-wrap:wrap;font-size:12px;color:{MUTED};">
              <span>Endpoint <span class="mono" style="color:#c7cdd8;">{html.escape(item['endpoint'])}</span></span>
              <span>Captured payloads <span class="mono" style="color:#c7cdd8;">{item['scope_size']}</span></span>
              <span>Validation <span class="mono" style="color:{vcolor};">{verdict}</span></span>
              <span>Source <span class="mono" style="color:#c7cdd8;">{html.escape(item['source'])}</span></span>
            </div>
          </div>
        """, unsafe_allow_html=True)

        # generated rule
        st.markdown(
            '<div class="rl-head"><div style="display:flex;align-items:center;gap:10px;">'
            '<span style="font-size:14px;font-weight:600;">Generated Rule</span>'
            f'<span style="font-size:11px;color:{FAINT};">ModSecurity · phase 2 · LLM-generated</span></div></div>'
            + _code_block(item["rule"]), unsafe_allow_html=True)

        if item["error"]:
            st.warning(f"Validation note: {item['error']}")

        # test + metrics
        t_col, m_col = st.columns([1.6, 1], gap="medium")
        with t_col:
            if not scope:
                st.markdown(
                    '<div class="rl-head"><span style="font-size:14px;font-weight:600;">'
                    'Test Against Captured Payloads</span></div>'
                    f'<div class="rl-tbl" style="padding:16px 20px;color:{MUTED};font-size:12.5px;">'
                    'No captured payloads for this cluster to test against.</div>',
                    unsafe_allow_html=True)
            else:
                rows = ""
                shown = scope[:14]
                for p in shown:
                    hit = p not in missed
                    lbg = "rgba(52,211,153,.14)" if hit else "rgba(248,113,113,.14)"
                    lfg = GREEN if hit else RED
                    pc = "#c7cdd8" if hit else "#7f8797"
                    lbl = "MATCH" if hit else "MISS"
                    rows += (f'<div class="rl-test"><span class="rl-badge" '
                             f'style="background:{lbg};color:{lfg};width:52px;text-align:center;">{lbl}</span>'
                             f'<span class="rl-p" style="color:{pc};" title="{html.escape(p)}">{html.escape(p)}</span></div>')
                more = (f'<div class="rl-test" style="color:{FAINT};font-size:12px;">'
                        f'+ {len(scope) - len(shown)} more payload(s)…</div>'
                        if len(scope) > len(shown) else "")
                st.markdown(
                    '<div class="rl-head">'
                    '<span style="font-size:14px;font-weight:600;">Test Against Captured Payloads</span>'
                    f'<span class="mono" style="font-size:12px;color:{GREEN};">{matched}/{len(scope)} matched</span>'
                    '</div>'
                    f'<div class="rl-tbl">{rows}{more}</div>', unsafe_allow_html=True)

        with m_col:
            fp_color = GREEN if n_fp == 0 else RED
            st.markdown(f"""
              <div class="rl-card">
                <div style="display:flex;justify-content:space-between;font-size:12.5px;margin-bottom:8px;">
                  <span style="color:{MUTED};">Match rate</span>
                  <span class="mono" style="color:{GREEN};font-weight:600;">{pct}%</span>
                </div>
                <div class="rl-bar"><div style="width:{pct}%;"></div></div>
                <div style="display:flex;justify-content:space-between;font-size:12.5px;
                    border-top:1px solid {LINE};padding-top:14px;margin-top:14px;">
                  <span style="color:{MUTED};">Benign false positives</span>
                  <span class="mono" style="color:{fp_color};font-weight:600;">{n_fp}</span>
                </div>
                <div style="display:flex;justify-content:space-between;font-size:12.5px;margin-top:10px;">
                  <span style="color:{MUTED};">Payloads covered</span>
                  <span class="mono" style="color:#c7cdd8;">{matched}/{item['scope_size']}</span>
                </div>
              </div>
            """, unsafe_allow_html=True)

            if item["disabled"]:
                st.markdown(
                    f'<div style="text-align:center;padding:12px;border-radius:11px;'
                    f'border:1px solid #4a3a24;background:rgba(251,191,36,.14);color:{AMBER};'
                    f'font-weight:600;font-size:14px;">⟲ Rolled back — not enforced</div>',
                    unsafe_allow_html=True)
            else:
                st.markdown(
                    f'<div style="text-align:center;padding:12px;border-radius:11px;'
                    f'border:1px solid #24402f;background:rgba(52,211,153,.14);color:{GREEN};'
                    f'font-weight:600;font-size:14px;">● Live — enforced by the WAF</div>',
                    unsafe_allow_html=True)
            st.markdown(
                f'<div style="font-size:11.5px;color:{FAINT};text-align:center;'
                'line-height:1.5;margin-top:8px;">Roll back or restore this rule from '
                '<b>Rule Approval</b>.</div>', unsafe_allow_html=True)

            if item["rule"]:
                st.download_button(
                    "⬇  Export rule (.conf)",
                    data=item["rule"].encode("utf-8"),
                    file_name=f"xaf_rule_{item['id']}.conf",
                    mime="text/plain", key=f"rl_dl_{item['id']}",
                    use_container_width=True)
