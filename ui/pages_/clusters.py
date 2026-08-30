"""Clusters — browse the attack clusters the pipeline discovered, drill into each one's captured payloads.
"""

import html

import pandas as pd
import streamlit as st

import lib
from theme import (BLUE, CARD, FAINT, GREEN, LINE, MUTED, RED, TEXT, VIOLET,
                   page_header)

# Family (from the clustered CSV's `family` column) -> accent colour + label.
FAMILY_COLORS = {"SQLi": BLUE, "XSS": GREEN, "SSTI": RED, "Other": MUTED}
FAMILY_LABELS = {"sqli": "SQLi", "xss": "XSS", "ssti": "SSTI"}

_CSS = f"""
<style>
  .cl-card {{ background:{CARD}; border:1px solid #1e2531; border-radius:16px;
      padding:20px 22px; }}
  .cl-member {{ padding:10px 12px; background:#0d1119; border-radius:8px; margin-bottom:6px;
      font-family:'JetBrains Mono',monospace; font-size:12.5px; color:#c7cdd8;
      overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }}

  /* ── cluster grid card (the visual; a transparent button overlays it) ── */
  /* margin-bottom spaces the rows; column gap spaces them across (see render). */
  .cl-c {{ background:{CARD}; border:1px solid #1e2531; border-radius:13px;
      padding:12px 14px; min-height:112px; margin-bottom:14px;
      display:flex; flex-direction:column; gap:6px; }}
  .cl-c-top {{ display:flex; align-items:center; gap:7px; }}
  .cl-c-dot {{ width:8px; height:8px; border-radius:3px; }}
  .cl-c-id {{ font-weight:700; font-size:13px; letter-spacing:.02em; }}
  .cl-c-fam {{ font-size:11.5px; color:{MUTED}; }}
  .cl-c-num {{ font-family:'JetBrains Mono',monospace; font-size:21px; font-weight:600;
      line-height:1; display:flex; align-items:baseline; gap:8px; }}
  .cl-c-sub {{ font-family:'Space Grotesk',sans-serif; font-size:11px; font-weight:400;
      color:{FAINT}; }}
  .cl-c-ep {{ font-family:'JetBrains Mono',monospace; font-size:11.5px; color:{BLUE};
      overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }}
  .cl-c-foot {{ font-size:11px; color:{MUTED}; border-top:1px solid {LINE};
      padding-top:8px; margin-top:auto; }}

  /* overlay the whole card with a transparent button so a click anywhere selects
     it (Streamlit buttons can't hold this layout, so the HTML card is the visual
     and the invisible button sits on top). Scoped so the nav rail is untouched. */
  .st-key-cl_grid div[data-testid="stColumn"] {{ position:relative; }}
  /* the card layer is visual only — let clicks fall through to the button beneath */
  .st-key-cl_grid div[data-testid="stElementContainer"]:has(> div[data-testid="stMarkdown"]) {{
      pointer-events:none; }}
  .st-key-cl_grid div[data-testid="stElementContainer"]:has(> div[data-testid="stButton"]) {{
      position:absolute !important; top:0 !important; left:0 !important;
      width:100% !important; height:100% !important; margin:0 !important;
      pointer-events:auto; z-index:3; }}
  .st-key-cl_grid div[data-testid="stButton"] {{ width:100% !important; height:100% !important; }}
  .st-key-cl_grid div[data-testid="stButton"] > button {{ width:100% !important;
      height:100% !important; min-height:0 !important; padding:0; opacity:0;
      border:none; background:transparent; }}
  .st-key-cl_grid div[data-testid="stColumn"]:hover .cl-c {{ border-color:#2c4a6e; }}
</style>
"""


def _card_html(cid: int, r: dict, selected: bool) -> str:
    """The rich cluster card (matches the design): family dot, C<id> + family,
    the hit count, target endpoint and a blocked footer."""
    fcolor = FAMILY_COLORS.get(r["family"], MUTED)
    hits = r["total"] or r["size"]
    sub = f"hits · {r['size']} payloads" if r["total"] else f"{r['size']} payloads"
    foot = f"{r['blocked']}/{r['total']} blocked" if r["total"] else "no request log"
    sel = (f"border-color:{BLUE};box-shadow:0 0 0 1px rgba(79,157,255,.35);"
           if selected else "")
    return f"""
      <div class="cl-c" style="{sel}">
        <div class="cl-c-top">
          <span class="cl-c-dot" style="background:{fcolor};box-shadow:0 0 8px {fcolor};"></span>
          <span class="cl-c-id">C{cid}</span>
          <span class="cl-c-fam">{r['family']}</span>
        </div>
        <div class="cl-c-num">{hits}<span class="cl-c-sub">{html.escape(sub)}</span></div>
        <div class="cl-c-ep">{html.escape(r['endpoint'])}</div>
        <div class="cl-c-foot">{html.escape(foot)}</div>
      </div>
    """


def _cluster_rows() -> dict[int, dict]:
    """Build the per-cluster view model, based on cluster id (noise cluster -1
    excluded). Payloads come from lib.load_cluster_payloads; family / endpoint /
    block rate are aggregated from the captured attacks when available."""
    payloads_by_cluster = lib.load_cluster_payloads()
    rows: dict[int, dict] = {
        cid: {"cid": cid, "payloads": payloads, "size": len(payloads),
              "family": "Other", "endpoint": "—", "blocked": 0, "total": 0}
        for cid, payloads in payloads_by_cluster.items()
    }

    df = lib.load_attacks()
    if not df.empty and "cluster" in df.columns:
        cids = pd.to_numeric(df["cluster"], errors="coerce")
        for cid, grp in df.groupby(cids):
            if pd.isna(cid) or int(cid) == -1:
                continue
            cid = int(cid)
            info = rows.setdefault(
                cid, {"cid": cid, "payloads": [], "size": 0,
                      "family": "Other", "endpoint": "—", "blocked": 0, "total": 0})

            fam = grp.get("family", pd.Series(dtype=str)).astype(str).str.strip()
            fam = fam[fam != ""]
            if not fam.empty:
                key = fam.value_counts().index[0].lower()
                info["family"] = FAMILY_LABELS.get(key, key.upper() or "Other")

            uris = grp["uri"].astype(str).str.split("?").str[0]
            uris = uris[uris != ""]
            path = uris.value_counts().index[0] if not uris.empty else ""
            meths = grp["method"].astype(str)
            meths = meths[meths != ""]
            meth = meths.value_counts().index[0] if not meths.empty else ""
            info["endpoint"] = f"{meth} {path}".strip() or "—"

            status = grp["status"].str.lower()
            info["total"] = len(grp)
            info["blocked"] = int((status == "blocked").sum())
            if info["size"] == 0:
                payloads = sorted(set(grp["payload"].astype(str)))
                info["payloads"] = payloads
                info["size"] = len(payloads)

    return dict(sorted(rows.items()))


def _open_in_approval(cid: int) -> None:
    # Jump to the Rule Approval page with the selected cluster pre-loaded
    st.session_state.ra_sel_cluster = cid
    st.session_state.ra_filter = "All"
    st.session_state.page = "Rule Approval"
    st.rerun()


def render() -> None:
    st.markdown(_CSS, unsafe_allow_html=True)
    st.markdown(page_header("Clusters",
                            "Attack traffic grouped by behavioural similarity"),
                unsafe_allow_html=True)

    rows = _cluster_rows()

    # -- empty state: offer to run clustering --
    if not rows:
        st.info("No clusters yet. Clustering groups the captured attacks by "
                "behavioural similarity (DBSCAN) into families the generator can "
                "target.")
        can_cluster = lib.PARSED_LOGS.exists()
        if not can_cluster:
            st.caption("Run the parser first (`output/parsed_logs.json` is missing).")
        if st.button("⚙  Run clustering", type="primary", disabled=not can_cluster):
            with st.spinner("Clustering captured attacks…"):
                res = lib.run_script("cluster")
            if res["ok"]:
                st.success("Clustering finished. Refreshing.")
                st.rerun()
            else:
                st.error(f"Clustering failed (exit {res['code']}).")
                st.code(res["stderr"] or res["stdout"] or "no output")
        return

    ids = list(rows)
    st.session_state.setdefault("cl_sel", ids[0])
    if st.session_state.cl_sel not in rows:
        st.session_state.cl_sel = ids[0]

    # -- cluster grid (3 across) --
    st.markdown('<div class="eyebrow" style="margin:0 0 6px 2px;">'
                'ATTACK CLUSTERS — click to inspect</div>', unsafe_allow_html=True)
    with st.container(key="cl_grid"):
        for row_start in range(0, len(ids), 3):
            cols = st.columns(3)
            for col, cid in zip(cols, ids[row_start:row_start + 3]):
                r = rows[cid]
                with col:
                    st.markdown(
                        _card_html(cid, r, cid == st.session_state.cl_sel),
                        unsafe_allow_html=True)
                    if st.button(f"Inspect cluster {cid}", key=f"cl_card_{cid}"):
                        st.session_state.cl_sel = cid
                        st.rerun()

    st.write("")

    # -- detail panel --
    cid = st.session_state.cl_sel
    r = rows[cid]
    fcolor = FAMILY_COLORS.get(r["family"], MUTED)
    signature = lib.cluster_signature_label(r["payloads"]) if r["payloads"] else "—"
    coverage = f"{round(r['blocked'] / r['total'] * 100)}%" if r["total"] else "—"

    head_col, action_col = st.columns([3, 1])
    with head_col:
        st.markdown(f"""
          <div style="display:flex;align-items:center;gap:12px;flex-wrap:wrap;padding-top:4px;">
            <span style="width:10px;height:10px;border-radius:3px;background:{fcolor};box-shadow:0 0 10px {fcolor};"></span>
            <span style="font-size:18px;font-weight:600;">Cluster {cid} · {r['family']}</span>
          </div>
        """, unsafe_allow_html=True)
    with action_col:
        if st.button("Open in Rule Approval ›", key=f"cl_lab_{cid}",
                     use_container_width=True):
            _open_in_approval(cid)

    members = r["payloads"][:20]
    more = (f'<div class="cl-member" style="color:{FAINT};background:transparent;">'
            f'+ {len(r["payloads"]) - len(members)} more payload(s)…</div>'
            if len(r["payloads"]) > len(members) else "")

    st.markdown(f"""
      <div class="cl-card" style="margin-top:10px;">
        <div style="font-size:13px;color:#c7cdd8;line-height:1.55;margin-bottom:12px;">
          Attacks grouped by behavioural similarity. Signature classification:
          <span class="mono" style="color:#c7cdd8;">{html.escape(signature)}</span>.
        </div>
        <div style="display:flex;gap:26px;flex-wrap:wrap;font-size:12px;color:{MUTED};margin-bottom:16px;">
          <span>Endpoint <span class="mono" style="color:#c7cdd8;">{html.escape(r['endpoint'])}</span></span>
          <span>Signature <span class="mono" style="color:#c7cdd8;">{html.escape(signature)}</span></span>
          <span>Captured payloads <span class="mono" style="color:#c7cdd8;">{r['size']}</span></span>
          <span>Blocked by CRS <span class="mono" style="color:{GREEN if r['total'] else MUTED};">{coverage}</span></span>
        </div>
        <div style="border-top:1px solid {LINE};padding-top:14px;">
          <div class="eyebrow" style="margin:0 0 10px 0;">MEMBER PAYLOADS</div>
          {''.join(f'<div class="cl-member">{html.escape(p)}</div>' for p in members) or
           f'<div class="cl-member" style="color:{FAINT};">No payloads captured for this cluster.</div>'}
          {more}
        </div>
      </div>
    """, unsafe_allow_html=True)
