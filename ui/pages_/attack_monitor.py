"""Attack Monitor — detailed request-level log for the current pipeline run.

Every row is read live from the pipeline output via lib.load_attacks()
(output/clustered_attacks.csv, falling back to output/parsed_logs.json), so
this page reflects exactly what the parser + clustering produced.

Controls:
  • search keyword + status buttons + date-range filter narrow the table
  • the table paginates 10 rows at a time
  • Export CSV opens a popover where you pick a keyword + status for the export,
    so you can download a different slice than what's on screen

The demo's Source IP / Confidence columns had no backing in the parsed data, so
they're replaced by the real Rule ID (the CRS rule that matched each request).
"""

import datetime
import html
import math

import pandas as pd
import streamlit as st

import lib
from theme import (AMBER, BLUE, FAINT, GREEN, MUTED, RED, TEAL, TEXT, VIOLET,
                   page_header)

PAGE_SIZE = 10

# Family (attack type) -> colour. Keyed uppercase to match the display label;
# families the clustering step didn't tag fall back to MUTED.
FAMILY_COLORS = {"SQLI": BLUE, "XSS": GREEN, "SSTI": RED,
                 "LFI": AMBER, "RCE": VIOLET, "XXE": TEAL}

# "bypassed" on disk means CRS didn't catch it — show it as UNCAUGHT in the UI.
STATUS_DISPLAY = {"blocked": "BLOCKED", "bypassed": "UNCAUGHT"}

# Page-specific CSS for the log table. The global theme (theme.inject_css) is
# already loaded by app.py; these classes are only used here.
_TABLE_CSS = f"""
<style>
  .stat {{ background:#10141d; border:1px solid #1e2531; border-radius:14px;
      padding:15px 18px; display:flex; align-items:center; gap:12px; }}
  .stat .lbl {{ font-size:12px; color:{MUTED}; flex:1; }}
  .stat .val {{ font-family:'JetBrains Mono',monospace; font-size:22px; font-weight:600; }}

  .tbl {{ background:#10141d; border:1px solid #1e2531; border-radius:16px; overflow:hidden; }}
  .grid {{ display:grid;
      grid-template-columns:92px 78px 96px minmax(0,1.2fr) minmax(0,1.55fr) 70px 64px 74px;
      gap:12px; align-items:center; }}
  .thead {{ padding:14px 20px; font-size:11px; color:{FAINT}; letter-spacing:.06em;
      text-transform:uppercase; border-bottom:1px solid #1a202b; background:#0d1119; }}
  .trow {{ padding:13px 20px; font-size:12.5px; border-bottom:1px solid #141922; }}
  .cmono {{ font-family:'JetBrains Mono',monospace; }}
  .clip {{ overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }}
  .tbl .badge {{ font-size:10px; font-weight:600; letter-spacing:.04em; padding:3px 8px;
      border-radius:6px; width:auto; text-align:left; }}
  .fam {{ display:flex; align-items:center; gap:6px; }}
  .fam .d {{ width:7px; height:7px; border-radius:2px; }}
  .foot {{ display:flex; align-items:center; justify-content:space-between;
      padding:13px 20px; font-size:12px; color:{FAINT}; }}

  div[data-testid="stTextInput"] input {{ background:#10141d; border:1px solid #222835;
      color:{TEXT}; font-family:'JetBrains Mono',monospace; border-radius:10px; }}
  div[data-testid="stDownloadButton"] button, div[data-testid="stPopover"] button {{
      background:rgba(79,157,255,.12); border:1px solid #2c4a6e; color:#8fc0ff;
      font-weight:600; border-radius:10px; }}
  div[data-testid="stDownloadButton"] button:hover, div[data-testid="stPopover"] button:hover {{
      background:rgba(79,157,255,.2); color:#c9e0ff; border-color:#2c4a6e; }}
</style>
"""


@st.cache_data(ttl=5)
def load_monitor_df() -> pd.DataFrame:
    """Read the parsed attacks and shape them into display-ready rows, newest
    first. Columns: date, time, status, uri, payload, family, cluster, rule_id
    (+ a hidden _dt datetime used for sorting and the date filter)."""
    df = lib.load_attacks()
    if df.empty:
        return df

    ts = pd.to_datetime(df["timestamp"], errors="coerce")
    cid = pd.to_numeric(df["cluster"], errors="coerce") if "cluster" in df.columns else pd.Series(pd.NA, index=df.index)
    rid = pd.to_numeric(df["rule_id"], errors="coerce")
    fam = (df["family"] if "family" in df.columns else pd.Series("", index=df.index)).fillna("").astype(str)

    d = pd.DataFrame({
        "date":    ts.dt.strftime("%Y-%m-%d").fillna("—"),
        "time":    ts.dt.strftime("%H:%M:%S").fillna("--:--:--"),
        "status":  df["status"].str.lower().map(STATUS_DISPLAY).fillna("UNKNOWN"),
        "uri":     df["uri"].fillna("").astype(str),
        "payload": df["payload"].fillna("").astype(str),
        "family":  fam.str.upper().replace("", "—"),
        "cluster": cid.apply(lambda x: "noise" if x == -1 else ("—" if pd.isna(x) else f"C{int(x)}")),
        "rule_id": rid.apply(lambda x: str(int(x)) if pd.notna(x) else "—"),
        "_dt":     ts,
    })
    d = d.sort_values("_dt", ascending=False, na_position="last")
    return d.reset_index(drop=True)


def _apply_filters(df: pd.DataFrame, query: str, status: str,
                   date_range: tuple | None = None) -> pd.DataFrame:
    """Filter rows by status, an optional (start, end) date range, and a
    free-text keyword matched across every visible field."""
    v = df
    if status == "Blocked":
        v = v[v["status"] == "BLOCKED"]
    elif status == "Uncaught":
        v = v[v["status"] == "UNCAUGHT"]

    if date_range is not None:
        start, end = date_range
        d = v["_dt"].dt.date
        mask = ((d >= start) & (d <= end)).fillna(True)   # keep rows w/o a parseable date
        v = v[mask]

    if query and query.strip():
        q = query.strip().lower()
        hay = (v["date"] + " " + v["time"] + " " + v["uri"] + " " + v["payload"]
               + " " + v["family"] + " " + v["cluster"] + " " + v["rule_id"]).str.lower()
        v = v[hay.str.contains(q, regex=False)]
    return v


def _csv_bytes(df: pd.DataFrame) -> bytes:
    """CSV of the visible columns only (drop the internal _dt helper)."""
    cols = [c for c in df.columns if not c.startswith("_")]
    return df[cols].to_csv(index=False).encode("utf-8-sig")


def render() -> None:
    st.markdown(_TABLE_CSS, unsafe_allow_html=True)

    df = load_monitor_df()

    # ── header row: title + Export CSV (moved up, top-right) ──
    h1, h2 = st.columns([3.4, 1])
    with h1:
        st.markdown(page_header("Attack Monitor",
                                "Detailed request log for the current pipeline run"),
                    unsafe_allow_html=True)
    with h2:
        # Filled in after the view is computed below — exports every row the
        # active filters produce (all pages of the table), not just this page.
        export_slot = st.empty()

    if df.empty:
        st.info("No parsed attacks yet. Run the parser + clustering to populate "
                "`output/parsed_logs.json` / `output/clustered_attacks.csv`, then refresh.")
        return

    total    = len(df)
    blocked  = int((df["status"] == "BLOCKED").sum())
    uncaught = int((df["status"] == "UNCAUGHT").sum())

    # ── stat strip ──
    for col, (lbl, val, color) in zip(
            st.columns(3),
            [("Total Events", total, TEXT), ("Blocked", blocked, GREEN),
             ("Uncaught", uncaught, RED)]):
        col.markdown(
            f'<div class="stat"><div style="width:8px;height:8px;border-radius:2px;'
            f'background:{color if color != TEXT else BLUE};"></div>'
            f'<div class="lbl">{lbl}</div>'
            f'<div class="val" style="color:{color};">{val}</div></div>',
            unsafe_allow_html=True)

    st.write("")

    # ── filter bar: search | date range | status buttons ──
    dts = df["_dt"].dropna()
    if not dts.empty:
        min_d, max_d = dts.min().date(), dts.max().date()
    else:
        min_d = max_d = datetime.date.today()

    f1, f2, f3 = st.columns([2.2, 1.4, 1.8])
    with f1:
        query = st.text_input("search", placeholder="Search URI, payload, family, cluster, rule…",
                              label_visibility="collapsed")
    with f2:
        picked = st.date_input("date", value=(min_d, max_d), min_value=min_d,
                               max_value=max_d, label_visibility="collapsed")
    with f3:
        status = st.segmented_control("status", ["All events", "Blocked", "Uncaught"],
                                      default="All events", label_visibility="collapsed")
    status = status or "All events"           # segmented_control returns None if deselected

    # date_input yields a single date mid-selection; normalise to a (start, end) pair
    if isinstance(picked, (list, tuple)):
        start_d, end_d = (picked[0], picked[-1]) if picked else (min_d, max_d)
    else:
        start_d = end_d = picked

    view = _apply_filters(df, query, status, (start_d, end_d))

    # ── Export CSV — the full filtered table (every page), rendered into the
    #     placeholder we reserved in the header row ──
    export_slot.download_button(
        "⬇  Export CSV",
        data=_csv_bytes(view) if not view.empty else b"",
        file_name="xaf_attack_logs.csv",
        mime="text/csv",
        use_container_width=True,
        disabled=view.empty)

    # ── pagination (10 rows/page); reset to page 1 whenever the filters change ──
    n_view = len(view)
    n_pages = max(1, math.ceil(n_view / PAGE_SIZE))
    sig = (query.strip().lower(), status, str(start_d), str(end_d))
    if st.session_state.get("am_sig") != sig:
        st.session_state.am_page = 1
        st.session_state.am_sig = sig
    page = min(st.session_state.get("am_page", 1), n_pages)
    lo = (page - 1) * PAGE_SIZE
    page_view = view.iloc[lo:lo + PAGE_SIZE]

    # ── log table ──
    header = (
        '<div class="grid thead">'
        '<div>Date</div><div>Time</div><div>Status</div>'
        '<div>URI</div><div>Payload</div><div>Family</div><div>Cluster</div>'
        '<div style="text-align:right;">Rule</div></div>')

    rows = []
    for _, r in page_view.iterrows():
        is_blocked = r["status"] == "BLOCKED"
        sbg = "rgba(52,211,153,.14)" if is_blocked else "rgba(248,113,113,.14)"
        sfg = GREEN if is_blocked else RED
        fcolor = FAMILY_COLORS.get(r["family"], MUTED)
        uri = html.escape(r["uri"]); payload = html.escape(r["payload"])
        rows.append(
            f'<div class="grid trow">'
            f'<div class="cmono" style="color:{MUTED};">{r["date"]}</div>'
            f'<div class="cmono" style="color:{MUTED};">{r["time"]}</div>'
            f'<div><span class="badge" style="background:{sbg};color:{sfg};">{r["status"]}</span></div>'
            f'<div class="cmono clip" style="color:#c7cdd8;" title="{uri}">{uri}</div>'
            f'<div class="cmono clip" style="color:#7f8797;" title="{payload}">{payload}</div>'
            f'<div class="fam"><span class="d" style="background:{fcolor};"></span>'
            f'<span style="color:#c7cdd8;font-size:12px;">{r["family"]}</span></div>'
            f'<div class="cmono" style="color:{MUTED};">{r["cluster"]}</div>'
            f'<div class="cmono" style="text-align:right;color:{MUTED};">{r["rule_id"]}</div>'
            f'</div>')

    if rows:
        body = "".join(rows)
        hi = lo + len(page_view)
        showing = (f'<span>Showing <span class="cmono" style="color:#c7cdd8;">{lo + 1}–{hi}</span> '
                   f'of <span class="cmono" style="color:#c7cdd8;">{n_view}</span> events</span>')
    else:
        body = (f'<div class="trow" style="text-align:center;color:{FAINT};padding:40px;">'
                'No events match the current filters.</div>')
        showing = '<span>No events</span>'

    foot = (f'<div class="foot">{showing}'
            f'<span>Page <span class="cmono" style="color:#c7cdd8;">{page}</span> '
            f'of <span class="cmono" style="color:#c7cdd8;">{n_pages}</span></span></div>')

    st.markdown(f'<div class="tbl">{header}{body}{foot}</div>', unsafe_allow_html=True)

    # ── pager controls ──
    p1, p2, p3 = st.columns([1, 2, 1])
    with p1:
        prev = st.button("‹ Prev", use_container_width=True, disabled=page <= 1)
    with p2:
        st.markdown(f'<div style="text-align:center;color:{MUTED};font-size:12.5px;'
                    f'padding-top:8px;">Page {page} of {n_pages}</div>',
                    unsafe_allow_html=True)
    with p3:
        nxt = st.button("Next ›", use_container_width=True, disabled=page >= n_pages)
    if prev:
        st.session_state.am_page = max(1, page - 1)
        st.rerun()
    if nxt:
        st.session_state.am_page = min(n_pages, page + 1)
        st.rerun()
