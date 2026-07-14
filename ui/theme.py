"""
XAF console — shared theme: palette + the global CSS the whole app depends on.

Every page imports the colour constants from here, and app.py calls inject_css()
once after set_page_config so the design lands before any content renders.
"""

# ─────────────────────────────────────────────────────────────────────────────
# Palette (matches the HTML design)
# ─────────────────────────────────────────────────────────────────────────────
BG     = "#06080c"
PANEL  = "#0b0e15"
CARD   = "#10141d"
BORDER = "#1e2531"
LINE   = "#1a202b"
RAIL   = "#0a0d13"
TEXT   = "#e7eaf0"
MUTED  = "#8a93a3"
FAINT  = "#5c6472"
BLUE   = "#4f9dff"
GREEN  = "#34d399"
RED    = "#f87171"
TEAL   = "#38d6c8"
AMBER  = "#fbbf24"
VIOLET = "#a78bfa"


def inject_css() -> None:
    """Inject the global stylesheet. Call once, right after set_page_config."""
    import streamlit as st

    st.markdown(f"""
<style>
  @import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap');
  .stApp {{ background:{BG}; }}
  html, body, [class*="css"] {{ font-family:'Space Grotesk',system-ui,sans-serif; color:{TEXT}; }}
  .mono {{ font-family:'JetBrains Mono',monospace; }}
  #MainMenu, footer, header {{ visibility:hidden; }}
  .block-container {{ padding:1.2rem 2rem 2rem; max-width:1560px; }}
  section[data-testid="stSidebar"] {{ display:none; }}
  div[data-testid="stHorizontalBlock"] > div[data-testid="column"] {{ padding:0 6px; }}

  /* ── the box around each graph section (st.container(border=True)) ── */
  div[data-testid="stVerticalBlockBorderWrapper"] {{
      background:{CARD}; border:1px solid {BORDER} !important;
      border-radius:18px; padding:8px 6px; }}

  /* ── navigation rail (st.container(key="rail")) ── */
  /* Fill the column height (Streamlit already makes the rail | content columns
     equal-height) instead of forcing a fixed 1200px, so the rail ends with the
     page content — e.g. the log table — rather than running past it. The wrapper
     around the rail is a flex-column child that otherwise collapses to its own
     content height, so grow it to fill the (taller) column first. */
  div[data-testid="stLayoutWrapper"]:has(> .st-key-rail) {{ flex-grow:1; }}
  .st-key-rail {{ background:{RAIL}; border:1px solid {LINE}; border-radius:18px;
      padding:22px 16px 26px; height:100%; }}
  .st-key-rail .stButton > button {{
      width:100%; justify-content:flex-start; text-align:left;
      background:transparent; border:1px solid transparent; border-left:2px solid transparent;
      color:{MUTED}; font-weight:500; font-size:13.5px; padding:9px 12px;
      border-radius:10px; margin:1px 0; box-shadow:none; }}
  .st-key-rail .stButton > button:hover {{
      background:rgba(255,255,255,.03); color:{TEXT}; }}
  .st-key-rail .stButton > button[kind="primary"],
  .st-key-rail .stButton > button[data-testid="stBaseButton-primary"] {{
      background:rgba(79,157,255,.10); color:{TEXT}; border-left:2px solid {BLUE}; }}
  .st-key-rail .stButton > button[kind="primary"]:hover {{
      background:rgba(79,157,255,.14); color:{TEXT}; }}

  .brand {{ display:flex; align-items:center; gap:12px; margin-bottom:22px; }}
  .brand .diamond {{ width:38px; height:38px; border-radius:11px;
      background:linear-gradient(135deg,#141b27,#0d1219); border:1px solid #2a3340;
      display:flex; align-items:center; justify-content:center; }}
  .brand .dot {{ width:13px; height:13px; background:{BLUE}; transform:rotate(45deg);
      border-radius:3px; box-shadow:0 0 12px #4f9dff99; }}
  .eyebrow {{ font-size:10px; color:{FAINT}; letter-spacing:.14em; margin:0 0 8px 8px; }}
  .statuscard {{ background:{CARD}; border:1px solid {BORDER}; border-radius:12px;
      padding:14px; display:flex; align-items:center; gap:10px; margin-top:8px; }}

  .kpi {{ background:{CARD}; border:1px solid {BORDER}; border-radius:14px; padding:16px 18px; }}
  .kpi-label {{ font-size:12px; color:{MUTED}; }}
  .kpi-value {{ font-family:'JetBrains Mono',monospace; font-size:27px; font-weight:600; line-height:1; margin:10px 0; }}
  .kpi-sub {{ font-size:12px; color:{FAINT}; }}
  .h {{ font-size:16px; font-weight:600; padding:6px 12px 0; }}
  .hsub {{ font-size:12.5px; color:{MUTED}; padding:0 12px; }}
  .page-title {{ font-size:22px; font-weight:600; }}
  .page-sub {{ font-size:12.5px; color:{MUTED}; margin:0 0 18px 0; }}

  .att {{ display:flex; align-items:center; gap:14px; padding:13px 14px; border-bottom:1px solid #141922; }}
  .badge {{ font-size:10.5px; font-weight:600; letter-spacing:.04em; padding:4px 10px;
      border-radius:6px; width:82px; text-align:center; }}
  .att-uri {{ font-family:'JetBrains Mono',monospace; font-size:13px; color:{TEXT};
      white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }}
  .att-pl {{ font-family:'JetBrains Mono',monospace; font-size:11.5px; color:{FAINT};
      white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }}
  .att-meta {{ font-family:'JetBrains Mono',monospace; font-size:12px; color:{MUTED}; text-align:right; }}
  .pipeline {{ display:flex; align-items:flex-start; padding:14px 26px 6px; }}
  .pstep {{ display:flex; flex-direction:column; align-items:center; gap:9px; }}
  .pstep .num {{ width:48px; height:48px; border-radius:50%; background:#0d121b;
      display:flex; align-items:center; justify-content:center;
      font-family:'JetBrains Mono',monospace; font-size:15px; font-weight:600;
      box-shadow:0 0 0 6px {CARD}; }}
  .pstep .plabel {{ font-size:12px; color:{MUTED}; }}
  .pline {{ flex:1; height:2px; margin-top:23px; border-radius:2px; opacity:.85; }}
</style>
""", unsafe_allow_html=True)


def page_header(title: str, subtitle: str = "") -> str:
    """HTML for a page's title + subtitle block (used at the top of each page)."""
    sub = f'<div class="page-sub">{subtitle}</div>' if subtitle else ""
    return f'<div class="page-title">{title}</div>{sub}'
