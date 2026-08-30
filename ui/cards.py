"""Shared 'attack cluster' picker card — the styled, clickable box used by the
Rule Approval review queue and the Attack Simulator library, so they stay in sync.

Streamlit buttons can't hold HTML, so each card is a styled <div> with a
transparent full-size button laid over it to capture the click.

card_css(key) scopes the overlay/gap rules to `.st-key-<key>` (the outer container) and 
its `st-key-<key>_card_*` children, so nothing else on the page (e.g. the nav-rail buttons) is affected.
"""

import html

from theme import BLUE, CARD, FAINT, MUTED, TEXT


def card_css(key: str) -> str:
    """The <style> block for the cluster cards. `key` is the st.container key the
    page wraps the cards in; per-card containers use `f"{key}_card_{id}"`."""
    return f"""
<style>
  .clcard {{ background:{CARD}; border:1px solid #1e2531; border-radius:12px;
      padding:12px 14px; overflow:hidden; transition:border-color .12s ease; }}
  .clcard.sel {{ border-color:#2c4a6e; border-left:3px solid {BLUE};
      background:rgba(79,157,255,.06); }}
  .clrow {{ display:flex; align-items:center; gap:8px; }}
  .clrow2 {{ display:flex; align-items:center; gap:8px; margin-top:8px; }}
  .cllead {{ display:flex; align-items:center; gap:8px; min-width:0; overflow:hidden; flex:1; }}
  .cldot {{ width:9px; height:9px; border-radius:3px; flex:none; }}
  .clid {{ font-family:'JetBrains Mono',monospace; font-weight:700; font-size:13px; color:{TEXT}; flex:none; }}
  .clfam {{ font-family:'JetBrains Mono',monospace; font-size:11px; font-weight:600;
      min-width:0; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }}
  .clbadge {{ font-size:8.5px; font-weight:600; letter-spacing:.04em; padding:2px 6px;
      border-radius:5px; flex:none; white-space:nowrap; }}
  .cll {{ display:flex; align-items:baseline; gap:6px; min-width:0; overflow:hidden; }}
  .clsub {{ font-family:'JetBrains Mono',monospace; font-size:10px; color:{FAINT};
      min-width:0; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }}
  .clval {{ font-family:'JetBrains Mono',monospace; font-size:11px; font-weight:600;
      letter-spacing:.03em; white-space:nowrap; flex:none; }}
  .clhits {{ font-family:'JetBrains Mono',monospace; font-size:11px; color:{FAINT}; flex:none; }}
  .cllabel {{ font-family:'JetBrains Mono',monospace; font-size:11px; font-weight:600;
      flex:none; white-space:nowrap; }}
  .clep {{ font-family:'JetBrains Mono',monospace; font-size:10.5px; color:{MUTED};
      flex:0 1 auto; min-width:0; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }}
  .clpay {{ font-family:'JetBrains Mono',monospace; font-size:12px; color:#c7cdd8;
      min-width:0; overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }}

  /* Streamlit measures the card's markdown wrapper ~16px (one line) shorter than the
     two-line card, so the card overflows its container. We pad the inter-card gap to
     absorb that overflow (→ ~12px visual gap between boxes) and extend the transparent
     overlay button 16px past the container bottom so the whole card stays clickable. */
  .st-key-{key} {{ gap:28px; }}
  .st-key-{key} [class*="st-key-{key}_card_"] {{ position:relative; gap:0; }}
  .st-key-{key} [class*="st-key-{key}_card_"]:hover .clcard {{ border-color:#2c4a6e; }}
  .st-key-{key} [class*="st-key-{key}_card_"] > div[data-testid="stElementContainer"]:last-child {{
      position:absolute; top:0; left:0; right:0; bottom:-16px; width:100%;
      margin:0; padding:0; z-index:2; }}
  .st-key-{key} [class*="st-key-{key}_card_"] > div[data-testid="stElementContainer"]:last-child button {{
      width:100%; height:100%; min-height:0; opacity:0; padding:0; border:none;
      background:transparent; cursor:pointer; }}
</style>
"""


def cluster_card_html(*, head: str, family: str, family_color: str,
                      pill: tuple[str, str, str], subgroup: str | None,
                      line2: tuple[str, str], count: str, selected: bool,
                      pill2: tuple[str, str, str] | None = None) -> str:
    """Build one card.

    head         — the id shown bold, e.g. "C3" or "#1000004"
    family       — display label, e.g. "SQLi" (coloured with family_color)
    pill         — (text, bg, fg) for the state pill (top-right)
    pill2        — optional second badge shown just left of `pill` (e.g. an
                   "UPDATE" tag alongside the "PENDING" state)
    subgroup     — optional secondary tag on line 2 (e.g. "boolean_and")
    line2        — (text, colour) for the main line-2 status (e.g. validation)
    count        — right-aligned count on line 2, e.g. "4 payloads"
    selected     — draws the selected (blue left-border) style
    """
    p_txt, p_bg, p_fg = pill
    l_txt, l_color = line2
    sub = (f'<span class="clsub">{html.escape(subgroup)} ·</span>'
           if subgroup else "")
    badge2 = ("" if pill2 is None else
              f'<span class="clbadge" style="background:{pill2[1]};color:{pill2[2]};">'
              f'{html.escape(pill2[0])}</span>')
    return (
        f'<div class="clcard{" sel" if selected else ""}">'
        f'<div class="clrow">'
        f'<span class="cllead">'
        f'<span class="cldot" style="background:{family_color};box-shadow:0 0 8px {family_color};"></span>'
        f'<span class="clid">{html.escape(head)}</span>'
        f'<span class="clfam" style="color:{family_color};">{html.escape(family)}</span>'
        f'</span>'
        f'<span style="display:inline-flex;align-items:center;gap:6px;">'
        f'{badge2}'
        f'<span class="clbadge" style="background:{p_bg};color:{p_fg};">{html.escape(p_txt)}</span>'
        f'</span>'
        f'</div>'
        f'<div class="clrow2">'
        f'<span class="cll">{sub}<span class="clval" style="color:{l_color};">{html.escape(l_txt)}</span></span>'
        f'<span style="flex:1;"></span>'
        f'<span class="clhits">{html.escape(count)}</span>'
        f'</div></div>')


def payload_card_html(*, label: str, label_color: str, endpoint: str,
                      payload: str, selected: bool) -> str:
    """A payload preset card (Attack Simulator's attack library): a coloured family
    dot + label and the target endpoint on line 1, the payload itself on line 2.
    Shares the same box/overlay styling as cluster_card_html (see card_css)."""
    return (
        f'<div class="clcard{" sel" if selected else ""}">'
        f'<div class="clrow">'
        f'<span class="cldot" style="background:{label_color};box-shadow:0 0 8px {label_color};"></span>'
        f'<span class="cllabel" style="color:{label_color};">{html.escape(label)}</span>'
        f'<span style="flex:1;"></span>'
        f'<span class="clep">{html.escape(endpoint)}</span>'
        f'</div>'
        f'<div class="clrow2">'
        f'<span class="clpay" title="{html.escape(payload)}">{html.escape(payload)}</span>'
        f'</div></div>')
