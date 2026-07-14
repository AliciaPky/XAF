"""Attack Simulator — fire real payloads at the live WAF and see the verdict.

Wired to system data, not fixtures. Everything comes from lib.py:
  • The attack library is lib.attack_catalog() — the SAME payloads the project's
    attackScript*.py generators fire, grouped by attack type → family (+ benign),
    so the simulator's ammunition is a single source of truth with the pipeline.
  • Launch actually sends the payload through nginx-modsec via lib.fire_payload()
    over the mapped vector (endpoint + param). The verdict is the WAF's real
    response: HTTP 403 == BLOCKED, anything else == UNCAUGHT. Latency is the real
    round-trip time; a transport error (WAF down) is surfaced as an ERROR verdict.
  • A block is attributed to the deployed custom rule that matches it
    (lib.attribute_block), and the "N rules deployed" pill is lib.count_deployed_rules().

Nothing here is simulated — remove the WAF and every row goes to ERROR rather
than lying with a synthetic 200/403.
"""

import datetime as dt
import html

import streamlit as st

import cards
import lib
from theme import (AMBER, BLUE, CARD, FAINT, GREEN, LINE, MUTED, RED, TEAL,
                   TEXT, page_header)

CODE = "#0a0d13"
BORDER = "#1e2531"

# Attack type display label -> catalog key. The catalog also fixes the vector
# (endpoint) each type is fired through, so picking a type sets the target too.
TYPES = {"SQLi": "sqli", "XSS": "xss", "SSTI": "ssti"}
TYPE_COLORS = {"sqli": BLUE, "xss": GREEN, "ssti": RED}

_CSS = f"""
<style>
  .metric {{ background:{CARD}; border:1px solid {BORDER}; border-radius:14px;
      padding:14px 16px; }}
  .metric .lbl {{ font-size:11.5px; color:{MUTED}; }}
  .metric .val {{ font-family:'JetBrains Mono',monospace; font-size:20px; font-weight:600; }}

  .verdict {{ border-radius:16px; padding:20px 22px; display:flex; align-items:center;
      gap:18px; flex-wrap:wrap; margin-top:14px; }}
  .sim-grid {{ display:grid; gap:12px; align-items:center;
      grid-template-columns:78px 92px minmax(0,1.7fr) 150px 52px 62px 58px 60px; }}
  .sim-thead {{ padding:11px 20px; font-size:10.5px; color:{FAINT}; letter-spacing:.06em;
      text-transform:uppercase; border-bottom:1px solid {LINE}; background:#0d1119; }}
  .sim-trow {{ padding:11px 20px; font-size:12px; border-bottom:1px solid #141922; }}
  .clip {{ overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }}
  .sim-badge {{ font-size:10px; font-weight:600; letter-spacing:.04em; padding:3px 8px;
      border-radius:6px; }}

  /* Launch button */
  .st-key-sim_launch div[data-testid="stButton"] button {{ width:100%;
      background:rgba(79,157,255,.14); border:1px solid #2c4a6e; color:#c9e0ff;
      font-weight:600; border-radius:10px; }}
  .st-key-sim_launch div[data-testid="stButton"] button:hover {{
      background:rgba(79,157,255,.22); border-color:#3a5f8c; }}

  div[data-testid="stTextInput"] input {{ background:{CODE}; border:1px solid #222835;
      color:{TEXT}; font-family:'JetBrains Mono',monospace; border-radius:10px; }}
</style>
"""


@st.cache_data(ttl=30)
def _catalog() -> dict:
    """The payload catalog, cached — reads and imports the attack scripts once."""
    return lib.attack_catalog()


def _launch() -> None:
    """Fire the current payload through the live WAF and record the real verdict."""
    text = (st.session_state.get("sim_payload") or "").strip()
    if not text:
        return
    type_key = TYPES.get(st.session_state.get("sim_type_label") or "SQLi", "sqli")
    vector = _catalog()[type_key]["vector"]
    target = (lib.VECTORS.get(vector) or {}).get("label", vector)
    res = lib.fire_payload(text, vector=vector)
    now = dt.datetime.now().strftime("%H:%M:%S")

    if not res.get("ok"):
        entry = dict(time=now, payload=text, target=target, status="error",
                     code="ERR", rule="—", cluster="—", latency="—",
                     error=res.get("error", "request failed"))
    else:
        blocked = res["blocked"]
        attr = lib.attribute_block(text) if blocked else {"rule_id": None, "cluster": None}
        rule = f"#{attr['rule_id']}" if attr["rule_id"] else "—"
        cluster = f"C{attr['cluster']}" if attr["cluster"] is not None else "—"
        entry = dict(time=now, payload=text, target=target,
                     status="blocked" if blocked else "uncaught",
                     code=str(res["status_code"]), rule=rule, cluster=cluster,
                     latency=f"{res.get('elapsed_ms', 0):.1f}ms", error=None)

    st.session_state.sim_log.insert(0, entry)
    st.session_state.sim_log = st.session_state.sim_log[:20]


def render() -> None:
    st.markdown(_CSS, unsafe_allow_html=True)
    st.markdown(cards.card_css("sim_lib"), unsafe_allow_html=True)

    ss = st.session_state
    cat = _catalog()
    # The segmented control (rendered below, keyed "sim_type_label") owns the type;
    # read its persisted value here so the header/target reflect the current pick.
    type_label = ss.get("sim_type_label") or "SQLi"
    type_key = TYPES.get(type_label, "sqli")
    block = cat.get(type_key, {"vector": "courses_q", "families": {}, "benign": []})
    vector = block["vector"]
    target = (lib.VECTORS.get(vector) or {}).get("label", vector)

    ss.setdefault("sim_payload", next(iter(next(iter(block["families"].values()), [""])), ""))
    ss.setdefault("sim_log", [])

    n_deployed = lib.count_deployed_rules()

    # ── header ──
    h_l, h_r = st.columns([2.4, 1])
    with h_l:
        st.markdown(page_header("Attack Simulator",
                                "Replay attack payloads against the live WAF rule set"),
                    unsafe_allow_html=True)
    with h_r:
        st.markdown(
            '<div style="text-align:right;padding-top:6px;">'
            f'<span style="display:inline-flex;align-items:center;gap:7px;padding:7px 13px;'
            f'border:1px solid #24405f;background:rgba(79,157,255,.08);border-radius:999px;'
            f'font-size:12.5px;color:#8fc0ff;font-weight:500;">'
            f'<span style="width:7px;height:7px;border-radius:50%;background:{BLUE};"></span>'
            f'{n_deployed} rules deployed</span></div>', unsafe_allow_html=True)

    lib_col, con_col = st.columns([1.15, 2.6], gap="medium")

    # ── attack library (real catalog: type → families → payloads + benign) ──
    with lib_col:
        st.markdown('<div class="eyebrow" style="margin:0 0 8px 2px;">ATTACK LIBRARY</div>',
                    unsafe_allow_html=True)
        st.segmented_control("type", list(TYPES), default="SQLi",
                             key="sim_type_label", label_visibility="collapsed")

        with st.container(key="sim_lib"):
            items = [(fam, p) for fam, plist in block["families"].items() for p in plist]
            items += [("benign", p) for p in block["benign"]]
            for i, (fam, payload) in enumerate(items):
                benign = fam == "benign"
                label = "benign" if benign else type_label
                color = MUTED if benign else TYPE_COLORS.get(type_key, MUTED)
                with st.container(key=f"sim_lib_card_{i}"):
                    st.markdown(cards.payload_card_html(
                        label=label, label_color=color, endpoint=target,
                        payload=payload, selected=ss.sim_payload == payload,
                    ), unsafe_allow_html=True)
                    if st.button("select", key=f"sim_lib_pick_{i}"):
                        ss.sim_payload = payload
                        st.rerun()

    # ── console ──
    with con_col:
        st.markdown(
            f'<div style="background:{CARD};border:1px solid {BORDER};border-radius:16px 16px 0 0;'
            f'border-bottom:1px solid {LINE};padding:13px 18px;display:flex;align-items:center;gap:10px;">'
            f'<span class="mono" style="font-size:12px;color:{FAINT};">TARGET</span>'
            f'<span class="mono" style="font-size:12.5px;color:#c7cdd8;">{html.escape(target)}</span>'
            f'<span class="mono" style="font-size:11px;color:{TYPE_COLORS.get(type_key, MUTED)};'
            f'margin-left:auto;">{type_label}</span></div>',
            unsafe_allow_html=True)

        st.text_input("payload", key="sim_payload", label_visibility="collapsed",
                      placeholder="Type a payload to send…")
        c1, c2 = st.columns([2.4, 1])
        c1.markdown(f'<div style="font-size:11.5px;color:{FAINT};padding-top:8px;">'
                    'Fired live through nginx-modsec — verdict is the WAF\'s real response.</div>',
                    unsafe_allow_html=True)
        with c2:
            with st.container(key="sim_launch"):
                st.button("▶  Launch Attack", on_click=_launch, use_container_width=True)

        # ── latest verdict ──
        if ss.sim_log:
            last = ss.sim_log[0]
            if last["status"] == "blocked":
                v_bg, v_bd, v_fg = "rgba(52,211,153,.10)", "#24402f", GREEN
                icon, msg, lbl = "🛡", "Request denied by the WAF", "BLOCKED"
            elif last["status"] == "uncaught":
                v_bg, v_bd, v_fg = "rgba(248,113,113,.10)", "#402424", RED
                icon, msg, lbl = "⚠", "Request passed through — no matching rule", "UNCAUGHT"
            else:  # error — couldn't reach the WAF
                v_bg, v_bd, v_fg = "rgba(251,191,36,.10)", "#40381f", AMBER
                icon = "⚡"
                msg = html.escape(last.get("error") or "Could not reach the WAF")
                lbl = "ERROR"
            st.markdown(f"""
              <div class="verdict" style="background:{v_bg};border:1px solid {v_bd};">
                <div style="width:48px;height:48px;border-radius:12px;background:rgba(0,0,0,.25);
                    display:flex;align-items:center;justify-content:center;font-size:22px;">{icon}</div>
                <div style="flex:1;min-width:200px;">
                  <div style="display:flex;align-items:center;gap:10px;">
                    <span style="font-size:18px;font-weight:700;color:{v_fg};">{lbl}</span>
                    <span class="mono" style="font-size:13px;color:{v_fg};">HTTP {last['code']}</span>
                  </div>
                  <div style="font-size:12.5px;color:#c7cdd8;margin-top:3px;">{msg}</div>
                  <div class="mono clip" style="font-size:11.5px;color:#7f8797;margin-top:8px;">{html.escape(last['payload'])}</div>
                </div>
                <div style="display:flex;gap:22px;">
                  <div><div style="font-size:10.5px;color:{MUTED};">Matched rule</div>
                    <div class="mono" style="font-size:14px;">{last['rule']}</div></div>
                  <div><div style="font-size:10.5px;color:{MUTED};">Cluster</div>
                    <div class="mono" style="font-size:14px;">{last['cluster']}</div></div>
                  <div><div style="font-size:10.5px;color:{MUTED};">Latency</div>
                    <div class="mono" style="font-size:14px;">{last['latency']}</div></div>
                </div>
              </div>
            """, unsafe_allow_html=True)

        # ── session stats (real outcomes only; errors excluded from the rate) ──
        fired = len(ss.sim_log)
        blocked = sum(1 for e in ss.sim_log if e["status"] == "blocked")
        uncaught = sum(1 for e in ss.sim_log if e["status"] == "uncaught")
        graded = blocked + uncaught
        rate = f"{round(blocked / graded * 100)}%" if graded else "—"
        st.write("")
        for col, (lbl, val, color) in zip(
                st.columns(4),
                [("Fired", fired, TEXT), ("Blocked", blocked, GREEN),
                 ("Uncaught", uncaught, RED), ("Block rate", rate, TEXT)]):
            col.markdown(f'<div class="metric"><div class="lbl">{lbl}</div>'
                         f'<div class="val" style="color:{color};">{val}</div></div>',
                         unsafe_allow_html=True)

        # ── session log ──
        st.write("")
        head_l, head_r = st.columns([3, 1])
        head_l.markdown('<div style="font-size:14px;font-weight:600;padding-top:4px;">Session Log</div>',
                        unsafe_allow_html=True)
        if head_r.button("Clear", use_container_width=True) and ss.sim_log:
            ss.sim_log = []
            st.rerun()

        if ss.sim_log:
            header = ('<div class="sim-grid sim-thead"><div>Time</div><div>Verdict</div><div>Payload</div>'
                      '<div>Target</div><div>Code</div><div>Rule</div><div>Cluster</div>'
                      '<div style="text-align:right;">Lat.</div></div>')
            style = {
                "blocked":  ("rgba(52,211,153,.14)", GREEN, "BLOCKED"),
                "uncaught": ("rgba(248,113,113,.14)", RED, "UNCAUGHT"),
                "error":    ("rgba(251,191,36,.14)", AMBER, "ERROR"),
            }
            rows = ""
            for e in ss.sim_log:
                lbg, lfg, lbl = style.get(e["status"], style["error"])
                rows += (
                    f'<div class="sim-grid sim-trow">'
                    f'<div class="mono" style="color:{MUTED};">{e["time"]}</div>'
                    f'<div><span class="sim-badge" style="background:{lbg};color:{lfg};">{lbl}</span></div>'
                    f'<div class="mono clip" style="color:#c7cdd8;" title="{html.escape(e["payload"])}">{html.escape(e["payload"])}</div>'
                    f'<div class="mono clip" style="color:#7f8797;font-size:11px;">{html.escape(e["target"])}</div>'
                    f'<div class="mono" style="color:{lfg};">{e["code"]}</div>'
                    f'<div class="mono" style="color:{MUTED};">{e["rule"]}</div>'
                    f'<div class="mono" style="color:{MUTED};">{e["cluster"]}</div>'
                    f'<div class="mono" style="color:{MUTED};text-align:right;">{e["latency"]}</div>'
                    f'</div>')
            st.markdown(f'<div style="background:{CARD};border:1px solid {BORDER};'
                        f'border-radius:16px;overflow:hidden;">{header}{rows}</div>',
                        unsafe_allow_html=True)
        else:
            st.markdown(
                f'<div style="background:{CARD};border:1px solid {BORDER};border-radius:16px;'
                f'padding:22px;text-align:center;font-size:12.5px;color:{FAINT};">'
                'No attacks fired yet — pick a payload and Launch.</div>', unsafe_allow_html=True)
