"""
XAF Operator Console — Streamlit entry point.

This file is just the shell: page config, global CSS, the navigation rail and a
tiny session-state router. Each page lives in pages_/ and exposes a render().
Shared bits live in theme.py (palette + CSS) and charts.py (plotly builders).
"""

import streamlit as st

import lib
import theme
from pages_ import (attack_monitor, attack_simulator, clusters, dashboard, landing, rule_approval, rule_builder)

# Nav label -> page module. Order here is the order shown in the rail; it follows
# the pipeline flow: detect → cluster → approve candidates → manage live rules → test.
PAGES = {
    "Threat Dashboard": dashboard,
    "Attack Monitor":   attack_monitor,
    "Clusters":         clusters,
    "Rule Approval":    rule_approval,
    "Rule Builder":     rule_builder,
    "Attack Simulator": attack_simulator,
}
NAV = list(PAGES)

st.set_page_config(page_title="XAF Operator Console", layout="wide",
                   initial_sidebar_state="collapsed")
theme.inject_css()

# Auth gate — everything below only runs for a signed-in operator. If not logged
# in, this renders the Google sign-in card and stops the script.
landing.require_login()

st.session_state.setdefault("page", NAV[0])

# Background auto-generate scheduler (idempotent; the thread idles while off).
lib.ensure_scheduler_running()

# Fire Telegram alerts for any new events (uncaught attack / new candidate / newly deployed rule)
try:
    lib.run_alert_checks()
except Exception:  
    pass

# While the scheduler is on, auto-refresh so new runs / candidates / status show up
# without the operator having to click.
if lib.get_scheduler_state()["enabled"]:
    try:
        from streamlit_autorefresh import st_autorefresh
        st_autorefresh(interval=15000, key="xaf_live_refresh")
    except ImportError:
        pass


def _save_alert_settings() -> None:
    # Persist the notification toggles to state/alerts.json (fired on_change)
    lib.set_alert_settings(
        enabled=st.session_state.alrt_enabled,
        attack=st.session_state.alrt_attack,
        candidate=st.session_state.alrt_candidate,
        deployed=st.session_state.alrt_deployed)


def _save_scheduler() -> None:
    # Persist the auto-generate toggle to state/scheduler.json (fired on_change)
    lib.set_scheduler_enabled(st.session_state.sched_enabled)


def render_rail() -> None:
    # The left navigation rail: brand, clickable nav, Docker status, version
    with st.container(key="rail"):
        st.markdown(f"""
          <div class="brand">
            <div class="diamond"><div class="dot"></div></div>
            <div>
              <div style="font-size:16px;font-weight:700;letter-spacing:.04em;">XAF</div>
              <div style="font-size:9.5px;color:{theme.FAINT};letter-spacing:.16em;">OPERATOR CONSOLE</div>
            </div>
          </div>
          <div class="eyebrow">NAVIGATION</div>
        """, unsafe_allow_html=True)

        for item in NAV:
            active = st.session_state.page == item
            if st.button(item, key=f"nav_{item}", use_container_width=True,
                         type="primary" if active else "secondary"):
                st.session_state.page = item
                st.rerun()

        docker = lib.docker_status()
        if all(v == "up" for v in docker.values()):
            dot, status_text = theme.GREEN, "All services running"
        elif any(v == "unknown" for v in docker.values()):
            dot, status_text = theme.MUTED, "Docker not reachable"
        else:
            dot, status_text = theme.RED, ", ".join(f"{n} {s}" for n, s in docker.items())

        st.markdown(f"""
          <div class="eyebrow" style="margin-top:22px;">SYSTEM STATUS</div>
          <div class="statuscard">
            <span style="width:8px;height:8px;border-radius:50%;background:{dot};box-shadow:0 0 8px {dot};"></span>
            <div>
              <div style="font-size:13px;font-weight:600;">Docker</div>
              <div style="font-size:11px;color:{theme.MUTED};">{status_text}</div>
            </div>
          </div>
        """, unsafe_allow_html=True)

        # Telegram — notification settings
        if lib.telegram_configured():
            _s = lib.get_alert_settings()
            for _key, _flag in (("alrt_enabled", "enabled"), ("alrt_attack", "attack"),
                                ("alrt_candidate", "candidate"), ("alrt_deployed", "deployed")):
                st.session_state.setdefault(_key, _s[_flag])

            st.markdown('<div class="eyebrow" style="margin-top:22px;">ALERTS</div>',
                        unsafe_allow_html=True)
            with st.popover("🔔  Notifications", use_container_width=True):
                st.toggle("Enable notifications", key="alrt_enabled",
                          on_change=_save_alert_settings)
                off = not st.session_state.alrt_enabled
                st.caption("Alert me on Telegram when…")
                st.toggle("⚠️ New uncaught attack", key="alrt_attack",
                          on_change=_save_alert_settings, disabled=off)
                st.toggle("🧩 New candidate rule", key="alrt_candidate",
                          on_change=_save_alert_settings, disabled=off)
                st.toggle("✅ Rule deployed to WAF", key="alrt_deployed",
                          on_change=_save_alert_settings, disabled=off)
                st.divider()
                if st.button("Send test alert", use_container_width=True, key="alrt_test",
                             disabled=off):
                    res = lib.send_telegram("🔔 *XAF test alert* — notifications are working.")
                    st.toast("Test alert sent ✓" if res["ok"] else f"Failed: {res['error']}")

        # Auto-generate scheduler — toggle + status
        sch = lib.get_scheduler_state()
        st.session_state.setdefault("sched_enabled", sch["enabled"])
        st.markdown('<div class="eyebrow" style="margin-top:22px;">AUTOMATION</div>',
                    unsafe_allow_html=True)
        st.toggle("Auto-generate", key="sched_enabled",
                  on_change=_save_scheduler)
        if sch["running"]:
            _step = {"parse": "Parsing", "cluster": "Clustering",
                     "generate": "Generating"}.get(sch.get("step"), "Running")
            st.caption(f"⏳ {_step}…")
        elif sch["last_run"]:
            icon = "✓" if sch["last_ok"] else "✗"
            st.caption(f"Last run {sch['last_run'][11:19]} {icon}")
        elif sch["enabled"]:
            st.caption("Waiting for first run…")

        # Signed-in operator + logout
        st.markdown('<div class="eyebrow" style="margin-top:22px;">SESSION</div>',
                    unsafe_allow_html=True)
        st.markdown(
            f'<div style="font-size:12px;color:{theme.MUTED};margin-bottom:6px;">'
            f'Signed in as <b style="color:{theme.TEXT};">{st.user.name}</b></div>',
            unsafe_allow_html=True)
        st.button("Log out", key="logout", use_container_width=True, on_click=st.logout)

        st.markdown('<div class="mono" style="font-size:11px;color:#3d4452;margin-top:22px;">v1.0.0</div>',
                    unsafe_allow_html=True)


rail_col, main_col = st.columns([1, 4.4], gap="small")
with rail_col:
    render_rail()
with main_col:
    PAGES[st.session_state.page].render()
