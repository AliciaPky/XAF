"""
XAF Operator Console — Streamlit entrypoint
-------------------------------------------
Run from the project root:

    streamlit run ui/app.py

Five pages (Dashboard, Attack Monitor, Clusters, Rules, Attack Simulator)
bound to the real pipeline output files. Every page degrades gracefully when
its data isn't there yet, so the app is useful before Docker is even up.
"""

from __future__ import annotations

import re

import pandas as pd
import streamlit as st

import lib

LOGO = lib.ROOT / "ui" / "icon" / "logo-dark.png"

st.set_page_config(page_title="XAF Operator Console", page_icon=str(LOGO), layout="wide")

# --- a little CSS to tighten the operator look (cards, mono, compact) ---
st.markdown(
    """
    <style>
      .block-container {padding-top: 1.6rem; padding-bottom: 2rem;}
      [data-testid="stMetric"] {background:#161c24; border:0.5px solid rgba(255,255,255,0.06);
                                border-radius:10px; padding:12px 14px;}
      .xaf-pill {display:inline-flex; align-items:center; gap:5px; padding:2px 9px;
                 border-radius:10px; font-size:12px;}
      .xaf-up   {background:rgba(63,185,80,0.15);  color:#3fb950;}
      .xaf-down {background:rgba(248,81,73,0.15);  color:#f85149;}
      .xaf-unk  {background:rgba(139,152,165,0.15); color:#8b98a5;}
      code {font-size: 0.85em;}
      /* nav buttons styled like a vertical nav bar */
      section[data-testid="stSidebar"] .stButton > button {
        width:100%; text-align:left; justify-content:flex-start;
        padding:10px 14px; font-size:14px; font-weight:500; border-radius:8px; margin:1px 0;
      }
    </style>
    """,
    unsafe_allow_html=True,
)

PAGES = ["Threat Dashboard", "Attack Monitor", "Clusters", "Rules", "Attack Simulator"]


# ----------------------------------------------------------------------------
# sidebar — system status + navigation (no duplicated KPIs, per the design)
# ----------------------------------------------------------------------------
def sidebar() -> str:
    st.session_state.setdefault("page", PAGES[0])

    with st.sidebar:
        if LOGO.exists():
            c = st.columns([1, 1, 1])[1]
            c.image(str(LOGO), use_container_width=True)
        else:
            st.markdown("### 🛡️ XAF Operator Console")
        st.divider()
        ICONS = {
        "Threat Dashboard": ":material/home:",
        "Attack Monitor":   ":material/monitor_heart:",
        "Clusters":         ":material/scatter_plot:",
        "Rules":            ":material/gavel:",
        "Attack Simulator": ":material/local_fire_department:",
        }

        for p in PAGES:
            active = st.session_state.page == p
            if st.button(p, key=f"nav_{p}", width="stretch", icon=ICONS[p],
                        type="primary" if active else "secondary"):
                st.session_state.page = p
                st.rerun()

        # st.markdown("**System status**")
        # docker = lib.docker_status()
        # for name, state in docker.items():
        #     cls = {"up": "xaf-up", "down": "xaf-down"}.get(state, "xaf-unk")
        #     st.markdown(
        #         f'<div style="display:flex;justify-content:space-between;font-size:13px;margin:2px 0;">'
        #         f'<span style="color:#8b98a5;">{name}</span>'
        #         f'<span class="xaf-pill {cls}">● {state}</span></div>',
        #         unsafe_allow_html=True,
        #     )

        try:
            from streamlit_autorefresh import st_autorefresh
            st_autorefresh(interval=5000, key="xaf_autorefresh")
            st.caption(":green[● Auto-refreshing every 5s]")
        except ImportError:
            st.caption("Install `streamlit-autorefresh` for live refresh.")

    return st.session_state.page


# Display labels for the on-disk status values. "bypassed" reads like it beat
# the whole system, so we show "Uncaught" (i.e. CRS didn't catch it) in the UI.
STATUS_DISPLAY = {"blocked": "Blocked", "bypassed": "Uncaught"}


def status_label(s) -> str:
    key = str(s).strip().lower()
    if key in ("", "nan", "none"):
        return "Unknown"
    return STATUS_DISPLAY.get(key, str(s))


def kpi_card(col, label, value, icon, color="#e6edf3", tint=None):
    """A compact metric card with an icon and a coloured value. `tint` (a
    {bg, border} dict) makes a card stand out — used to flag bad numbers."""
    bg, border = "#161c24", "rgba(255,255,255,0.06)"
    if tint:
        bg, border = tint["bg"], tint["border"]
    col.markdown(
        f'<div style="background:{bg}; border:1px solid {border}; border-radius:12px; padding:14px 16px;">'
        f'<div style="display:flex; align-items:center; justify-content:space-between;">'
        f'<span style="font-size:13px; color:#8b98a5;">{label}</span>'
        f'<span style="font-size:20px; line-height:1;">{icon}</span></div>'
        f'<div style="font-size:30px; font-weight:600; color:{color}; margin-top:6px;">{value}</div>'
        f'</div>',
        unsafe_allow_html=True,
    )


# ----------------------------------------------------------------------------
# 1 — Threat Dashboard
# ----------------------------------------------------------------------------
def render_dashboard():
    st.subheader("Threat Dashboard")
    st.caption("At-a-glance overview of your application security")

    df = lib.load_attacks()
    if df.empty:
        st.info("No parsed attacks yet. Run the parser + clustering to populate "
                "`output/parsed_logs.json` / `output/clustered_attacks.csv`.")
        return

    m = lib.attack_metrics(df)
    c1, c2, c3, c5 = st.columns(4)
    kpi_card(c1, "Total Attacks", m["total"], "🎯")
    kpi_card(c2, "Blocked by CRS", m["blocked"], "🛡️", color="#3fb950")
    kpi_card(c3, "Uncaught by CRS", m["bypassed"], "⚠️", color="#f85149",
             tint={"bg": "rgba(248,81,73,0.08)", "border": "rgba(248,81,73,0.35)"})
    # kpi_card(c4, "Unique Payloads", m["unique"], "🧬", color="#a371f7")
    kpi_card(c5, "Active Clusters", m["clusters"], "🗂️", color="#5AB2FF")
    st.divider()
    left, right = st.columns([1, 1.4])

    with left:
        st.markdown("**Coverage over time** — cumulative % of attacks caught by CRS")
        cov = lib.coverage_over_time(df)
        if cov.empty:
            st.caption("No timestamped attacks yet.")
        else:
            st.line_chart(cov, x="time", y="coverage", height=240)

    with right:
        st.markdown("**Top Rule IDs** — by hits")
        # rule_id reads as float when some rows are blank (942100.0); coerce to
        # numeric, drop blanks, and cast to int so the labels are clean strings.
        rid = pd.to_numeric(df["rule_id"], errors="coerce").dropna().astype(int).astype(str)
        top = (rid.value_counts().head(8)
               .rename_axis("rule_id").reset_index(name="hits"))
        if top.empty:
            st.caption("No rule IDs recorded.")
        else:
            st.bar_chart(top, x="rule_id", y="hits", height=240)


    st.markdown("**Recent Attacks**")
    recent = df.tail(8).iloc[::-1]
    cols = [c for c in ("timestamp", "status", "uri", "payload", "rule_id", "cluster") if c in recent.columns]
    recent_view = recent[cols].copy()
    recent_view["status"] = recent_view["status"].map(status_label)
    st.dataframe(recent_view, use_container_width=True, hide_index=True)


# ----------------------------------------------------------------------------
# 2 — Attack Monitor
# ----------------------------------------------------------------------------
def render_monitor():
    st.subheader("Attack Monitor")
    st.caption("Full, filterable stream of detected attacks")

    df = lib.load_attacks()
    if df.empty:
        st.info("No attacks to show yet.")
        return

    per_min = lib.attacks_per_minute(df)
    if not per_min.empty:
        st.markdown("**Attacks over time** — per minute")
        st.area_chart(per_min, color=["#3fb950", "#f85149"], height=200)

    f1, f2, f3 = st.columns([1, 1, 2])
    statuses = ["All"] + sorted(s for s in df["status"].map(status_label).unique() if s)
    sel_status = f1.selectbox("Status", statuses)
    uris = ["All"] + sorted(u for u in df["uri"].astype(str).unique() if u)[:200]
    sel_uri = f2.selectbox("URI", uris)
    search = f3.text_input("Search payload", placeholder="e.g. union, sleep, OR 1=1")

    view = df.copy()
    if sel_status != "All":
        view = view[view["status"].map(status_label) == sel_status]
    if sel_uri != "All":
        view = view[view["uri"].astype(str) == sel_uri]
    if search:
        view = view[view["payload"].astype(str).str.contains(search, case=False, na=False)]

    b = int((view["status"].str.lower() == "blocked").sum())
    u = int((view["status"].str.lower() == "bypassed").sum())
    st.caption(f"Showing {len(view)} of {len(df)} entries  ·  "
               f":green[{b} blocked]  ·  :red[{u} uncaught]")
    cols = [c for c in ("timestamp", "status", "method", "uri", "payload",
                        "rule_id", "rule_msg", "cluster") if c in view.columns]
    out = view[cols].copy()
    out["status"] = out["status"].map(status_label)
    st.dataframe(out, use_container_width=True, hide_index=True, height=460)

    csv = out.to_csv(index=False).encode("utf-8")
    st.download_button("Export CSV", csv, file_name="xaf_attacks.csv", mime="text/csv")


# ----------------------------------------------------------------------------
# 3 — Clusters
# ----------------------------------------------------------------------------
def render_clusters():
    st.subheader("Clusters")
    st.caption("Attack clusters and payload analysis · DBSCAN on TF-IDF char n-grams")

    payloads = lib.load_cluster_payloads()
    if not payloads:
        st.info("No clusters yet. Run `clustering/cluster_attacks.py` to produce "
                "`output/clustered_attacks.csv`.")
        return

    summary_col, plot_col = st.columns([1, 1.2])

    with summary_col:
        st.markdown("**Cluster summary**")
        for cid, ps in payloads.items():
            with st.container(border=True):
                st.markdown(f"**Cluster {cid}** &nbsp; `{len(ps)} payloads`")
                st.caption(lib.cluster_signature_label(ps))
                st.code(ps[0], language=None)

    with plot_col:
        st.markdown("**PCA scatter (TF-IDF)**")
        _render_pca(payloads)

    st.markdown("**Payloads**")
    cid = st.selectbox("Cluster", list(payloads.keys()), format_func=lambda c: f"Cluster {c}")
    st.code("\n".join(payloads[cid]), language=None)


def _render_pca(payloads: dict):
    """2D PCA of TF-IDF char n-grams, coloured by cluster — same features the
    clustering step uses, so the picture matches DBSCAN's input."""
    rows, labels = [], []
    for cid, ps in payloads.items():
        rows.extend(ps)
        labels.extend([str(cid)] * len(ps))
    if len(rows) < 3:
        st.caption("Need at least 3 payloads to plot.")
        return
    try:
        from sklearn.feature_extraction.text import TfidfVectorizer
        from sklearn.decomposition import PCA
        X = TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5),
                            max_features=1000).fit_transform(rows).toarray()
        comps = PCA(n_components=2).fit_transform(X)
        plot_df = pd.DataFrame({"PC1": comps[:, 0], "PC2": comps[:, 1], "cluster": labels})
        st.scatter_chart(plot_df, x="PC1", y="PC2", color="cluster", height=320)
    except Exception as e:  # noqa: BLE001 — show, don't crash the page
        st.caption(f"Could not compute PCA: {e}")


# ----------------------------------------------------------------------------
# 4 — Rules (generate + validate + approve + deploy)
# ----------------------------------------------------------------------------
def _render_craft_rule(payloads_by_cluster: dict):
    """Analyst writes their own SecRule, validates it against a cluster (same gate
    as generated rules), optionally asks the LLM for advice, then deploys."""
    with st.expander("✍️ Craft & deploy your own rule"):
        if not payloads_by_cluster:
            st.caption("Need at least one cluster to validate against. Run clustering first.")
            return

        cluster = st.selectbox("Target cluster", list(payloads_by_cluster.keys()),
                               format_func=lambda c: f"Cluster {c}", key="craft_cluster")
        st.session_state.setdefault("manual_id", lib.next_manual_id())
        rid = st.session_state.manual_id
        st.caption(f"Assigned rule ID `{rid}` — forced on deploy so it can't collide.")

        template = (f'SecRule ARGS|ARGS_NAMES "@rx REGEX_HERE" \\\n'
                    f'    "id:{rid},phase:2,deny,log,'
                    f"msg:'XAF manual rule (cluster {cluster})',tag:'xaf-manual',severity:'CRITICAL'\"")
        rule_text = st.text_area("SecRule", value=template, height=170, key="craft_rule")

        # objective gate — the same functional validation generated rules pass
        res = lib.review_manual_rule(rule_text, cluster, rid)
        if not res["structural_ok"]:
            st.error(res["error"])
        elif res["valid"] is None:
            st.warning(res["error"] or "Could not validate.")
        elif res["valid"]:
            st.success(f"Validation passed — matches all {res['scope']} payloads, 0 false positives.")
        else:
            if res["missed"]:
                st.error("Misses: " + ", ".join(f"`{p}`" for p in res["missed"][:6]))
            if res["false_pos"]:
                st.error("False positives: " + ", ".join(f"`{p}`" for p in res["false_pos"][:6]))
            if res["error"]:
                st.error(res["error"])

        cc1, cc2 = st.columns(2)
        if cc1.button("🤖 Ask LLM to review", key="craft_llm", width="stretch"):
            with st.spinner("Asking the model…"):
                rev = lib.llm_review_rule(rule_text, payloads_by_cluster.get(cluster, []))
            st.session_state.craft_review = rev["text"] if rev["ok"] else f"LLM review failed: {rev['error']}"

        passed = res["structural_ok"] and res["valid"] is True
        if cc2.button("🚀 Deploy → reload", key="craft_deploy", type="primary",
                      disabled=not passed, width="stretch"):
            lib.deploy_manual_rule(res["cleaned"], cluster)
            with st.spinner("Reloading ModSecurity…"):
                rl = lib.reload_modsecurity()
            (st.success if rl["ok"] else st.warning)(
                "Crafted rule deployed." if rl["ok"]
                else f"Wrote rule, but reload failed: {rl['stderr']}")
            for k in ("manual_id", "craft_rule", "craft_review"):
                st.session_state.pop(k, None)
            st.rerun()
        if not passed:
            st.caption("Deploy unlocks once validation passes (advisory LLM review is optional).")

        if st.session_state.get("craft_review"):
            st.markdown("**LLM review** *(advisory)*")
            st.info(st.session_state.craft_review)


def render_rules():
    st.subheader("Rules")
    st.caption("Validated rules deploy automatically — disable any rule here to roll it back")

    deployed = lib.load_deployed_rules()
    payloads_by_cluster = lib.load_cluster_payloads()
    att = lib.load_attacks()
    trace_by_cluster = {q["cluster"]: q for q in lib.load_rule_queue()}

    live = [d for d in deployed if not d["disabled"]]
    rolled = [d for d in deployed if d["disabled"]]

    # --- header: live/disabled counts + a Generate / Reload menu ---
    _, h2 = st.columns([3, 1])
    h2.markdown(
        f"<div style='text-align:right;color:#8b98a5;font-size:13px;'>"
        f"🟢 {len(live)} live · ⚪ {len(rolled)} disabled</div>", unsafe_allow_html=True)
    with h2.popover("⚙️ Generate"):
        st.caption("Runs the LLM generator (XAF_MODEL / XAF_BASE_URL / OPENAI_API_KEY). "
                   "Passing rules are written to rules/custom/ and go live on reload.")
        if st.button("Run generator", key="run_gen"):
            with st.spinner("Generating + validating rules…"):
                res = lib.run_script("generate")
            if res["ok"]:
                with st.spinner("Reloading ModSecurity to deploy…"):
                    rl = lib.reload_modsecurity()
                (st.success if rl["ok"] else st.warning)(
                    "Generated and deployed." if rl["ok"]
                    else f"Generated, but reload failed: {rl['stderr']}")
            else:
                st.error(f"Generator failed (exit {res['code']}).")
            if res["stdout"]:
                st.code(res["stdout"][-3000:])
        st.divider()
        if st.button("↻ Reload ModSecurity now", key="reload_manual"):
            with st.spinner("Restarting nginx-modsec…"):
                rl = lib.reload_modsecurity()
            (st.success if rl["ok"] else st.error)(
                "Reloaded." if rl["ok"] else f"Failed: {rl['stderr']}")

    _render_craft_rule(payloads_by_cluster)

    if not deployed:
        st.info("No rules generated yet. Use ⚙️ Generate or craft your own above.")
        return

    st.divider()
    left, right = st.columns([1, 2.3])

    with left:
        st.markdown(f"**Deployed rules ({len(deployed)})**")
        ids = [d["id"] for d in deployed if d["id"]]
        if ids and st.session_state.get("rule_sel") not in ids:
            st.session_state.rule_sel = ids[0]
        for d in deployed:
            if not d["id"]:
                continue
            selected = st.session_state.get("rule_sel") == d["id"]
            chip = "🟢 LIVE" if not d["disabled"] else "⚪ DISABLED"
            if st.button(f"{d['id']} · Cluster {d['cluster']} · {chip}",
                         key=f"sel_{d['id']}", width="stretch",
                         type="primary" if selected else "secondary"):
                st.session_state.rule_sel = d["id"]
                st.rerun()

    with right:
        item = next((d for d in deployed if d["id"] == st.session_state.get("rule_sel")), None)
        if item is None:
            st.caption("Select a rule to review it here.")
        else:
            tr = trace_by_cluster.get(item["cluster"])
            status = "🟢 Live" if not item["disabled"] else "⚪ Disabled (rolled back)"
            st.markdown(f"### Rule {item['id']}")
            st.caption(f"Cluster {item['cluster']} · {status} · source `{item['source']}`")
            st.code(item["rule"], language="apacheconf")

            p1, p2 = st.columns(2)
            with p1:
                with st.container(border=True):
                    if tr and tr["valid"] is not None:
                        caught = tr["scope_size"] - len(tr["missed"])
                        st.markdown(f"**Validation** · {caught}/{tr['scope_size']} · "
                                    f"{len(tr['false_pos'])} FP")
                        scope = payloads_by_cluster.get(item["cluster"], [])
                        for p in [x for x in scope if x not in tr["missed"]][:6]:
                            st.markdown(f"<span style='color:#3fb950;'>✓</span> `{p}`",
                                        unsafe_allow_html=True)
                        for p in tr["missed"][:4]:
                            st.markdown(f"<span style='color:#f85149;'>✗</span> `{p}`",
                                        unsafe_allow_html=True)
                    else:
                        st.markdown("**Validation**")
                        st.caption("No trace/validation data for this rule.")
            with p2:
                with st.container(border=True):
                    st.markdown("**Diff vs CRS**")
                    cl = att[att["cluster"].astype(str) == str(item["cluster"])] if not att.empty else att
                    if cl is None or cl.empty:
                        st.caption("No CRS status recorded for this cluster.")
                    else:
                        crs_missed = int((cl["status"].str.lower() == "bypassed").sum())
                        crs_blocked = int((cl["status"].str.lower() == "blocked").sum())
                        if crs_missed:
                            st.markdown(f"<span style='color:#3fb950;'>+ covers {crs_missed} "
                                        f"payload(s) CRS left uncaught</span>", unsafe_allow_html=True)
                        st.caption(f"CRS already caught {crs_blocked} in this cluster")

            if tr:
                with st.expander("Trace · prompt → response"):
                    st.caption("Prompt"); st.code(tr["prompt"] or "(not saved)")
                    st.caption("Raw response"); st.code(tr["response"] or "(not saved)")

            # rollback / restore — applies immediately by reloading ModSecurity
            if not item["disabled"]:
                if st.button("🚫 Disable (roll back) → reload", type="primary", width="stretch"):
                    lib.set_rule_disabled(item["id"], True)
                    with st.spinner("Reloading ModSecurity…"):
                        rl = lib.reload_modsecurity()
                    (st.success if rl["ok"] else st.warning)(
                        "Rule disabled and removed from the live WAF." if rl["ok"]
                        else f"Disabled in config, but reload failed: {rl['stderr']}")
                    st.rerun()
            else:
                if st.button("✅ Re-enable → reload", type="primary", width="stretch"):
                    lib.set_rule_disabled(item["id"], False)
                    with st.spinner("Reloading ModSecurity…"):
                        rl = lib.reload_modsecurity()
                    (st.success if rl["ok"] else st.warning)(
                        "Rule re-enabled." if rl["ok"]
                        else f"Re-enabled in config, but reload failed: {rl['stderr']}")
                    st.rerun()

    st.divider()
    st.caption("Production stats (last fired, live false positives) need the ModSecurity "
               "audit log wired in — not available yet.")


# ----------------------------------------------------------------------------
# 5 — Attack Simulator
# ----------------------------------------------------------------------------
def render_simulator():
    st.subheader("Attack Simulator")
    st.caption("Fire a payload at Juice Shop through nginx-modsec and watch the loop close")

    docker = lib.docker_status()
    if docker.get("nginx-modsec") != "up":
        st.warning("`nginx-modsec` doesn't appear to be up — `docker compose up` first, "
                   "or firing will just error.")

    samples = ["'/**/OR/**/1=1-- -", "' OR 1=1-- -", "admin'-- -",
               "' UNION SELECT NULL-- -", "' OR SLEEP(5)-- -"]
    st.session_state.setdefault("xaf_payload", samples[0])
    cols = st.columns(len(samples))
    for i, s in enumerate(samples):
        if cols[i].button(s, use_container_width=True):
            st.session_state["xaf_payload"] = s
    payload = st.text_input("Payload", key="xaf_payload")

    if st.button("🔥 Fire", type="primary"):
        res = lib.fire_payload(payload)
        if not res["ok"]:
            st.error(f"Request failed: {res['error']}")
        else:
            st.session_state["xaf_last_fire"] = res

    res = st.session_state.get("xaf_last_fire")
    if res and res.get("ok"):
        b1, b2 = st.columns(2)
        with b1:
            st.markdown("**Result**")
            if res["blocked"]:
                st.success(f"{res['status_code']} · BLOCKED")
            else:
                st.error(f"{res['status_code']} · BYPASSED — slipped past the WAF")
            st.caption(res["url"])

    st.divider()
    st.markdown("**Re-run the pipeline on what you just fired**")
    p1, p2 = st.columns(2)
    if p1.button("Re-cluster"):
        with st.spinner("Clustering…"):
            r = lib.run_script("cluster")
        (st.success if r["ok"] else st.error)("Clustering done." if r["ok"] else "Clustering failed.")
        if r["stdout"]:
            st.code(r["stdout"][-2000:])
    if p2.button("Regenerate rules"):
        with st.spinner("Generating…"):
            r = lib.run_script("generate")
        (st.success if r["ok"] else st.error)("Generation done." if r["ok"] else "Generation failed.")
        if r["stdout"]:
            st.code(r["stdout"][-2000:])
    st.caption("Note: parsing the freshly-fired request into parsed_logs.json depends on your "
               "parser step; wire that in once the parser writes the full log.")


# ----------------------------------------------------------------------------
ROUTES = {
    "Threat Dashboard": render_dashboard,
    "Attack Monitor": render_monitor,
    "Clusters": render_clusters,
    "Rules": render_rules,
    "Attack Simulator": render_simulator,
}

page = sidebar()
ROUTES[page]()
