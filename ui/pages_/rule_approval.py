"""Rule Approval — the one place every WAF rule lives, filterable by state.

Both the real deploy gate AND the lifecycle control panel for deployed rules:
  • CANDIDATE rules (lib.load_candidate_rules) — the generator's validated output in
    rules/experiments/, which the WAF does NOT load. Nothing is live until approved.
  • LIVE rules (lib.load_finalized_rules) — SecRules the WAF loads from rules/custom/,
    which the operator can roll back or restore.
Deduped by ID and filterable (All / Pending / Live / Rolled back / Rejected). Each
card carries its family, subgroup and functional validation, using the shared styled
cluster cards (ui/cards.py).

Actions are real:
  • Approve → promotes the candidate into rules/custom/auto_approved.conf and reloads
    ModSecurity (lib.deploy_generated_rule).
  • Reject / Undo → lib.set_rule_status.
  • Roll back / Restore → lib.set_rule_disabled + reload (SecRuleRemoveById).
"""

import html
import re

import streamlit as st

import cards
import lib
from theme import (AMBER, BLUE, CARD, FAINT, GREEN, LINE, MUTED, RED,
                   TEXT, page_header)

CODE = "#0a0d13"

# Family accent + display label. The raw family (sqli/xss/ssti) comes from the
# clustered CSV via lib.load_rule_queue, same as the rest of the pipeline.
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


def _status_pill(item: dict) -> tuple[str, str, str]:
    """(label, bg, fg) for the rule-state pill."""
    if item["live"]:
        if item.get("disabled"):
            return "ROLLED BACK", "rgba(251,191,36,.14)", AMBER
        return "LIVE", "rgba(52,211,153,.14)", GREEN
    if item["status"] == "rejected":
        return "REJECTED", "rgba(248,113,113,.14)", RED
    return "PENDING", "rgba(251,191,36,.14)", AMBER


def _state_of(item: dict) -> str:
    """One of 'pending' / 'live' / 'rolled back' / 'rejected' — used by the filter."""
    if item["live"]:
        return "rolled back" if item.get("disabled") else "live"
    return item["status"]

_CSS = f"""
<style>
  .ra-pill {{ display:inline-flex; align-items:center; gap:7px; padding:6px 12px;
      border-radius:999px; font-size:12px; font-weight:500; }}
  .ra-badge {{ font-size:9.5px; font-weight:600; letter-spacing:.04em; padding:3px 8px;
      border-radius:6px; }}
  .ra-card {{ background:{CARD}; border:1px solid #1e2531; border-radius:16px;
      padding:18px 20px; }}
  .ra-metric {{ background:{CARD}; border:1px solid #1e2531; border-radius:14px;
      padding:15px 18px; }}
  .ra-metric .lbl {{ font-size:11.5px; color:{MUTED}; }}

  .ra-head {{ background:{CARD}; border:1px solid #1e2531; border-radius:16px 16px 0 0;
      border-bottom:1px solid {LINE}; padding:14px 20px;
      display:flex; align-items:center; justify-content:space-between; }}
  .ra-code {{ background:{CODE}; border:1px solid #1e2531; border-top:none;
      border-radius:0 0 16px 16px; padding:16px 0;
      font-family:'JetBrains Mono',monospace; font-size:12.5px; line-height:1.7; }}
  .ra-ln {{ display:flex; gap:16px; padding:1.5px 20px; }}
  .ra-n {{ color:#3d4452; user-select:none; min-width:20px; text-align:right; }}
  .ra-t {{ white-space:pre-wrap; word-break:break-all; }}
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


def _code_block(text: str) -> str:
    lines = text.splitlines() or [text]
    rows = []
    for i, ln in enumerate(lines):
        color = FAINT if ln.strip().startswith("#") else "#c7cdd8"
        rows.append(f'<div class="ra-ln"><span class="ra-n">{i + 1:02d}</span>'
                    f'<span class="ra-t" style="color:{color};">{html.escape(ln)}</span></div>')
    return f'<div class="ra-code">{"".join(rows)}</div>'


def render() -> None:
    st.markdown(_CSS, unsafe_allow_html=True)
    st.markdown(cards.card_css("ra_queue"), unsafe_allow_html=True)

    # The control panel for every rule's deployment state: pending candidates
    # (rules/experiments, awaiting approval) AND live rules (rules/custom, which can
    # be rolled back or restored). Deduped by ID — a promoted candidate shows once,
    # as live.
    live = lib.load_finalized_rules()          # in rules/custom (has `disabled`)
    cand = lib.load_candidate_rules()          # in rules/experiments (has `status`)
    live_ids = {r["id"] for r in live}
    for r in live:
        r["live"], r["status"] = True, "approved"
    queue = list(live) + [dict(c, live=False) for c in cand if c["id"] not in live_ids]

    endpoints = _endpoints_by_cluster()
    for item in queue:
        item["rule_id"] = item["id"]
        item["family"] = _display_family(item.get("family"))   # CSV family -> display label
        item["endpoint"] = endpoints.get(item["cluster"], "—")

    def _rank(it):
        if not it["live"]:
            return 0 if it["status"] == "pending" else 3          # pending first, rejected last
        return 1 if not it.get("disabled") else 2                 # live, then rolled back
    queue.sort(key=lambda it: (_rank(it), int(it["id"])))
    # Stable render-unique handle: the generator can reassign the same rule ID to two
    # different clusters, so `id` is not safe as a widget key / selection id. See
    # load_candidate_rules, which dedupes by cluster (not ID).
    for i, item in enumerate(queue):
        item["_uid"] = i

    n_pending = sum(1 for q in queue if not q["live"] and q["status"] == "pending")
    n_live    = sum(1 for q in queue if q["live"] and not q.get("disabled"))
    n_rolled  = sum(1 for q in queue if q["live"] and q.get("disabled"))

    # ── header: title + state pills ──
    head_l, head_r = st.columns([2, 1.4])
    with head_l:
        st.markdown(page_header("Rule Approval",
                                "Approve AI candidates before they go live — and roll back "
                                "or restore rules that already are"),
                    unsafe_allow_html=True)
    with head_r:
        st.markdown(
            f'<div style="display:flex;gap:8px;justify-content:flex-end;padding-top:6px;">'
            f'<span class="ra-pill" style="border:1px solid #3a3320;background:rgba(251,191,36,.08);color:{AMBER};">'
            f'<span style="width:6px;height:6px;border-radius:50%;background:{AMBER};"></span>{n_pending} pending</span>'
            f'<span class="ra-pill" style="border:1px solid #24402f;background:rgba(52,211,153,.08);color:{GREEN};">'
            f'<span style="width:6px;height:6px;border-radius:50%;background:{GREEN};"></span>{n_live} live</span>'
            f'<span class="ra-pill" style="border:1px solid #3a3320;background:rgba(251,191,36,.08);color:{AMBER};">'
            f'<span style="width:6px;height:6px;border-radius:50%;background:{AMBER};"></span>{n_rolled} rolled back</span>'
            f'</div>', unsafe_allow_html=True)

    # ── empty state: offer to run the generator ──
    if not queue:
        st.info("No candidate or live rules yet. The generator turns each uncaught attack "
                "cluster into a validated ModSecurity rule for sign-off.")
        can_gen = lib.CLUSTERED_CSV.exists()
        if not can_gen:
            st.caption("Run the parser + clustering first "
                       "(`output/clustered_attacks.csv` is missing).")
        if st.button("⚙  Run generator", type="primary", disabled=not can_gen):
            with st.spinner("Generating rules from clustered attacks…"):
                res = lib.run_script("generate")
            if res["ok"]:
                st.success("Generator finished. Refreshing the queue.")
                st.rerun()
            else:
                st.error(f"Generator failed (exit {res['code']}).")
                st.code(res["stderr"] or res["stdout"] or "no output")
        return

    # ── filter (labels stay stable so changing counts don't reset the choice) ──
    FILTERS = {"All": None, "Pending": "pending", "Live": "live",
               "Rolled back": "rolled back", "Rejected": "rejected"}
    choice = st.segmented_control("filter", list(FILTERS), default="All",
                                  key="ra_filter", label_visibility="collapsed") or "All"
    want = FILTERS[choice]
    visible = [q for q in queue if want is None or _state_of(q) == want]

    if not visible:
        st.info(f"No rules are **{choice.lower()}**.")
        return

    # Resolve a cross-page preselect (from the Clusters page) — keyed by cluster,
    # since rule IDs aren't stable — into this render's concrete queue handle.
    jump_cid = st.session_state.pop("ra_sel_cluster", None)
    if jump_cid is not None:
        hit = next((q for q in visible if q["cluster"] == jump_cid), None)
        if hit:
            st.session_state.ra_sel = hit["_uid"]

    if st.session_state.get("ra_sel") not in {q["_uid"] for q in visible}:
        st.session_state.ra_sel = visible[0]["_uid"]

    queue_col, detail_col = st.columns([1.1, 2.4], gap="medium")

    # ── review queue ──
    with queue_col:
        st.markdown('<div class="eyebrow" style="margin:0 0 8px 2px;">REVIEW QUEUE</div>',
                    unsafe_allow_html=True)
        with st.container(key="ra_queue"):
            for item in visible:
                cid = item["cluster"]
                with st.container(key=f"ra_queue_card_{item['_uid']}"):
                    st.markdown(cards.cluster_card_html(
                        head=f"C{cid}" if cid is not None else f"#{item['id']}",
                        family=item["family"],
                        family_color=FAMILY_COLORS.get(item["family"], MUTED),
                        pill=_status_pill(item),
                        subgroup=item.get("subgroup"),
                        line2=_validation_label(item),
                        count=f"{item['scope_size']} payloads",
                        selected=item["_uid"] == st.session_state.ra_sel,
                    ), unsafe_allow_html=True)
                    if st.button("select", key=f"ra_queue_pick_{item['_uid']}"):
                        st.session_state.ra_sel = item["_uid"]
                        st.rerun()

    # ── review detail ──
    with detail_col:
        item = next(q for q in visible if q["_uid"] == st.session_state.ra_sel)
        status = item["status"]
        live = item["live"]
        fcolor = FAMILY_COLORS.get(item["family"], MUTED)
        scope = item["scope"]
        missed = set(item["missed"] or [])
        matched = max(item["scope_size"] - len(missed), 0)
        pct = round(matched / item["scope_size"] * 100) if item["scope_size"] else 0
        n_fp = len(item["false_pos"] or [])
        cluster_lbl = (f"Cluster {item['cluster']}"
                       if item["cluster"] is not None else item["id"])
        rid_txt = f"Rule #{item['rule_id']}" if item["rule_id"] else "no id"

        if item["valid"] is True:
            verdict, vcolor = "PASSED", GREEN
        elif item["valid"] is False:
            verdict, vcolor = "FAILED", RED
        else:
            verdict, vcolor = "no payloads", MUTED

        if item["live"]:
            desc = ("Live rule enforced by the WAF. Roll it back to remove it from the "
                    "WAF without deleting the rule; restore to re-enable.")
        elif status == "rejected":
            desc = "You rejected this candidate. Undo to move it back to pending."
        else:
            desc = ("AI-drafted candidate for this attack cluster, validated against its "
                    "captured payloads. Approve to promote it into the live WAF.")

        # header card
        st.markdown(f"""
          <div class="ra-card">
            <div style="display:flex;align-items:center;gap:12px;flex-wrap:wrap;margin-bottom:12px;">
              <span style="width:10px;height:10px;border-radius:3px;background:{fcolor};box-shadow:0 0 10px {fcolor};"></span>
              <span style="font-size:18px;font-weight:600;">{cluster_lbl} · {item['family']}</span>
              <span class="ra-badge" style="background:rgba(79,157,255,.12);color:#8fc0ff;">
                VALIDATION {verdict}</span>
              <span style="flex:1;"></span>
              <span class="mono" style="font-size:12px;color:{FAINT};">{rid_txt}</span>
            </div>
            <div style="font-size:13px;color:#c7cdd8;line-height:1.55;margin-bottom:12px;">{desc}</div>
            <div style="display:flex;gap:26px;flex-wrap:wrap;font-size:12px;color:{MUTED};">
              <span>Endpoint <span class="mono" style="color:#c7cdd8;">{html.escape(item['endpoint'])}</span></span>
              <span>Source <span class="mono" style="color:#c7cdd8;">{html.escape(item['source'])}</span></span>
              <span>Captured payloads <span class="mono" style="color:#c7cdd8;">{item['scope_size']}</span></span>
              <span>Validation <span class="mono" style="color:{vcolor};">{verdict}</span></span>
            </div>
          </div>
        """, unsafe_allow_html=True)

        # coverage — click to reveal the exact payloads this rule matches / misses
        st.write("")
        cov_label = f"Coverage · {matched}/{item['scope_size']} payloads matched"
        if n_fp:
            cov_label += f"  ·  ⚠ {n_fp} false positive(s)"
        with st.expander(cov_label):
            if not scope:
                st.caption("No captured payloads for this cluster to test against.")
            else:
                rows = []
                for p in scope[:40]:
                    hit = p not in missed
                    bg = "rgba(52,211,153,.14)" if hit else "rgba(248,113,113,.14)"
                    fg = GREEN if hit else RED
                    lbl = "MATCH" if hit else "MISS"
                    rows.append(
                        '<div style="display:flex;align-items:center;gap:12px;padding:9px 2px;'
                        'border-bottom:1px solid #141922;">'
                        f'<span class="ra-badge" style="background:{bg};color:{fg};width:48px;'
                        f'text-align:center;">{lbl}</span>'
                        f'<span class="mono" style="font-size:12px;color:#c7cdd8;overflow:hidden;'
                        f'text-overflow:ellipsis;white-space:nowrap;" title="{html.escape(p)}">{html.escape(p)}</span>'
                        '</div>')
                if len(scope) > 40:
                    rows.append(f'<div style="padding:8px 2px;color:{FAINT};font-size:11.5px;">'
                                f'+ {len(scope) - 40} more…</div>')
                st.markdown("".join(rows), unsafe_allow_html=True)
                if item["false_pos"]:
                    fp = ", ".join(item["false_pos"][:6])
                    st.markdown(f'<div style="margin-top:10px;color:{RED};font-size:12px;">'
                                f'⚠ Also matched benign input: {html.escape(fp)}</div>',
                                unsafe_allow_html=True)

        # rule preview
        st.write("")
        st.markdown(
            '<div class="ra-head"><div style="display:flex;align-items:center;gap:10px;">'
            '<span style="font-size:14px;font-weight:600;">Rule</span>'
            f'<span style="font-size:11px;color:{FAINT};">ModSecurity · phase 2 · {html.escape(item["source"])}</span></div></div>'
            + _code_block(item["rule"]), unsafe_allow_html=True)

        if item["error"]:
            st.warning(f"Validation note: {item['error']}")

        # decision / lifecycle bar — the single place a rule's deploy state is controlled
        st.write("")
        _reload_note = "Reloading ModSecurity…"

        def _pill(txt, bg, fg):
            return (f'<span class="ra-badge" style="background:{bg};color:{fg};padding:5px 12px;">{txt}</span>')

        if not item["live"] and status == "pending":
            info_col, rej_col, app_col = st.columns([2, 1, 1.2])
            with info_col:
                st.markdown(
                    '<div style="display:flex;align-items:center;gap:10px;padding-top:6px;">'
                    f'<div style="width:32px;height:32px;border-radius:50%;background:rgba(251,191,36,.14);'
                    f'display:flex;align-items:center;justify-content:center;color:{AMBER};">⏳</div>'
                    '<div><div style="font-size:13.5px;font-weight:600;">Awaiting your decision</div>'
                    f'<div style="font-size:11.5px;color:{MUTED};">Approving promotes it into the live WAF.</div></div>'
                    '</div>', unsafe_allow_html=True)
            with rej_col:
                if st.button("✕  Reject", key=f"ra_rej_{item['id']}", use_container_width=True):
                    lib.set_cluster_rejected(item["ckey"], True)
                    st.rerun()
            with app_col:
                deploy_disabled = item["valid"] is False
                if st.button("✓  Approve & Deploy", key=f"ra_app_{item['id']}",
                             type="primary", use_container_width=True,
                             disabled=deploy_disabled):
                    lib.deploy_generated_rule(item["rule"], item["cluster"], item["id"],
                                              item.get("subgroup"))
                    with st.spinner(_reload_note):
                        rl = lib.reload_modsecurity()
                    (st.toast("Approved — promoted to the live WAF.") if rl["ok"]
                     else st.warning("Promoted to rules/custom, but WAF reload failed: "
                                     f"{rl['stderr']}"))
                    st.rerun()
                if deploy_disabled:
                    st.caption("Validation failed — regenerate before deploying.")

        elif not item["live"]:                       # rejected candidate
            info_col, undo_col = st.columns([3, 1])
            info_col.markdown(
                '<div style="display:flex;align-items:center;gap:10px;padding-top:6px;">'
                + _pill("Rejected", "rgba(248,113,113,.14)", RED)
                + f'<span style="font-size:12px;color:{MUTED};">Not deployed.</span></div>',
                unsafe_allow_html=True)
            if undo_col.button("↩  Undo (to pending)", key=f"ra_undo_{item['id']}",
                               use_container_width=True):
                lib.set_cluster_rejected(item["ckey"], False)
                st.rerun()

        elif not item.get("disabled"):               # live & enforced
            info_col, rb_col = st.columns([3, 1.2])
            info_col.markdown(
                '<div style="display:flex;align-items:center;gap:10px;padding-top:6px;">'
                + _pill("Live", "rgba(52,211,153,.14)", GREEN)
                + f'<span style="font-size:12px;color:{MUTED};">Enforced by the WAF.</span></div>',
                unsafe_allow_html=True)
            if rb_col.button("⟲  Roll back", key=f"ra_rollback_{item['id']}",
                             use_container_width=True):
                lib.set_rule_disabled(item["id"], True)
                with st.spinner(_reload_note):
                    rl = lib.reload_modsecurity()
                (st.toast("Rolled back — removed from the live WAF.") if rl["ok"]
                 else st.warning(f"Rolled back in config, but WAF reload failed: {rl['stderr']}"))
                st.rerun()

        else:                                        # live but rolled back
            info_col, rs_col = st.columns([3, 1.2])
            info_col.markdown(
                '<div style="display:flex;align-items:center;gap:10px;padding-top:6px;">'
                + _pill("Rolled back", "rgba(251,191,36,.14)", AMBER)
                + f'<span style="font-size:12px;color:{MUTED};">Not enforced.</span></div>',
                unsafe_allow_html=True)
            if rs_col.button("✓  Restore", key=f"ra_restore_{item['id']}", type="primary",
                             use_container_width=True):
                lib.set_rule_disabled(item["id"], False)
                with st.spinner(_reload_note):
                    rl = lib.reload_modsecurity()
                (st.toast("Restored — enforced by the WAF again.") if rl["ok"]
                 else st.warning(f"Restored in config, but WAF reload failed: {rl['stderr']}"))
                st.rerun()
