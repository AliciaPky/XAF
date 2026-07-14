"""Rule Builder — write your own ModSecurity rule and deploy it to the live WAF.

The analyst path alongside the AI generator: craft a SecRule, validate it against a
cluster's captured payloads with the SAME functional gate the generated rules pass,
optionally ask the model for a second opinion, then deploy. A crafted rule goes
straight to rules/custom/manual.conf (live) — you are the gate for your own rule, so
it doesn't route through Rule Approval. Backed by lib.py (review_manual_rule /
llm_review_rule / deploy_manual_rule / next_manual_id).
"""

import streamlit as st

import lib
from theme import page_header


def render() -> None:
    st.markdown(page_header("Rule Builder",
                            "Craft your own ModSecurity rule and deploy it to the live WAF"),
                unsafe_allow_html=True)

    payloads_by_cluster = lib.csv_cluster_payloads()
    if not payloads_by_cluster:
        st.info("Need at least one attack cluster to validate against. Run the parser + "
                "clustering first (`output/clustered_attacks.csv` is missing).")
        return

    st.caption("Your rule is validated against a cluster's captured payloads with the same "
               "functional gate generated rules pass, then deployed straight to "
               "`rules/custom/manual.conf` — live immediately (you are the gate for your own rule).")
    st.write("")

    edit_col, side_col = st.columns([2, 1.2], gap="large")

    with edit_col:
        cluster = st.selectbox(
            "Target cluster", list(payloads_by_cluster),
            format_func=lambda c: f"Cluster {c} · {len(payloads_by_cluster[c])} payloads",
            key="rb_cluster")
        st.session_state.setdefault("rb_manual_id", lib.next_manual_id())
        rid = st.session_state.rb_manual_id
        st.caption(f"Assigned rule ID `{rid}` — forced on deploy so it can't collide "
                   "with existing rules.")

        template = (f'SecRule ARGS|ARGS_NAMES "@rx REGEX_HERE" \\\n'
                    f'    "id:{rid},phase:2,deny,log,'
                    f"msg:'XAF manual rule (cluster {cluster})',tag:'xaf-manual',severity:'CRITICAL'\"")
        rule_text = st.text_area("SecRule", value=template, height=210, key="rb_rule")

        with st.expander(f"Payloads cluster {cluster} should catch"):
            for p in payloads_by_cluster.get(cluster, [])[:25]:
                st.code(p, language=None)

    with side_col:
        # objective gate — the same functional validation generated rules pass
        res = lib.review_manual_rule(rule_text, cluster, rid)
        st.markdown("**Validation**")
        if not res["structural_ok"]:
            st.error(res["error"])
        elif res["valid"] is None:
            st.warning(res["error"] or "Could not validate.")
        elif res["valid"]:
            st.success(f"Passed — matches all {res['scope']} payloads, 0 false positives.")
        else:
            if res["missed"]:
                st.error("Misses: " + ", ".join(f"`{p}`" for p in res["missed"][:6]))
            if res["false_pos"]:
                st.error("False positives: " + ", ".join(f"`{p}`" for p in res["false_pos"][:6]))
            if res["error"]:
                st.error(res["error"])

        passed = res["structural_ok"] and res["valid"] is True
        if st.button("🚀  Deploy → reload", type="primary", disabled=not passed,
                     use_container_width=True, key="rb_deploy"):
            lib.deploy_manual_rule(res["cleaned"], cluster)
            with st.spinner("Reloading ModSecurity…"):
                rl = lib.reload_modsecurity()
            (st.success if rl["ok"] else st.warning)(
                "Crafted rule deployed to the live WAF." if rl["ok"]
                else f"Wrote rule to manual.conf, but WAF reload failed: {rl['stderr']}")
            for k in ("rb_manual_id", "rb_rule", "rb_review"):
                st.session_state.pop(k, None)
            st.rerun()
        if not passed:
            st.caption("Deploy unlocks once validation passes.")

        if st.button("🤖  Ask LLM to review", use_container_width=True, key="rb_llm"):
            with st.spinner("Asking the model…"):
                rev = lib.llm_review_rule(rule_text, payloads_by_cluster.get(cluster, []))
            st.session_state.rb_review = (rev["text"] if rev["ok"]
                                          else f"LLM review failed: {rev['error']}")
        st.caption("Advisory only — never gates deploy.")

    if st.session_state.get("rb_review"):
        st.write("")
        st.markdown("**LLM review** *(advisory)*")
        st.info(st.session_state.rb_review)
