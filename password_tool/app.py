"""
Educational password checker and hash demonstration.

Use this app only for learning and security testing with passwords and hashes
you create yourself. It does not accept arbitrary target hashes or automate
dictionary/brute-force guessing.
"""

import streamlit as st

from checker import check_strength
from cracker import hash_password, verify_candidate

st.set_page_config(page_title="Password Crasher/Checker", page_icon="🔐")
st.title("Password Crasher/Checker")
st.caption(
    "Educational use only: test passwords and hashes you generate yourself. "
    "The hash demo checks one candidate and does not crack hashes. "
    "MD5, SHA-1, and SHA-256 are fast demo hashes, not safe password storage."
)

strength_tab, hash_tab = st.tabs(["Strength Checker", "Hash Demo"])

with strength_tab:
    st.subheader("Password Strength Checker")
    password = st.text_input("Password", type="password", key="strength_password")
    if password:
        assessment = check_strength(password)
        score = assessment["score"]
        color = ("#d32f2f", "#ef6c00", "#f9a825", "#66bb6a", "#2e7d32")[score]
        st.markdown(
            f"""
            <div style="background:#e0e0e0;border-radius:6px;height:12px">
              <div style="background:{color};width:{(score + 1) * 20}%;
                          height:12px;border-radius:6px"></div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        st.write(f"Strength score: **{score}/4**")
        st.write(f"Estimated offline crack time: **{assessment['crack_time_display']}**")
        if assessment["feedback"]:
            st.markdown("**Suggestions**")
            for suggestion in assessment["feedback"]:
                st.markdown(f"- {suggestion}")
        else:
            st.success("No additional suggestions.")

with hash_tab:
    st.subheader("Generate a Demo Hash")
    algo = st.selectbox(
        "Hash algorithm",
        ("md5", "sha1", "sha256", "bcrypt"),
        key="hash_algo",
    )
    if algo == "bcrypt":
        st.caption(
            "bcrypt adds a random salt, so hashing the same password again produces "
            "a different stored hash. Candidate checking still verifies correctly."
        )
    plaintext = st.text_input("Plaintext password", type="password", key="hash_plaintext")
    if st.button("Generate hash"):
        if not plaintext:
            st.warning("Enter a password to generate its hash.")
        else:
            st.session_state["generated_hash"] = hash_password(plaintext, algo)
            st.session_state["generated_hash_algo"] = algo

    generated_hash = st.session_state.get("generated_hash")
    generated_algo = st.session_state.get("generated_hash_algo")
    if generated_hash:
        st.code(generated_hash)
        st.caption(f"Generated with {generated_algo}. This value is held only in this session.")
        candidate = st.text_input("Try one candidate", type="password", key="hash_candidate")
        if st.button("Check candidate"):
            if not candidate:
                st.warning("Enter a candidate to check.")
            elif verify_candidate(candidate, generated_hash, generated_algo):
                st.success("Match: this candidate produced the generated hash.")
            else:
                st.info("No match for this candidate.")
