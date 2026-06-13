import os
import streamlit as st
import requests
from dotenv import load_dotenv

load_dotenv()

API_URL = "https://security-review-sakshum.lemonriver-d0f61589.eastus.azurecontainerapps.io"
API_KEY = os.environ.get("API_KEY", "")

SEVERITY_COLORS = {
    "CRITICAL": "🔴",
    "HIGH": "🟠",
    "MEDIUM": "🟡",
    "LOW": "🔵",
}

CONFIDENCE_BADGES = {
    "HIGH": "🟢 High confidence",
    "MEDIUM": "🟡 Medium confidence",
    "LOW": "🔴 Low confidence",
}

st.title("Security Review Tool")

language = st.selectbox(
    "Language",
    ["python", "javascript", "java", "typescript", "go", "ruby", "php", "csharp", "cpp", "other"],
)

code = st.text_area("Paste your code here", height=300)

if st.button("Scan"):
    if not code.strip():
        st.warning("Please paste some code first")
    else:
        with st.spinner("Scanning..."):
            try:
                response = requests.post(
                    f"{API_URL}/scan",
                    json={"code": code, "language": language},
                    headers={"X-API-Key": API_KEY},
                    timeout=120,
                )
            except requests.exceptions.RequestException as e:
                st.error(f"Request failed: {e}")
                st.stop()

        if response.status_code == 400:
            st.error(response.json().get("detail", "Bad request"))
            st.stop()
        elif response.status_code == 401:
            st.error("Invalid or missing API key.")
            st.stop()
        elif response.status_code == 429:
            st.error("Rate limit exceeded. Try again later.")
            st.stop()
        elif not response.ok:
            st.error(f"Server error ({response.status_code}): {response.text}")
            st.stop()

        data = response.json()
        vulns = data.get("vulnerabilities", [])
        summary = data.get("summary", "")
        fixed_code = data.get("fixed_code", "")

        # Summary
        st.subheader("Summary")
        st.info(summary if summary else "No summary returned.")

        # Vulnerabilities
        st.subheader(f"Vulnerabilities ({len(vulns)} found)")
        if not vulns:
            st.success("No vulnerabilities detected.")
        else:
            for v in vulns:
                severity = v.get("severity", "UNKNOWN")
                icon = SEVERITY_COLORS.get(severity, "⚪")
                label = f"{icon} [{severity}] {v.get('name', 'Unknown')}  —  {v.get('owasp_category', '')}"
                with st.expander(label):
                    confidence = v.get("confidence", "HIGH")
                    confidence_badge = CONFIDENCE_BADGES.get(confidence, "🟡 Unknown confidence")
                    st.markdown(f"**Rule:** `{v.get('rule_id', '')}`")
                    st.markdown(f"**Severity:** {severity}  |  **Confidence:** {confidence_badge}")
                    st.markdown(f"**OWASP Category:** {v.get('owasp_category', '')}")
                    if confidence == "LOW":
                        st.warning("⚠️ Needs human review")
                    st.markdown("**Explanation:**")
                    st.write(v.get("explanation", ""))
                    st.markdown("**Vulnerable Snippet:**")
                    st.code(v.get("vulnerable_snippet", ""), language=language)

        # Fixed code
        st.subheader("Fixed Code")
        if fixed_code:
            st.code(fixed_code, language=language)
        else:
            st.write("No fixed code returned.")
