

import streamlit as st

from sources import (
    SOURCE_REGISTRY,
    LLMExplainer,
    SourceError,
    AuthError,
    NotFoundError,
    RateLimitError,
    LLMError,
    validate_indicator,
)

st.set_page_config(page_title="ThreatLens", page_icon="🔎", layout="centered")

# --------------------------------------------------------------------------- #
# Session state
# --------------------------------------------------------------------------- #
if "result" not in st.session_state:
    st.session_state.result = None
if "explanation" not in st.session_state:
    st.session_state.explanation = None
if "explanation_error" not in st.session_state:
    st.session_state.explanation_error = None

INDICATOR_LABELS = {
    "IP Address": "ip",
    "Domain": "domain",
    "URL": "url",
}

INPUT_PROMPTS = {
    "ip": "Enter the IP address to check",
    "domain": "Enter the domain to check",
    "url": "Enter the URL to check",
}

# --------------------------------------------------------------------------- #
# Sidebar — inputs
# --------------------------------------------------------------------------- #
st.sidebar.title("🔎 ThreatLens")
st.sidebar.caption("AI-powered threat intelligence assistant")

input_type_label = st.sidebar.radio("Input type", list(INDICATOR_LABELS.keys()))
indicator_type = INDICATOR_LABELS[input_type_label]

knowledge_level = st.sidebar.radio(
    "Knowledge level", ["Beginner", "Intermediate", "Expert"], index=1
)

indicator_value = st.sidebar.text_input(INPUT_PROMPTS[indicator_type])

st.sidebar.markdown("---")
st.sidebar.subheader("API Keys")
groq_api_key = st.sidebar.text_input("Groq API key", type="password")
vt_api_key = st.sidebar.text_input("VirusTotal API key", type="password")

keys_present = bool(groq_api_key.strip()) and bool(vt_api_key.strip())
if not keys_present:
    st.sidebar.warning("Both a Groq API key and a VirusTotal API key are required.")

analyze_clicked = st.sidebar.button(
    "Analyze", type="primary", disabled=not keys_present
)

# --------------------------------------------------------------------------- #
# Main area
# --------------------------------------------------------------------------- #
st.title("ThreatLens")
st.caption(
    "Look up an IP, domain, or URL, get VirusTotal detection data, and a "
    "plain-language risk explanation tuned to your knowledge level."
)

if analyze_clicked:
    st.session_state.result = None
    st.session_state.explanation = None
    st.session_state.explanation_error = None

    if not validate_indicator(indicator_value, indicator_type):
        st.error(
            f"'{indicator_value}' doesn't look like a valid {input_type_label.lower()}. "
            "Please double-check the value and try again."
        )
    else:
        vt_source = SOURCE_REGISTRY["virustotal"]
        with st.spinner(f"Querying {vt_source.name}..."):
            try:
                result = vt_source.fetch(
                    indicator_value.strip(), indicator_type, vt_api_key.strip()
                )
                st.session_state.result = result
            except NotFoundError:
                st.info("No data available for this indicator on VirusTotal.")
            except AuthError as exc:
                st.error(f"VirusTotal authentication failed: {exc.message}")
            except RateLimitError as exc:
                st.error(f"VirusTotal rate limit hit: {exc.message}")
            except SourceError as exc:
                status = f" (HTTP {exc.status_code})" if exc.status_code else ""
                st.error(f"VirusTotal error{status}: {exc.message}")

        if st.session_state.result is not None:
            with st.spinner("Generating explanation..."):
                explainer = LLMExplainer()
                try:
                    st.session_state.explanation = explainer.explain(
                        st.session_state.result, knowledge_level, groq_api_key.strip()
                    )
                except LLMError as exc:
                    st.session_state.explanation_error = str(exc)

# --------------------------------------------------------------------------- #
# Results
# --------------------------------------------------------------------------- #
result = st.session_state.result

if result is not None:
    st.subheader(f"Result for `{result['indicator']}`")

    verdict = result["verdict"]
    verdict_colors = {
        "malicious": "🔴",
        "suspicious": "🟠",
        "harmless": "🟢",
        "unknown": "⚪",
    }
    st.markdown(f"**Verdict:** {verdict_colors.get(verdict, '⚪')} `{verdict.upper()}`")

    stats = result["stats"]
    cols = st.columns(4)
    cols[0].metric("Malicious", stats["malicious"])
    cols[1].metric("Suspicious", stats["suspicious"])
    cols[2].metric("Harmless", stats["harmless"])
    cols[3].metric("Undetected", stats["undetected"])

    if result["metadata"]:
        st.markdown("**Metadata**")
        st.table(
            {
                "Field": list(result["metadata"].keys()),
                "Value": [str(v) for v in result["metadata"].values()],
            }
        )

    st.markdown("### AI Explanation")
    if st.session_state.explanation:
        st.markdown(st.session_state.explanation)
    elif st.session_state.explanation_error:
        st.warning(
            "The AI summary failed, but here's the raw VirusTotal data above.\n\n"
            f"Details: {st.session_state.explanation_error}"
        )
    else:
        st.info("No explanation generated yet.")

    with st.expander("Raw VirusTotal response (JSON)"):
        st.json(result["raw"])
else:
    st.write("Enter an indicator in the sidebar and click **Analyze** to get started.")