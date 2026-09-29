import json
from pathlib import Path

import pandas as pd
import streamlit as st

DATA_FILE = Path("data/enriched_events.json")

st.set_page_config(
    page_title="DevSecOps Security Event Dashboard",
    layout="wide"
)

st.title("Explainable AI Security Event Prioritisation Dashboard")

if not DATA_FILE.exists():
    st.error("No enriched events found. Run riskenrichment.py first.")
    st.stop()

with open(DATA_FILE, "r", encoding="utf-8") as file:
    events = json.load(file)

df = pd.DataFrame(events)

# -------------------------
# Sidebar filters
# -------------------------
st.sidebar.header("Filters")

search_term = st.sidebar.text_input(
    "Search Events",
    placeholder="CVE, package, title or event ID",
)

platform_options = sorted(
    df["source_platform"].dropna().unique().tolist()
)

platform_filter = st.sidebar.multiselect(
    "Filter by Platform",
    options=platform_options,
    default=platform_options,
)

severity_filter = st.sidebar.multiselect(
    "Filter by Severity",
    options=sorted(df["severity"].dropna().unique()),
    default=sorted(df["severity"].dropna().unique())
)

priority_filter = st.sidebar.multiselect(
    "Filter by Priority",
    options=sorted(df["priority_level"].dropna().unique()),
    default=sorted(df["priority_level"].dropna().unique())
)

filtered_df = df[
    (df["source_platform"].isin(platform_filter))
    & (df["severity"].isin(severity_filter))
    & (df["priority_level"].isin(priority_filter))
    ]
filtered_df = filtered_df.sort_values(
    by=["risk_score", "cvss_score"],
    ascending=[False, False],
)

if search_term:
    search_value = search_term.strip().lower()

    searchable_columns = [
        "event_id",
        "cve_id",
        "package_name",
        "title",
        "source_platform",
        "source_tool",
    ]

    search_mask = False

    for column in searchable_columns:
        if column in filtered_df.columns:
            column_match = (
                filtered_df[column]
                .fillna("")
                .astype(str)
                .str.lower()
                .str.contains(
                    search_value,
                    regex=False,
                )
            )

            search_mask = search_mask | column_match

    filtered_df = filtered_df[search_mask]


# -------------------------
# Summary metrics
# -------------------------
st.subheader("Security Event Summary")

col1, col2, col3, col4, col5, col6 = st.columns(6)

col1.metric("Total Events", len(filtered_df))

col2.metric(
    "GitHub Events",
    len(filtered_df[filtered_df["source_platform"] == "GitHub"]),
)

col3.metric(
    "GitLab Events",
    len(filtered_df[filtered_df["source_platform"] == "GitLab"]),
)

col4.metric(
    "Critical Events",
    len(filtered_df[filtered_df["severity"] == "critical"]),
)

col5.metric(
    "P1 Immediate",
    len(
        filtered_df[
            filtered_df["priority_level"] == "P1 - Immediate"
            ]
    ),
)

average_risk = (
    round(filtered_df["risk_score"].mean(), 2)
    if not filtered_df.empty
    else 0
)

col6.metric("Average Risk Score", average_risk)

# -------------------------
# Charts
# -------------------------
st.subheader("Security Event Visualisation")

chart_col1, chart_col2, chart_col3 = st.columns(3)

with chart_col1:
    st.write("Severity Distribution")
    severity_counts = filtered_df["severity"].value_counts()
    st.bar_chart(severity_counts)

with chart_col2:
    st.write("Priority Distribution")
    priority_counts = filtered_df["priority_level"].value_counts()
    st.bar_chart(priority_counts)


with chart_col3:
    st.write("Platform Distribution")
    platform_counts = filtered_df["source_platform"].value_counts()
    st.bar_chart(platform_counts)

# -------------------------
# Events table
# -------------------------
st.subheader("Events Table")

display_columns = [
    "event_id",
    "source_platform",
    "source_tool",
    "title",
    "severity",
    "cve_id",
    "cvss_score",
    "risk_score",
    "priority_level"
]

st.dataframe(filtered_df[display_columns], use_container_width=True)


# -------------------------
# Add cross-platform comparison
# -------------------------

st.subheader("Cross-Platform Vulnerability Comparison")

comparison_source = df.dropna(
    subset=["cve_id", "source_platform"]
).copy()

comparison_source["comparison_key"] = (
        comparison_source["cve_id"].astype(str)
        + "|"
        + comparison_source["package_name"].fillna("unknown-package").astype(str)
)

platform_coverage = (
    comparison_source.groupby("comparison_key")["source_platform"]
    .nunique()
)

shared_keys = platform_coverage[
    platform_coverage > 1
    ].index.tolist()

shared_events = comparison_source[
    comparison_source["comparison_key"].isin(shared_keys)
].copy()

shared_cve_count = shared_events["comparison_key"].nunique()

comparison_col1, comparison_col2, comparison_col3 = st.columns(3)

comparison_col1.metric(
    "Shared Vulnerabilities",
    shared_cve_count,
)

comparison_col2.metric(
    "GitHub-Only Findings",
    comparison_source[
        ~comparison_source["comparison_key"].isin(shared_keys)
        & (comparison_source["source_platform"] == "GitHub")
        ]["comparison_key"].nunique(),
)

comparison_col3.metric(
    "GitLab-Only Findings",
    comparison_source[
        ~comparison_source["comparison_key"].isin(shared_keys)
        & (comparison_source["source_platform"] == "GitLab")
        ]["comparison_key"].nunique(),
)

if shared_events.empty:
    st.info(
        "No matching CVE and package combinations were found "
        "across GitHub and GitLab."
    )
else:
    comparison_table = shared_events[
        [
            "cve_id",
            "package_name",
            "source_platform",
            "source_tool",
            "severity",
            "cvss_score",
            "risk_score",
            "priority_level",
        ]
    ].sort_values(
        by=["cve_id", "source_platform"]
    )

    st.dataframe(
        comparison_table,
        use_container_width=True,
        hide_index=True,
    )

# -------------------------
# Create the comparison table
# -------------------------
if shared_events.empty:
    st.info(
        "No matching CVE and package combinations were found "
        "across GitHub and GitLab."
    )
else:
    comparison_table = shared_events[
        [
            "cve_id",
            "package_name",
            "source_platform",
            "source_tool",
            "severity",
            "cvss_score",
            "risk_score",
            "priority_level",
        ]
    ].sort_values(
        by=["cve_id", "source_platform"]
    )

    st.dataframe(
        comparison_table,
        use_container_width=True,
        hide_index=True,
    )

# -------------------------
# Detect severity disagreements
# -------------------------

st.subheader("Tool Agreement Analysis")

agreement_rows = []

for comparison_key, group in shared_events.groupby("comparison_key"):
    cve_id = group["cve_id"].iloc[0]
    package_name = group["package_name"].iloc[0]

    severity_values = sorted(
        group["severity"].dropna().astype(str).unique().tolist()
    )

    cvss_values = sorted(
        {
            float(value)
            for value in group["cvss_score"].dropna().tolist()
        }
    )

    priority_values = sorted(
        group["priority_level"]
        .dropna()
        .astype(str)
        .unique()
        .tolist()
    )

    agreement_rows.append(
        {
            "cve_id": cve_id,
            "package_name": package_name,
            "platforms": ", ".join(
                sorted(
                    group["source_platform"]
                    .dropna()
                    .astype(str)
                    .unique()
                    .tolist()
                )
            ),
            "severity_agreement": (
                "Yes" if len(severity_values) == 1 else "No"
            ),
            "severity_values": ", ".join(severity_values),
            "cvss_agreement": (
                "Yes" if len(cvss_values) == 1 else "No"
            ),
            "cvss_values": ", ".join(
                str(value) for value in cvss_values
            ),
            "priority_agreement": (
                "Yes" if len(priority_values) == 1 else "No"
            ),
            "priority_values": ", ".join(priority_values),
        }
    )

    agreement_df = pd.DataFrame(agreement_rows)

if agreement_df.empty:
    st.info("No cross-platform matches are available for comparison.")
else:
    st.dataframe(
        agreement_df,
        use_container_width=True,
        hide_index=True,
    )

# -------------------------
# Event details
# -------------------------
st.subheader("Event Details")

if len(filtered_df) == 0:
    st.warning("No events match the selected filters.")
    st.stop()

selected_event = st.selectbox(
    "Select an event to inspect",
    filtered_df["event_id"].tolist()
)

event = filtered_df[filtered_df["event_id"] == selected_event].iloc[0].to_dict()

st.markdown(f"### {event.get('title')}")

left, right = st.columns(2)

with left:
    st.write("**Event ID:**", event.get("event_id"))
    st.write("**Source Platform:**", event.get("source_platform"))
    st.write("**Source Tool:**", event.get("source_tool"))
    st.write("**Event Type:**", event.get("event_type"))
    st.write("**Package:**", event.get("package_name"))
    st.write("**Ecosystem:**", event.get("package_ecosystem"))
    st.write("**CVE:**", event.get("cve_id"))
    st.write("**CVSS Score:**", event.get("cvss_score"))

with right:
    st.write("**Severity:**", event.get("severity"))
    st.write("**Risk Score:**", event.get("risk_score"))
    st.write("**Priority Level:**", event.get("priority_level"))
    st.write("**Patched Version:**", event.get("patched_version"))
    st.write("**STRIDE Categories:**", ", ".join(event.get("stride_categories", [])))

# -------------------------
# Explanation
# -------------------------
st.subheader("Risk Explanation")

explanation = event.get("explanation", {})

st.info(explanation.get("summary", "No explanation available."))

for reason in explanation.get("reasons", []):
    st.write(f"- {reason}")

# -------------------------
# AI Analysis placeholder
# -------------------------
st.subheader("AI Analysis")

st.warning(
    "AI analysis is currently pending. This section will later display OpenAI/BERT-generated security analysis."
)