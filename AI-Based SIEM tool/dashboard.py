# step:3
import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime
import os
import json
import yaml

print("Starting dashboard... Run with: streamlit run dashboard.py")

# Page config
st.set_page_config(
    page_title="Self-Evolving SIEM Rule Engine",
    page_icon="🛡️",
    layout="wide"
)

# Title
st.title("🛡️ Self-Evolving SIEM Rule Engine")
st.markdown("An AI-powered system that learns normal behavior and generates detection rules automatically")

# Sidebar
st.sidebar.header("Controls")
refresh = st.sidebar.button("Refresh Data")

# Add filter options in sidebar
st.sidebar.header("Filters")
min_anomaly_score = st.sidebar.slider("Min Anomaly Score", 0.0, 1.0, 0.0, 0.01)


# Load data
@st.cache_data
def load_data():
    try:
        df = pd.read_csv('data/result/detection_results.csv')
        return df
    except Exception as e:
        st.error(f"Error loading data: {e}")
        return None


@st.cache_data
def load_rules():
    rules = []
    if os.path.exists('rules'):
        for file in os.listdir('rules'):
            if file.endswith('.yml'):
                with open(f'rules/{file}', 'r') as f:
                    try:
                        rule = yaml.safe_load(f)
                        rules.append({
                            'file': file,
                            'title': rule.get('title', 'Unknown'),
                            'severity': rule.get('level', 'medium'),
                            'description': rule.get('description', '')
                        })
                    except:
                        pass
    return rules


@st.cache_data
def load_summary():
    try:
        with open('rules/summary.json', 'r') as f:
            return json.load(f)
    except:
        return None


df = load_data()
rules = load_rules()
summary = load_summary()

if df is None:
    st.error("No detection results found. Run anomaly_detector.py first!")
    st.stop()

# Determine which anomaly column exists
if 'ae_anomaly' in df.columns:
    anomaly_col = 'ae_anomaly'
    score_col = 'ae_score'
elif 'iso_anomaly' in df.columns:
    anomaly_col = 'iso_anomaly'
    score_col = None
else:
    st.error("No anomaly detection columns found in data!")
    st.stop()

# Apply filters
df_filtered = df[df[score_col] >= min_anomaly_score] if score_col and min_anomaly_score > 0 else df

# Main dashboard layout
st.header("📈 Real-Time Statistics")

col1, col2, col3, col4, col5 = st.columns(5)

with col1:
    st.metric(
        "Total Events",
        f"{len(df):,}",
        help="Total number of login events analyzed"
    )

with col2:
    anomaly_count = df[anomaly_col].sum()
    anomaly_pct = anomaly_count / len(df) * 100
    st.metric(
        "Anomalies Detected",
        f"{anomaly_count:,}",
        delta=f"{anomaly_pct:.1f}%",
        delta_color="inverse",
        help="Events flagged as anomalous by AI"
    )

with col3:
    st.metric(
        "Active Rules",
        len(rules),
        help="Sigma rules automatically generated from anomalies"
    )

with col4:
    if 'Is Attack IP' in df.columns:
        attack_count = df['Is Attack IP'].sum()
        attack_pct = attack_count / len(df) * 100
        st.metric(
            "Attack IPs",
            f"{attack_count:,}",
            delta=f"{attack_pct:.1f}%",
            delta_color="inverse",
            help="Known attack IPs in dataset"
        )
    else:
        st.metric("Attack IPs", "N/A")

with col5:
    if 'Is Account Takeover' in df.columns:
        takeover_count = df['Is Account Takeover'].sum()
        takeover_pct = takeover_count / len(df) * 100
        st.metric(
            "Account Takeovers",
            f"{takeover_count:,}",
            delta=f"{takeover_pct:.1f}%",
            delta_color="inverse",
            help="Confirmed account takeover events"
        )
    else:
        st.metric("Account Takeovers", "N/A")

# Detection Performance
if 'true_attack' in df.columns or 'Is Attack IP' in df.columns:
    st.header("🎯 Detection Performance")

    # Use appropriate attack column
    if 'true_attack' in df.columns:
        attack_col = 'true_attack'
    elif 'Is Attack IP' in df.columns:
        attack_col = 'Is Attack IP'
    else:
        attack_col = None

    if attack_col:
        col1, col2, col3 = st.columns(3)

        # Calculate metrics
        true_pos = ((df[anomaly_col] == True) & (df[attack_col] == True)).sum()
        false_pos = ((df[anomaly_col] == True) & (df[attack_col] == False)).sum()
        false_neg = ((df[anomaly_col] == False) & (df[attack_col] == True)).sum()
        true_neg = ((df[anomaly_col] == False) & (df[attack_col] == False)).sum()

        precision = true_pos / (true_pos + false_pos) if (true_pos + false_pos) > 0 else 0
        recall = true_pos / (true_pos + false_neg) if (true_pos + false_neg) > 0 else 0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0

        with col1:
            st.metric("Precision", f"{precision:.3f}", help="True Positives / (True Positives + False Positives)")
        with col2:
            st.metric("Recall", f"{recall:.3f}", help="True Positives / (True Positives + False Negatives)")
        with col3:
            st.metric("F1 Score", f"{f1:.3f}", help="Harmonic mean of precision and recall")

# Charts
st.header("📊 Anomaly Detection Overview")

tab1, tab2, tab3, tab4 = st.tabs(["📈 Time Analysis", "🌍 Geographic", "📱 Device Analysis", "📊 Statistics"])

with tab1:
    col1, col2 = st.columns(2)

    with col1:
        # Time series of anomalies by hour
        if 'login_hour' in df.columns:
            hourly_anomalies = df.groupby('login_hour')[anomaly_col].agg(['sum', 'count']).reset_index()
            hourly_anomalies['rate'] = hourly_anomalies['sum'] / hourly_anomalies['count'] * 100

            fig = px.bar(hourly_anomalies, x='login_hour', y='sum',
                         title='Anomalies by Hour of Day',
                         labels={'login_hour': 'Hour', 'sum': 'Anomaly Count'},
                         color='rate',
                         color_continuous_scale='Reds')
            st.plotly_chart(fig, use_container_width=True)

    with col2:
        # Anomaly score distribution
        if score_col in df.columns:
            fig = px.histogram(df, x=score_col, color=anomaly_col,
                               title='Anomaly Score Distribution',
                               labels={score_col: 'Reconstruction Error', 'count': 'Frequency'},
                               color_discrete_map={False: '#1f77b4', True: '#ff4b4b'},
                               nbins=50)
            st.plotly_chart(fig, use_container_width=True)

    # Success rate by hour
    if 'Login Successful' in df.columns:
        success_by_hour = df.groupby('login_hour')['Login Successful'].mean().reset_index()
        fig = px.line(success_by_hour, x='login_hour', y='Login Successful',
                      title='Login Success Rate by Hour',
                      labels={'login_hour': 'Hour', 'Login Successful': 'Success Rate'})
        fig.add_hline(y=success_by_hour['Login Successful'].mean(),
                      line_dash="dash",
                      annotation_text="Average")
        st.plotly_chart(fig, use_container_width=True)

with tab2:
    col1, col2 = st.columns(2)

    with col1:
        # Top countries with anomalies
        if 'Country' in df.columns:
            country_anomalies = df.groupby('Country')[anomaly_col].agg(['sum', 'count']).reset_index()
            country_anomalies['rate'] = country_anomalies['sum'] / country_anomalies['count'] * 100
            country_anomalies = country_anomalies.sort_values('sum', ascending=False).head(15)

            fig = px.bar(country_anomalies, x='Country', y='sum',
                         title='Top 15 Countries by Anomaly Count',
                         labels={'sum': 'Anomaly Count', 'Country': ''},
                         color='rate',
                         color_continuous_scale='Reds')
            st.plotly_chart(fig, use_container_width=True)

    with col2:
        # Anomaly rate by country (world map if we have coordinates, otherwise bar chart)
        if 'Country' in df.columns:
            country_rate = df.groupby('Country')[anomaly_col].mean().reset_index()
            country_rate = country_rate.sort_values(anomaly_col, ascending=False).head(20)

            fig = px.bar(country_rate, x='Country', y=anomaly_col,
                         title='Anomaly Rate by Country (%)',
                         labels={anomaly_col: 'Anomaly Rate (%)', 'Country': ''},
                         color=anomaly_col,
                         color_continuous_scale='Reds')
            st.plotly_chart(fig, use_container_width=True)

with tab3:
    col1, col2 = st.columns(2)

    with col1:
        # Device type analysis
        if 'Device Type' in df.columns:
            device_anomalies = df.groupby('Device Type')[anomaly_col].agg(['sum', 'count']).reset_index()
            device_anomalies['rate'] = device_anomalies['sum'] / device_anomalies['count'] * 100
            device_anomalies = device_anomalies.sort_values('sum', ascending=False)

            fig = px.bar(device_anomalies, x='Device Type', y='sum',
                         title='Anomalies by Device Type',
                         labels={'sum': 'Anomaly Count', 'Device Type': ''},
                         color='rate',
                         color_continuous_scale='Reds')
            st.plotly_chart(fig, use_container_width=True)

    with col2:
        # ASN analysis if available
        if 'ASN' in df.columns:
            asn_anomalies = df.groupby('ASN')[anomaly_col].agg(['sum', 'count']).reset_index()
            asn_anomalies['rate'] = asn_anomalies['sum'] / asn_anomalies['count'] * 100
            asn_anomalies = asn_anomalies[asn_anomalies['count'] > 100].sort_values('rate', ascending=False).head(15)

            fig = px.bar(asn_anomalies, x='ASN', y='rate',
                         title='Top 15 ASNs by Anomaly Rate',
                         labels={'rate': 'Anomaly Rate (%)', 'ASN': ''},
                         color='rate',
                         color_continuous_scale='Reds')
            st.plotly_chart(fig, use_container_width=True)

    # RTT Analysis if available
    if 'Round-Trip Time [ms]' in df.columns:
        fig = px.box(df, x=anomaly_col, y='Round-Trip Time [ms]',
                     title='Round-Trip Time Distribution: Normal vs Anomaly',
                     labels={anomaly_col: 'Classification', 'Round-Trip Time [ms]': 'RTT (ms)'},
                     color=anomaly_col,
                     color_discrete_map={False: '#1f77b4', True: '#ff4b4b'})
        st.plotly_chart(fig, use_container_width=True)

with tab4:
    col1, col2 = st.columns(2)

    with col1:
        # Summary statistics
        st.subheader("📊 Summary Statistics")
        stats_data = {
            'Metric': ['Total Events', 'Anomalies', 'Anomaly Rate', 'Unique IPs', 'Unique Users', 'Unique Countries'],
            'Value': [
                f"{len(df):,}",
                f"{df[anomaly_col].sum():,}",
                f"{df[anomaly_col].mean() * 100:.2f}%",
                f"{df['IP Address'].nunique():,}" if 'IP Address' in df.columns else 'N/A',
                f"{df['User ID'].nunique():,}" if 'User ID' in df.columns else 'N/A',
                f"{df['Country'].nunique()}" if 'Country' in df.columns else 'N/A'
            ]
        }
        stats_df = pd.DataFrame(stats_data)
        st.table(stats_df)

    with col2:
        # Confusion Matrix if attack labels exist
        if attack_col in df.columns:
            st.subheader("📊 Confusion Matrix")

            # Create confusion matrix
            cm = pd.crosstab(
                df[attack_col].map({0: 'Normal', 1: 'Attack'}),
                df[anomaly_col].map({False: 'Predicted Normal', True: 'Predicted Anomaly'}),
                margins=True
            )
            st.dataframe(cm)

# Generated Rules Section
st.header("📝 Automatically Generated Sigma Rules")

if rules:
    # Add severity filter
    severity_filter = st.multiselect(
        "Filter by severity",
        options=['low', 'medium', 'high', 'critical'],
        default=['low', 'medium', 'high', 'critical']
    )

    filtered_rules = [r for r in rules if r['severity'] in severity_filter]

    for rule in filtered_rules:
        with st.expander(f"📄 {rule['title']}"):
            col1, col2 = st.columns([1, 4])
            with col1:
                severity_color = {
                    'low': '🟢',
                    'medium': '🟡',
                    'high': '🟠',
                    'critical': '🔴'
                }.get(rule['severity'], '⚪')
                st.markdown(f"**Severity:** {severity_color} {rule['severity'].upper()}")
                st.markdown(f"**File:** `{rule['file']}`")
                # Add download button for each rule
                with open(f"rules/{rule['file']}", 'r') as f:
                    rule_content = f.read()
                st.download_button(
                    label="📥 Download Rule",
                    data=rule_content,
                    file_name=rule['file'],
                    mime="text/yaml"
                )
            with col2:
                st.markdown(f"**Description:** {rule['description']}")
else:
    st.info("No rules generated yet. Run rule_generator.py to create rules.")

# Raw data explorer
st.header("🔍 Raw Data Explorer")

# Column selector for raw data
available_cols = ['Login Timestamp', 'User ID', 'IP Address', 'Country', 'Device Type',
                  'Login Successful', 'login_hour', anomaly_col]
available_cols = [col for col in available_cols if col in df.columns]

selected_cols = st.multiselect(
    "Select columns to display",
    options=available_cols,
    default=available_cols[:6]  # First 6 columns
)

if selected_cols:
    # Add search/filter
    search_term = st.text_input("🔍 Search (e.g., IP address, country)", "")

    display_df = df[selected_cols].copy()

    if search_term:
        # Simple search across all selected columns
        mask = pd.Series([False] * len(display_df))
        for col in display_df.columns:
            if display_df[col].dtype == 'object':
                mask |= display_df[col].astype(str).str.contains(search_term, case=False, na=False)
        display_df = display_df[mask]

    st.dataframe(display_df.head(500), use_container_width=True)  # Limit to 500 rows for performance
    st.caption(f"Showing {min(500, len(display_df))} of {len(display_df)} rows")

# Footer with system info
st.markdown("---")
col1, col2, col3 = st.columns(3)
with col1:
    st.markdown(f"**Last Updated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
with col2:
    if summary:
        st.markdown(f"**Rules Generated:** {summary.get('rules_generated', 'N/A')}")
with col3:
    st.markdown("**Status:** 🟢 Active")

st.markdown("---")
st.markdown(
    "**Self-Evolving SIEM Rule Engine** | Built with AutoEncoder + Isolation Forest | Generates Sigma Rules automatically")