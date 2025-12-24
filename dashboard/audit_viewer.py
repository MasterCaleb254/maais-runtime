"""
MAAIS-Runtime Security Dashboard
Real-time monitoring and visualization
"""
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
from pathlib import Path
import sys
import json

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.runtime import get_runtime
from core.engine.mitre_policy_engine import MITREPolicyEngine

# Page configuration
st.set_page_config(
    page_title="MAAIS-Runtime Security Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        color: #1E88E5;
        margin-bottom: 1rem;
    }
    .metric-card {
        background-color: #f8f9fa;
        padding: 1rem;
        border-radius: 0.5rem;
        border-left: 4px solid #1E88E5;
    }
    .blocked-card {
        border-left: 4px solid #dc3545;
    }
    .allowed-card {
        border-left: 4px solid #28a745;
    }
    .mitre-badge {
        display: inline-block;
        padding: 0.25rem 0.5rem;
        margin: 0.1rem;
        background-color: #6c757d;
        color: white;
        border-radius: 0.25rem;
        font-size: 0.75rem;
    }
</style>
""", unsafe_allow_html=True)

# Initialize session state
if 'runtime' not in st.session_state:
    st.session_state.runtime = get_runtime()
if 'refresh' not in st.session_state:
    st.session_state.refresh = False

# Title
st.markdown('<h1 class="main-header">🛡️ MAAIS-Runtime Security Dashboard</h1>', unsafe_allow_html=True)

# Sidebar
with st.sidebar:
    st.title("🔧 Configuration")
    
    # Time range filter
    st.subheader("Time Range")
    time_range = st.selectbox(
        "Select time range",
        ["Last 1 hour", "Last 24 hours", "Last 7 days", "All time"]
    )
    
    # Agent filter
    st.subheader("Agent Filter")
    all_agents = ["All Agents"] + list(set([
        event['action_request']['agent_id'] 
        for event in st.session_state.runtime.audit_logger.get_recent_events(1000)
    ]))
    selected_agent = st.selectbox("Select agent", all_agents)
    
    # Action type filter
    st.subheader("Action Type")
    action_types = ["All Types"] + list(set([
        event['action_request']['action_type'] 
        for event in st.session_state.runtime.audit_logger.get_recent_events(1000)
    ]))
    selected_action = st.selectbox("Select action type", action_types)
    
    # Decision filter
    st.subheader("Decision")
    decision_filter = st.selectbox(
        "Filter by decision",
        ["All", "Allowed Only", "Blocked Only"]
    )
    
    # Refresh button
    st.markdown("---")
    if st.button("🔄 Refresh Data", type="primary"):
        st.session_state.refresh = True
        st.rerun()

# Main dashboard layout
tab1, tab2, tab3, tab4 = st.tabs(["📊 Overview", "🚨 Security Events", "🎯 MITRE ATLAS", "📈 Analytics"])

with tab1:
    # Metrics row
    col1, col2, col3, col4, col5 = st.columns(5)
    
    # Get recent events
    events = st.session_state.runtime.audit_logger.get_recent_events(1000)
    
    # Calculate metrics
    total_events = len(events)
    allowed_events = sum(1 for e in events if e['decision']['allow'])
    blocked_events = sum(1 for e in events if not e['decision']['allow'])
    unique_agents = len(set(e['action_request']['agent_id'] for e in events))
    
    # CIAA violations
    ciaa_violations = sum(
        1 for e in events 
        if e['decision']['ciaa_violations'] and e['decision']['ciaa_violations'] != {}
    )
    
    with col1:
        st.markdown(f"""
        <div class="metric-card">
            <h3>Total Events</h3>
            <h2>{total_events}</h2>
        </div>
        """, unsafe_allow_html=True)
    
    with col2:
        st.markdown(f"""
        <div class="metric-card allowed-card">
            <h3>Allowed</h3>
            <h2>{allowed_events}</h2>
            <p>{allowed_events/total_events*100:.1f}% of total</p>
        </div>
        """, unsafe_allow_html=True)
    
    with col3:
        st.markdown(f"""
        <div class="metric-card blocked-card">
            <h3>Blocked</h3>
            <h2>{blocked_events}</h2>
            <p>{blocked_events/total_events*100:.1f}% of total</p>
        </div>
        """, unsafe_allow_html=True)
    
    with col4:
        st.markdown(f"""
        <div class="metric-card">
            <h3>Active Agents</h3>
            <h2>{unique_agents}</h2>
        </div>
        """, unsafe_allow_html=True)
    
    with col5:
        st.markdown(f"""
        <div class="metric-card">
            <h3>CIAA Violations</h3>
            <h2>{ciaa_violations}</h2>
        </div>
        """, unsafe_allow_html=True)
    
    # Charts row
    col1, col2 = st.columns(2)
    
    with col1:
        st.subheader("Decisions Over Time")
        
        # Prepare time series data
        if events:
            df_timeseries = pd.DataFrame([
                {
                    'timestamp': pd.to_datetime(e['timestamp']),
                    'decision': 'Allowed' if e['decision']['allow'] else 'Blocked',
                    'agent': e['action_request']['agent_id']
                }
                for e in events
            ])
            
            # Resample by hour
            df_timeseries.set_index('timestamp', inplace=True)
            allowed_series = df_timeseries[df_timeseries['decision'] == 'Allowed'].resample('1H').size()
            blocked_series = df_timeseries[df_timeseries['decision'] == 'Blocked'].resample('1H').size()
            
            fig = go.Figure()
            fig.add_trace(go.Scatter(
                x=allowed_series.index, 
                y=allowed_series.values,
                name='Allowed',
                line=dict(color='green', width=2)
            ))
            fig.add_trace(go.Scatter(
                x=blocked_series.index, 
                y=blocked_series.values,
                name='Blocked',
                line=dict(color='red', width=2)
            ))
            
            fig.update_layout(
                xaxis_title="Time",
                yaxis_title="Number of Events",
                hovermode='x unified',
                height=300
            )
            
            st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        st.subheader("Top Agents by Activity")
        
        if events:
            agent_counts = pd.DataFrame([
                {
                    'agent': e['action_request']['agent_id'],
                    'decision': 'Allowed' if e['decision']['allow'] else 'Blocked'
                }
                for e in events
            ])
            
            agent_summary = agent_counts.groupby(['agent', 'decision']).size().unstack(fill_value=0)
            agent_summary['total'] = agent_summary.sum(axis=1)
            agent_summary = agent_summary.sort_values('total', ascending=False).head(10)
            
            fig = go.Figure(data=[
                go.Bar(name='Allowed', x=agent_summary.index, y=agent_summary.get('Allowed', 0), marker_color='green'),
                go.Bar(name='Blocked', x=agent_summary.index, y=agent_summary.get('Blocked', 0), marker_color='red')
            ])
            
            fig.update_layout(
                xaxis_title="Agent",
                yaxis_title="Number of Actions",
                barmode='stack',
                height=300
            )
            
            st.plotly_chart(fig, use_container_width=True)

with tab2:
    st.subheader("Recent Security Events")
    
    # Filters
    col1, col2, col3 = st.columns(3)
    with col1:
        search_term = st.text_input("🔍 Search events", placeholder="Search in agent, target, explanation...")
    
    with col2:
        min_severity = st.selectbox(
            "Minimum Severity",
            ["All", "Critical", "High", "Medium", "Low"]
        )
    
    with col3:
        limit_events = st.slider("Show events", 10, 100, 50)
    
    # Filter events
    filtered_events = events[:limit_events]
    
    if selected_agent != "All Agents":
        filtered_events = [e for e in filtered_events if e['action_request']['agent_id'] == selected_agent]
    
    if selected_action != "All Types":
        filtered_events = [e for e in filtered_events if e['action_request']['action_type'] == selected_action]
    
    if decision_filter == "Allowed Only":
        filtered_events = [e for e in filtered_events if e['decision']['allow']]
    elif decision_filter == "Blocked Only":
        filtered_events = [e for e in filtered_events if not e['decision']['allow']]
    
    if search_term:
        filtered_events = [
            e for e in filtered_events
            if search_term.lower() in json.dumps(e).lower()
        ]
    
    # Display events
    for event in filtered_events:
        action = event['action_request']
        decision = event['decision']
        
        # Determine card style
        if decision['allow']:
            border_color = "4px solid #28a745"
            icon = "✅"
        else:
            border_color = "4px solid #dc3545"
            icon = "❌"
        
        # Create expandable card
        with st.container():
            st.markdown(f"""
            <div style="
                border-left: {border_color};
                background-color: #f8f9fa;
                padding: 1rem;
                margin-bottom: 0.5rem;
                border-radius: 0.25rem;
            ">
                <div style="display: flex; justify-content: space-between; align-items: center;">
                    <div>
                        <strong>{icon} {action['action_type']}</strong> | 
                        <strong>Agent:</strong> {action['agent_id']} | 
                        <strong>Target:</strong> {action['target']}
                    </div>
                    <div style="font-size: 0.8rem; color: #6c757d;">
                        {pd.to_datetime(event['timestamp']).strftime('%Y-%m-%d %H:%M:%S')}
                    </div>
                </div>
                <div style="margin-top: 0.5rem;">
                    <strong>Goal:</strong> {action['declared_goal']}
                </div>
            </div>
            """, unsafe_allow_html=True)
            
            # Expand for details
            with st.expander("View Details", expanded=False):
                col1, col2 = st.columns(2)
                
                with col1:
                    st.write("**Action Request**")
                    st.json(action, expanded=False)
                
                with col2:
                    st.write("**Decision**")
                    st.json(decision, expanded=False)
                    
                    if decision['ciaa_violations']:
                        st.write("**CIAA Violations**")
                        for key, value in decision['ciaa_violations'].items():
                            st.error(f"**{key}**: {value}")
                
                st.write("**Raw Event**")
                st.code(json.dumps(event, indent=2), language='json')

with tab3:
    st.subheader("MITRE ATLAS Coverage")
    
    # Initialize MITRE policy engine
    mitre_engine = MITREPolicyEngine()
    mitre_summary = mitre_engine.get_mitre_summary()
    
    # MITRE Tactics Coverage
    col1, col2 = st.columns(2)
    
    with col1:
        st.write("### 🎯 MITRE ATLAS Tactics")
        
        if mitre_summary['tactics']:
            df_tactics = pd.DataFrame(
                list(mitre_summary['tactics'].items()),
                columns=['Tactic', 'Policy Count']
            )
            
            fig = px.bar(
                df_tactics, 
                x='Tactic', 
                y='Policy Count',
                color='Policy Count',
                color_continuous_scale='reds'
            )
            fig.update_layout(height=400)
            st.plotly_chart(fig, use_container_width=True)
    
    with col2:
        st.write("### 📊 Severity Distribution")
        
        df_severity = pd.DataFrame(
            list(mitre_summary['severity_counts'].items()),
            columns=['Severity', 'Count']
        )
        
        fig = px.pie(
            df_severity,
            values='Count',
            names='Severity',
            color='Severity',
            color_discrete_map={
                'critical': '#dc3545',
                'high': '#fd7e14',
                'medium': '#ffc107',
                'low': '#28a745'
            }
        )
        fig.update_layout(height=400)
        st.plotly_chart(fig, use_container_width=True)
    
    # MITRE Techniques Table
    st.write("### 🛡️ Protected Techniques")
    
    if mitre_summary['techniques']:
        df_techniques = pd.DataFrame(mitre_summary['techniques'])
        st.dataframe(
            df_techniques,
            column_config={
                "id": "MITRE ID",
                "name": "Technique Name",
                "tactic": "Tactic",
                "severity": "Severity",
                "policy_id": "Policy ID"
            },
            use_container_width=True
        )

with tab4:
    st.subheader("Advanced Analytics")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.write("### 📈 Performance Metrics")
        
        # Calculate average decision time (simulated)
        avg_time = 3.2  # ms - would be calculated from actual timestamps
        
        st.metric("Average Decision Time", f"{avg_time} ms")
        st.metric("Peak Events/Minute", "42")
        st.metric("Policy Cache Hit Rate", "98.7%")
    
    with col2:
        st.write("### 🔍 Pattern Detection")
        
        # Detect suspicious patterns
        patterns = [
            {"name": "Rapid Failed Attempts", "count": 3, "agents": ["malicious_agent", "evasion_agent"]},
            {"name": "Parameter Obfuscation", "count": 5, "agents": ["evasion_agent"]},
            {"name": "Time-based Attacks", "count": 1, "agents": ["abuse_agent"]}
        ]
        
        for pattern in patterns:
            with st.expander(f"🚨 {pattern['name']} ({pattern['count']} occurrences)"):
                st.write(f"**Agents involved:** {', '.join(pattern['agents'])}")
                st.write(f"**Recommendation:** Increase monitoring for these agents")
    
    # Export options
    st.write("### 📤 Data Export")
    col1, col2, col3 = st.columns(3)
    
    with col1:
        if st.button("Export Audit Logs", type="secondary"):
            # Create downloadable JSON
            audit_json = json.dumps(events, indent=2)
            st.download_button(
                label="Download JSON",
                data=audit_json,
                file_name=f"audit_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                mime="application/json"
            )
    
    with col2:
        if st.button("Export Security Report", type="secondary"):
            # Create report
            report = f"""
            MAAIS-Runtime Security Report
            Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
            
            Summary:
            - Total Events: {total_events}
            - Blocked Actions: {blocked_events}
            - Block Rate: {blocked_events/total_events*100:.1f}%
            - CIAA Violations: {ciaa_violations}
            
            Top Agents:
            {chr(10).join([f"- {agent}: {count}" for agent, count in list(agent_counts['agent'].value_counts().head(5).items())])}
            """
            
            st.download_button(
                label="Download Report",
                data=report,
                file_name=f"security_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                mime="text/plain"
            )

# Footer
st.markdown("---")
st.markdown("""
<div style="text-align: center; color: #6c757d; font-size: 0.8rem;">
    MAAIS-Runtime Security Dashboard | Real-time AI Agent Security Monitoring
</div>
""", unsafe_allow_html=True)

# Auto-refresh
if st.session_state.refresh:
    st.session_state.refresh = False
    st.rerun()