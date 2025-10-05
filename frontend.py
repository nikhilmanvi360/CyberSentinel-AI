import streamlit as st
import requests
import json
import pandas as pd
import plotly.express as px
from datetime import datetime
import pyttsx3
import threading
import time

# Configure the page with wide layout and custom logo
st.set_page_config(
    page_title="CyberSentinel AI",
    page_icon="🛡️",
    layout="wide"
)

# Initialize text-to-speech engine
def init_tts_engine():
    """
    Initialize the text-to-speech engine with appropriate settings.
    Returns a configured pyttsx3 engine instance.
    """
    engine = pyttsx3.init()
    engine.setProperty('rate', 150)    # Speed of speech
    engine.setProperty('volume', 1.0)  # Volume
    return engine

def speak_async(text):
    """
    Speak the given text asynchronously using pyttsx3.
    """
    if st.session_state.get('voice_alerts', False):
        def speak_text():
            engine = init_tts_engine()
            engine.say(text)
            engine.runAndWait()
        thread = threading.Thread(target=speak_text)
        thread.start()

# Backend API URL
BACKEND_URL = "http://localhost:8000"

# Backend API functions
def check_backend_health():
    try:
        response = requests.get(f"{BACKEND_URL}/ping")
        return response.status_code == 200
    except:
        return False

def detect_phishing(message: str) -> dict:
    response = requests.post(
        f"{BACKEND_URL}/detect_phishing",
        json={"text": message}
    )
    return response.json()

def detect_anomaly(login_counts: list) -> dict:
    response = requests.post(
        f"{BACKEND_URL}/detect_anomaly",
        json={"logins": login_counts}
    )
    return response.json()

def get_security_alerts() -> dict:
    response = requests.get(f"{BACKEND_URL}/alerts")
    return response.json()

def get_stats() -> dict:
    response = requests.get(f"{BACKEND_URL}/stats")
    return response.json()

def generate_security_report() -> dict:
    response = requests.get(f"{BACKEND_URL}/generate_report")
    return response.json()

# Add custom CSS for better styling
st.markdown("""
    <style>
    .main {
        padding: 2rem;
    }
    .stAlert {
        padding: 1rem;
        margin: 1rem 0;
        border-radius: 0.5rem;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }
    .explanation-box {
        padding: 1.5rem;
        background-color: #f0f2f6;
        border-radius: 0.5rem;
        margin: 1rem 0;
        border-left: 4px solid #1e3c72;
    }
    .banner {
        padding: 3rem 2rem;
        background: linear-gradient(135deg, #1e3c72 0%, #2a5298 100%);
        color: white;
        border-radius: 1rem;
        text-align: center;
        margin-bottom: 2rem;
        box-shadow: 0 4px 6px rgba(0,0,0,0.1);
    }
    .feature-button {
        padding: 1.5rem;
        background-color: #f8f9fa;
        border-radius: 0.75rem;
        text-align: center;
        margin: 0.75rem;
        cursor: pointer;
        transition: all 0.3s ease;
        border: 1px solid #e9ecef;
        box-shadow: 0 2px 4px rgba(0,0,0,0.05);
    }
    .feature-button:hover {
        transform: translateY(-2px);
        box-shadow: 0 4px 8px rgba(0,0,0,0.1);
        background-color: #ffffff;
    }
    .stButton>button {
        width: 100%;
        border-radius: 0.5rem;
        padding: 0.5rem 1rem;
        background-color: #1e3c72;
        color: white;
        border: none;
        transition: all 0.3s ease;
    }
    .stButton>button:hover {
        background-color: #2a5298;
        transform: translateY(-1px);
    }
    </style>
""", unsafe_allow_html=True)

# Initialize session state for voice alerts
if 'voice_alerts' not in st.session_state:
    st.session_state.voice_alerts = False

# Voice alerts toggle in sidebar
with st.sidebar:
    st.header("🔊 Voice Alert Settings")
    voice_enabled = st.checkbox("Enable Voice Alerts", value=st.session_state.voice_alerts)
    st.session_state.voice_alerts = voice_enabled
    if voice_enabled:
        st.success("Voice alerts are enabled")
        st.info("The system will speak alerts when threats are detected")
    else:
        st.info("Voice alerts are disabled")

# Check backend health
if not check_backend_health():
    st.error("⚠️ Backend server is not running. Please start the backend server first.")
    st.stop()

# Create tabs for different features
tab0, tab1, tab2, tab3, tab4, tab5, tab6 = st.tabs([
    "🏠 Home",
    "📊 Dashboard",
    "🔍 Threat Detection",
    "📈 Threat Monitor",
    "🤖 Auto-Response",
    "🧱 Alerts Ledger",
    "ℹ️ About"
])

# Home/Intro Tab
with tab0:
    # Project banner with logo
    st.markdown("""
        <div class="banner">
            <h1>🛡️ CyberSentinel AI</h1>
            <h2>Smart Cyber Defense</h2>
            <p>Protecting India's digital future with AI.</p>
        </div>
    """, unsafe_allow_html=True)
    
    # Feature navigation buttons
    st.markdown("### 🚀 Quick Access to Features")
    col1, col2, col3 = st.columns(3)
    
    with col1:
        st.markdown("""
            <div class="feature-button">
                <h3>🔍 Threat Detection</h3>
                <p>AI-powered phishing detection with detailed analysis</p>
            </div>
        """, unsafe_allow_html=True)
    
    with col2:
        st.markdown("""
            <div class="feature-button">
                <h3>📊 Live Dashboard</h3>
                <p>Real-time security metrics and threat monitoring</p>
            </div>
        """, unsafe_allow_html=True)
    
    with col3:
        st.markdown("""
            <div class="feature-button">
                <h3>🤖 Auto-Response</h3>
                <p>Automated threat response and mitigation</p>
            </div>
        """, unsafe_allow_html=True)
    
    # Project highlights
    st.markdown("### 🌟 Key Highlights")
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
            - 🧠 **Advanced AI Models**
              - Real-time phishing detection
              - Anomaly detection in login patterns
              - Automated threat response system
            
            - 🔒 **Enterprise-Grade Security**
              - Blockchain-based audit trail
              - Tamper-proof security logs
              - Voice alert system
        """)
    
    with col2:
        st.markdown("""
            - 📊 **Comprehensive Dashboard**
              - Real-time threat metrics
              - Interactive visualizations
              - Downloadable security reports
            
            - 🚀 **Easy Integration**
              - RESTful API backend
              - Modern web interface
              - Scalable architecture
        """)

# AI Threat Dashboard Tab
with tab1:
    st.header("📊 AI Threat Dashboard")
    st.markdown("""
        Real-time overview of security events and threat metrics.
        This dashboard provides insights into detected threats and system activity.
    """)
    
    # Add refresh and report generation buttons
    col1, col2 = st.columns([1, 3])
    with col1:
        if st.button("🔄 Refresh Dashboard"):
            st.experimental_rerun()
    with col2:
        if st.button("📄 Generate Security Report"):
            with st.spinner("Generating security report..."):
                report = generate_security_report()
                
                # Display the report
                st.markdown("### 📋 Security Report")
                st.code(report["content"], language="text")
                
                # Download button for the report
                st.download_button(
                    "📥 Download Report",
                    report["content"],
                    "security_report.txt",
                    "text/plain",
                    key='download-report'
                )
    
    # Fetch latest stats and alerts
    with st.spinner("Loading dashboard data..."):
        stats = get_stats()
        alerts = get_security_alerts()
        
        # Display metrics with colored badges
        col1, col2, col3 = st.columns(3)
        with col1:
            st.markdown(f"""
                <div style='padding: 1rem; background-color: rgba(255, 0, 0, 0.1); border-radius: 0.5rem; text-align: center;'>
                    <h3 style='color: #ff0000;'>🚨 Phishing Detections</h3>
                    <h2 style='color: #ff0000;'>{stats['phishing_count']}</h2>
                </div>
            """, unsafe_allow_html=True)
        
        with col2:
            st.markdown(f"""
                <div style='padding: 1rem; background-color: rgba(255, 165, 0, 0.1); border-radius: 0.5rem; text-align: center;'>
                    <h3 style='color: #ffa500;'>⚠️ Suspicious Activities</h3>
                    <h2 style='color: #ffa500;'>{stats['suspicious_count']}</h2>
                </div>
            """, unsafe_allow_html=True)
        
        with col3:
            st.markdown(f"""
                <div style='padding: 1rem; background-color: rgba(0, 0, 255, 0.1); border-radius: 0.5rem; text-align: center;'>
                    <h3 style='color: #0000ff;'>🛡️ Total Alerts</h3>
                    <h2 style='color: #0000ff;'>{stats['total_alerts']}</h2>
                </div>
            """, unsafe_allow_html=True)
        
        # Create timeline chart
        st.markdown("### 📈 Threat Detection Timeline")
        if stats['timeline']:
            df = pd.DataFrame(stats['timeline'])
            df['time'] = pd.to_datetime(df['time'])
            df['count'] = 1
            
            timeline_df = df.groupby(['time', 'type']).count().reset_index()
            
            fig = px.line(timeline_df, x='time', y='count', color='type',
                         title='Security Events Over Time',
                         labels={'count': 'Number of Events', 'time': 'Time'},
                         markers=True)
            st.plotly_chart(fig)
        else:
            st.info("No events recorded in the timeline yet.")
        
        # Recent Alerts Table
        st.markdown("### 🔔 Recent Alerts")
        if alerts['alerts']:
            recent_alerts = alerts['alerts'][:5]
            alert_df = pd.DataFrame([{
                'Time': alert['timestamp'],
                'Type': alert['event_type'],
                'Details': alert['data'].get('reason', str(alert['data']))[:100] + '...' if len(str(alert['data'])) > 100 else str(alert['data'])
            } for alert in recent_alerts])
            st.dataframe(alert_df, use_container_width=True)
        else:
            st.info("No recent alerts to display.")

# Phishing Detection Tab
with tab2:
    st.header("🔍 Phishing Detection")
    st.markdown("""
        Enter a message to check if it's a potential phishing attempt.
        Our AI model will analyze the text and provide a detailed explanation.
    """)
    
    message = st.text_area("Enter the message to analyze:", height=100)
    
    if st.button("🔍 Analyze Message"):
        if message:
            with st.spinner("Analyzing message..."):
                result = detect_phishing(message)
                
                # Display the result with appropriate styling
                if result["prediction"] == "Phishing":
                    st.error(f"🚨 **Phishing Detected!** (Confidence: {result['confidence']}%)")
                    # Trigger voice alert
                    speak_async("Warning! Phishing attempt detected!")
                else:
                    st.success(f"✅ **Safe Message** (Confidence: {result['confidence']}%)")
                
                # Show detailed probabilities
                st.markdown("### 📊 Detailed Analysis")
                col1, col2 = st.columns(2)
                with col1:
                    st.metric("Phishing Probability", f"{result['details']['phishing_probability']}%")
                with col2:
                    st.metric("Safe Probability", f"{result['details']['safe_probability']}%")
                
                # Display AI Explanation
                st.markdown("### 🤖 AI Explanation")
                st.markdown(f"""
                    <div class="explanation-box">
                        {result.get('reason', 'No detailed explanation available.')}
                    </div>
                """, unsafe_allow_html=True)
        else:
            st.warning("Please enter a message to analyze.")

# AI Threat Monitor Tab
with tab3:
    st.header("📈 AI Threat Monitor")
    st.markdown("""
        Monitor login patterns for suspicious activity.
        Enter comma-separated numbers representing login counts over time periods.
        Example: 10,12,8,45,9,11 (sudden spike to 45 might be suspicious)
    """)
    
    login_input = st.text_input("Enter login counts (comma-separated):", "10,12,8,15,9,11")
    
    if st.button("📊 Analyze Pattern"):
        try:
            # Convert input to list of integers
            login_counts = [int(x.strip()) for x in login_input.split(",")]
            
            with st.spinner("Analyzing login pattern..."):
                result = detect_anomaly(login_counts)
                
                # Display the result
                if result["status"] == "Suspicious":
                    st.error(f"🚨 **Suspicious Activity Detected!** (Confidence: {result['confidence']}%)")
                    # Trigger voice alert
                    speak_async("Warning! Suspicious login activity detected!")
                else:
                    st.success(f"✅ **Normal Activity Pattern** (Confidence: {result['confidence']}%)")
                
                # Display AI Explanation
                st.markdown("### 🤖 AI Explanation")
                st.markdown(f"""
                    <div class="explanation-box">
                        {result.get('reason', 'No detailed explanation available.')}
                    </div>
                """, unsafe_allow_html=True)
                
                # Create a line chart of the login pattern
                df = pd.DataFrame({
                    'Time Period': range(1, len(login_counts) + 1),
                    'Login Count': login_counts
                })
                
                fig = px.line(df, x='Time Period', y='Login Count',
                            title='Login Activity Pattern',
                            markers=True)
                st.plotly_chart(fig)
                
                # Show anomaly score details
                st.markdown("### 📊 Technical Details")
                st.json(result["details"])
                
        except ValueError:
            st.error("Please enter valid numbers separated by commas.")

# AI Threat Response Tab
with tab4:
    st.header("🤖 AI Threat Response")
    st.markdown("""
        Automatically respond to detected threats with predefined security actions.
        The system can block users or monitor devices based on the type of threat.
    """)
    
    # Create the form for auto-response
    with st.form("auto_response_form"):
        # Input for source/user ID
        source = st.text_input(
            "Source/User ID",
            placeholder="e.g., user@example.com or device123",
            help="Enter the identifier of the user or device to take action on"
        )
        
        # Dropdown for threat type
        threat_type = st.selectbox(
            "Threat Type",
            options=["Phishing", "Suspicious"],
            help="Select the type of threat detected"
        )
        
        # Submit button
        submitted = st.form_submit_button("Run Auto-Response")
        
        if submitted and source:
            try:
                # Send request to auto-response endpoint
                response = requests.post(
                    f"{BACKEND_URL}/auto_response",
                    json={"type": threat_type, "source": source}
                )
                
                if response.status_code == 200:
                    result = response.json()
                    
                    # Display the action with appropriate color
                    if result["severity"] == "Critical":
                        st.error(f"🚫 Action Taken: {result['action']}")
                        # Trigger voice alert for blocking actions
                        if st.session_state.voice_alerts:
                            speak_async(f"Critical alert! {result['action']} for {source}")
                    else:
                        st.warning(f"⚠️ Action Taken: {result['action']}")
                    
                    # Show additional details
                    st.info(f"""
                        **Details:**
                        - Source: {result['source']}
                        - Severity: {result['severity']}
                        - Timestamp: {datetime.fromtimestamp(result['timestamp']).strftime('%Y-%m-%d %H:%M:%S')}
                    """)
                else:
                    st.error("Failed to execute auto-response. Please try again.")
            except Exception as e:
                st.error(f"Error: {str(e)}")
        elif submitted:
            st.warning("Please enter a Source/User ID")

# Security Alerts Ledger Tab
with tab5:
    st.header("🧱 Security Alerts Ledger")
    st.markdown("""
        Blockchain-based ledger of all security events.
        Each alert is cryptographically linked to ensure tamper-proof logging.
    """)
    
    # Add refresh button
    if st.button("🔄 Refresh Alerts", key="refresh_alerts"):
        st.experimental_rerun()
    
    # Fetch and display alerts
    with st.spinner("Loading security alerts..."):
        result = get_security_alerts()
        
        # Display chain validation status
        if result["chain_valid"]:
            st.success("✅ Blockchain integrity verified")
        else:
            st.error("❌ Blockchain integrity compromised!")
        
        # Display alerts in a table
        if result["alerts"]:
            alerts_df = pd.DataFrame([{
                'Time': alert['timestamp'],
                'Type': alert['event_type'],
                'Confidence': f"{alert['data'].get('confidence', 'N/A')}%",
                'Explanation': alert['data'].get('reason', 'No explanation available'),
                'Details': str(alert['data'])
            } for alert in result["alerts"]])
            
            st.dataframe(alerts_df, use_container_width=True)
            
            # Download button for alerts
            csv = alerts_df.to_csv(index=False)
            st.download_button(
                "📥 Download Alerts CSV",
                csv,
                "security_alerts.csv",
                "text/csv",
                key='download-csv'
            )
        else:
            st.info("No security alerts recorded yet.")

# About Tab
with tab6:
    st.header("ℹ️ About CyberSentinel AI")
    st.markdown("""
        ### 🛡️ Overview
        CyberSentinel AI is an advanced cybersecurity system that uses artificial intelligence
        to protect against various cyber threats. The system combines multiple AI models to
        detect phishing attempts and suspicious activities in real-time.
        
        ### 🔍 Key Features
        1. **AI-Powered Phishing Detection**
           - Analyzes messages for phishing indicators
           - Provides detailed explanations for detections
           - Uses machine learning for accurate classification
        
        2. **Anomaly Detection**
           - Monitors login patterns for suspicious activity
           - Detects unusual behavior in real-time
           - Explains why activities are flagged
        
        3. **Blockchain Security Ledger**
           - Tamper-proof logging of security events
           - Cryptographic verification of alert history
           - Downloadable security audit trails
        
        4. **Voice Alerts**
           - Optional voice notifications for threats
           - Immediate audio warnings for critical events
           - Configurable alert settings
        
        5. **Automated Response**
           - Rule-based threat response
           - User blocking for critical threats
           - Device monitoring for suspicious activity
        
        ### 🔒 Security Features
        - Real-time threat detection and alerting
        - Detailed AI explanations for all detections
        - Blockchain-based immutable audit trail
        - Voice alerts for immediate notification
        - Comprehensive security dashboard
        - Automated threat response system
        - Downloadable security reports
        
        ### 👥 Created By
        Developed as a hackathon project to demonstrate the power of AI in cybersecurity.
        Protecting India's digital future with advanced threat detection and response.
    """)

# Run the application with: streamlit run frontend.py