# Import required libraries
# FastAPI - A modern web framework for building APIs
from fastapi import FastAPI, Body
# CORS middleware to allow frontend to communicate with backend
from fastapi.middleware.cors import CORSMiddleware
# Pydantic for data validation
from pydantic import BaseModel
# NumPy for numerical operations
import numpy as np
# Scikit-learn for machine learning models
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import IsolationForest
# Python standard libraries
from typing import Dict, List
import hashlib
import time
import json

# Create a FastAPI application instance with a title
app = FastAPI(title="CyberSentinel AI Backend")

# Configure Cross-Origin Resource Sharing (CORS)
# This allows the frontend (running on a different port) to communicate with the backend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # In production, specify exact origins for security
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

class SimpleBlockchain:
    """
    A simple blockchain implementation for logging security alerts.
    This ensures that security events are stored in a tamper-proof way.
    
    How it works:
    1. Each block contains security event data and is linked to the previous block
    2. Blocks are linked using cryptographic hashes
    3. Any attempt to modify a block will break the chain
    
    Block structure:
    - timestamp: when the alert was created
    - event_type: type of security alert (Phishing or Suspicious)
    - data: additional details about the alert
    - previous_hash: hash of the previous block
    - hash: hash of the current block
    """
    def __init__(self):
        """Initialize the blockchain with a genesis (first) block"""
        self.chain = []
        self.create_genesis_block()
    
    def create_genesis_block(self):
        """
        Create the first block (genesis block) in the chain.
        This is a special block that starts the chain.
        """
        genesis_block = {
            'timestamp': time.time(),
            'event_type': 'Genesis',
            'data': 'Genesis Block',
            'previous_hash': '0' * 64,  # 64 zeros for the genesis block
        }
        genesis_block['hash'] = self.calculate_hash(genesis_block)
        self.chain.append(genesis_block)
    
    def calculate_hash(self, block: Dict) -> str:
        """
        Calculate SHA-256 hash of a block.
        This creates a unique fingerprint of the block's contents.
        
        Args:
            block (Dict): The block to hash
            
        Returns:
            str: The hexadecimal hash of the block
        """
        # Create a copy of the block without the hash field
        block_copy = block.copy()
        block_copy.pop('hash', None)  # Remove hash if it exists
        
        # Convert the block to a JSON string and encode it
        block_string = json.dumps(block_copy, sort_keys=True).encode()
        
        # Calculate and return the SHA-256 hash
        return hashlib.sha256(block_string).hexdigest()
    
    def add_block(self, event_type: str, data: Dict):
        """
        Add a new block to the chain.
        
        Args:
            event_type (str): Type of security event (e.g., 'Phishing', 'Suspicious')
            data (Dict): Details about the security event
        """
        new_block = {
            'timestamp': time.time(),
            'event_type': event_type,
            'data': data,
            'previous_hash': self.chain[-1]['hash']  # Link to previous block
        }
        new_block['hash'] = self.calculate_hash(new_block)
        self.chain.append(new_block)
    
    def get_chain(self) -> List[Dict]:
        """
        Return the entire blockchain.
        
        Returns:
            List[Dict]: List of all blocks in the chain
        """
        return self.chain
    
    def verify_chain(self) -> bool:
        """
        Verify the integrity of the blockchain.
        Checks if any blocks have been tampered with.
        
        Returns:
            bool: True if chain is valid, False if tampering detected
        """
        for i in range(1, len(self.chain)):
            current_block = self.chain[i]
            previous_block = self.chain[i-1]
            
            # Verify the current block's hash
            if current_block['hash'] != self.calculate_hash(current_block):
                return False
            
            # Verify the previous_hash reference
            if current_block['previous_hash'] != previous_block['hash']:
                return False
        
        return True

# Define request models using Pydantic for data validation
class MessageRequest(BaseModel):
    """Model for phishing detection requests"""
    text: str

class ActivityRequest(BaseModel):
    """Model for anomaly detection requests"""
    logins: List[int]

class AutoResponseRequest(BaseModel):
    """Model for automated threat response requests"""
    type: str  # Threat type (Phishing or Suspicious)
    source: str  # Source identifier (user or device)

# Initialize the blockchain for storing security events
blockchain = SimpleBlockchain()

# Sample training data for phishing detection
# This comprehensive dataset includes examples of both phishing and safe messages
phishing_examples = [
    # Financial/Banking Phishing - Messages trying to steal banking information
    "Urgent: Your account has been compromised. Click here to reset your password immediately.",
    "Your bank account will be suspended. Verify your identity by providing your account details.",
    "Suspicious activity detected in your account. Login now to secure your funds.",
    "Important: Your online banking access has been limited. Click to restore full access.",
    "Your credit card has been charged $750. Click here to dispute this transaction.",
    
    # Prize/Reward Scams - False promises of rewards to collect personal information
    "Congratulations! You've won a free iPhone. Click the link to claim your prize now.",
    "You've been selected for a $1000 Amazon gift card. Claim within 24 hours.",
    "You're our 1,000,000th visitor! Click here to receive your reward.",
    "Your email has won our monthly lottery. Submit details to claim prize.",
    "Exclusive offer: Claim your free vacation package now!",
    
    # Account/Service Related - Fake service notifications
    "Your Netflix subscription has expired. Update payment information to continue service.",
    "Your Apple ID has been locked for security reasons. Verify now.",
    "Your Microsoft account requires immediate attention. Sign in to prevent deletion.",
    "Your Google Drive storage is full. Click here to upgrade your account.",
    "Your PayPal account has been limited. Complete security check now.",
    
    # Delivery/Shipping Scams - Fake delivery notifications
    "Your package delivery failed. Click here to reschedule.",
    "Important: Update needed for your pending delivery.",
    "Your parcel is held at customs. Pay fees to release it.",
    "DHL: Your package is waiting for delivery confirmation.",
    "USPS: Package delivery attempted. Click to reschedule.",
    
    # Tax/Government Scams - Impersonating government agencies
    "Tax refund notification: Submit your bank details to receive your refund.",
    "IRS: You have a pending tax refund. Verify your information.",
    "Government stimulus payment waiting. Confirm eligibility now.",
    "Important notice from Social Security Administration. Login to respond.",
    "Your voter registration requires verification. Click to confirm.",
    
    # Technical Support Scams - Fake technical issues
    "Warning: Your computer has been infected. Call our support now.",
    "Your antivirus subscription has expired. Renew now to stay protected.",
    "System Alert: Multiple threats detected on your device.",
    "Your browser needs a critical security update. Install now.",
    "Technical Alert: Your IP address has been compromised."
]

# Examples of legitimate messages for comparison
safe_examples = [
    # Professional Communication - Normal business messages
    "The team meeting is scheduled for tomorrow at 10 AM.",
    "Please review the attached document and provide feedback.",
    "The quarterly report is ready for your review.",
    "Can we schedule a call next week to discuss the project?",
    "Here are the meeting minutes from yesterday's discussion.",
    
    # Customer Service - Legitimate service messages
    "Thank you for your recent purchase. Your order has been shipped.",
    "Your support ticket #12345 has been resolved.",
    "We've received your feedback and will get back to you soon.",
    "Your appointment has been confirmed for next Tuesday.",
    "Here's your requested account statement for March 2024.",
    
    # Company Updates - Normal company communications
    "The office will be closed on Monday for the holiday.",
    "We've updated our privacy policy. No action is required.",
    "Join us for the company picnic this Saturday.",
    "The new employee handbook is now available on the intranet.",
    "System maintenance scheduled for this weekend.",
    
    # Project Management - Work-related messages
    "The deadline for the project submission is next Friday.",
    "Please upload your presentations to the shared folder.",
    "The client has approved the latest design mockups.",
    "Team training session will be held next Wednesday.",
    "Sprint planning meeting at 2 PM in Conference Room A.",
    
    # HR/Administrative - Standard HR communications
    "Please submit your expense reports by the end of the month.",
    "Your vacation request has been approved.",
    "Remember to complete your annual compliance training.",
    "New parking permits are available at the security desk.",
    "The company newsletter is now available to read.",
    
    # IT Department - Legitimate IT notifications
    "Your password has been successfully changed.",
    "System upgrade completed. No issues reported.",
    "New collaboration tools are now available.",
    "Your software license has been renewed.",
    "VPN access has been granted as requested."
]

# Create labels for the training data
# 1 for phishing (malicious), 0 for safe (legitimate)
labels = np.array([1] * len(phishing_examples) + [0] * len(safe_examples))
training_data = phishing_examples + safe_examples

# Initialize and train the phishing detection model
# TfidfVectorizer converts text into numerical features
vectorizer = TfidfVectorizer(stop_words='english', max_features=1000)
X = vectorizer.fit_transform(training_data)  # Transform text to features
model = LogisticRegression()  # Simple but effective classifier
model.fit(X, labels)  # Train the model

# Initialize the anomaly detection model
# IsolationForest detects anomalies in login patterns
anomaly_detector = IsolationForest(
    contamination=0.1,  # Expected proportion of anomalies
    random_state=42  # For reproducible results
)

@app.get("/ping")
async def ping():
    """
    Simple endpoint to check if the backend is running.
    Used by the frontend to verify backend connectivity.
    
    Returns:
        dict: A simple response with "pong" message
    """
    return {"message": "pong"}

def generate_phishing_explanation(text: str, probabilities: np.ndarray, vectorizer: TfidfVectorizer) -> str:
    """
    Generate a human-readable explanation for why a message was classified as phishing.
    This helps users understand why a message is considered suspicious.
    
    Args:
        text (str): The message being analyzed
        probabilities (np.ndarray): Model's prediction probabilities
        vectorizer (TfidfVectorizer): The text vectorizer used by the model
    
    Returns:
        str: A detailed explanation of why the message might be phishing
    """
    # Get the feature names (words) from the vectorizer
    feature_names = vectorizer.get_feature_names_out()
    
    # Transform the input text to get used features
    text_vector = vectorizer.transform([text])
    
    # Get the non-zero features (words present in the text)
    present_features = text_vector.nonzero()[1]
    suspicious_words = [feature_names[i] for i in present_features]
    
    # Common patterns that might indicate phishing
    patterns = {
        'urgency': ['urgent', 'immediately', 'quick', 'act now', 'limited time'],
        'financial': ['money', 'cash', 'bank', 'account', 'credit', 'debit'],
        'personal_info': ['password', 'login', 'verify', 'details', 'information'],
        'prize': ['winner', 'won', 'prize', 'claim', 'reward'],
        'pressure': ['warning', 'suspended', 'deleted', 'blocked', 'restricted']
    }
    
    # Check which patterns are present in the text
    found_patterns = []
    for category, words in patterns.items():
        if any(word in text.lower() for word in words):
            found_patterns.append(category)
    
    # Generate explanation based on probability and patterns
    if probabilities[1] > 0.8:  # High confidence phishing
        confidence_level = "strongly indicates"
    elif probabilities[1] > 0.6:
        confidence_level = "suggests"
    else:
        confidence_level = "might be"
    
    explanation = f"Analysis {confidence_level} this is a phishing attempt. "
    
    # Add pattern-based explanations
    if found_patterns:
        pattern_explanations = {
            'urgency': "creates a false sense of urgency",
            'financial': "requests financial information",
            'personal_info': "asks for personal information",
            'prize': "makes unrealistic promises or offers",
            'pressure': "uses pressure tactics"
        }
        reasons = [pattern_explanations[pattern] for pattern in found_patterns]
        if reasons:
            explanation += "The message " + ", and ".join(reasons) + "."
    
    # Add suspicious words if found
    if suspicious_words:
        explanation += f" Suspicious terms detected: {', '.join(suspicious_words[:5])}"
        if len(suspicious_words) > 5:
            explanation += " and others."
    
    return explanation

def generate_anomaly_explanation(login_data: np.ndarray, score: float, scores: np.ndarray) -> str:
    """
    Generate a human-readable explanation for why activity was flagged as suspicious.
    This helps users understand why login patterns are considered anomalous.
    
    Args:
        login_data (np.ndarray): Recent login activity data
        score (float): Anomaly score for the current activity
        scores (np.ndarray): Historical anomaly scores for comparison
    
    Returns:
        str: A detailed explanation of why the activity might be suspicious
    """
    # Look at the last 3 data points for recent patterns
    recent_logins = login_data[-3:]
    # Calculate average of previous logins for baseline
    avg_logins = np.mean(login_data[:-1])
    # Get the most recent login count
    last_login = login_data[-1][0]
    
    explanation = ""
    
    # Check for sudden spike in login attempts
    if last_login > avg_logins * 2:
        explanation += f"Detected a sudden spike in login attempts ({last_login} vs average of {avg_logins:.1f}). "
    
    # Check for unusual patterns over time
    if len(recent_logins) >= 3:
        if all(x[0] > avg_logins * 1.5 for x in recent_logins):
            explanation += "Sustained high login activity detected. "
        elif all(x[0] < avg_logins * 0.5 for x in recent_logins):
            explanation += "Unusually low login activity detected. "
    
    # Add score-based explanation for anomaly severity
    min_score = min(scores)
    max_score = max(scores)
    score_range = max_score - min_score
    if score_range != 0:
        normalized_score = (score - min_score) / score_range
        if normalized_score < 0.3:
            explanation += "Activity pattern significantly deviates from normal behavior. "
        elif normalized_score < 0.5:
            explanation += "Activity pattern shows moderate deviation from normal behavior. "
    
    # Default explanation if no specific patterns are found
    if not explanation:
        explanation = "Multiple factors in the login pattern indicate suspicious activity. "
    
    return explanation.strip()

@app.post("/detect_phishing")
async def detect_phishing(request: MessageRequest):
    """
    Endpoint to detect if a message is phishing or safe.
    Uses machine learning to analyze text and identify potential phishing attempts.
    
    Args:
        request (MessageRequest): Contains the text message to analyze
    
    Returns:
        dict: Detection results including prediction, confidence score, and explanation
    """
    # Transform the input text using the trained vectorizer
    text_features = vectorizer.transform([request.text])
    
    # Get prediction probabilities (phishing vs safe)
    probabilities = model.predict_proba(text_features)[0]
    
    # Get the final prediction (1 for phishing, 0 for safe)
    prediction = model.predict(text_features)[0]
    
    # Calculate confidence score as a percentage
    confidence = probabilities[1] if prediction == 1 else probabilities[0]
    confidence = round(confidence * 100, 2)
    
    # Convert numerical prediction to text label
    result = "Phishing" if prediction == 1 else "Safe"
    
    # Generate detailed explanation for the prediction
    explanation = ""
    if result == "Phishing":
        explanation = generate_phishing_explanation(request.text, probabilities, vectorizer)
    else:
        explanation = "Message appears to be safe. No suspicious patterns or indicators detected."
    
    # Create the response with detailed information
    response_data = {
        "prediction": result,
        "confidence": confidence,
        "reason": explanation,
        "details": {
            "phishing_probability": round(probabilities[1] * 100, 2),
            "safe_probability": round(probabilities[0] * 100, 2)
        }
    }
    
    # If phishing is detected, log it to the blockchain for security audit
    if result == "Phishing":
        blockchain.add_block(
            event_type="Phishing",
            data={
                "message_preview": request.text[:100] + "..." if len(request.text) > 100 else request.text,
                "confidence": confidence,
                "reason": explanation,
                "probabilities": {
                    "phishing": round(probabilities[1] * 100, 2),
                    "safe": round(probabilities[0] * 100, 2)
                }
            }
        )
    
    return response_data

@app.post("/detect_anomaly")
async def detect_anomaly(request: ActivityRequest):
    """
    Endpoint to detect if the latest login activity is anomalous.
    Uses machine learning to identify suspicious login patterns.
    
    Args:
        request (ActivityRequest): Contains a list of recent login counts
    
    Returns:
        dict: Detection results including status, confidence, and explanation
    """
    # Convert login counts to 2D array for scikit-learn
    login_data = np.array(request.logins).reshape(-1, 1)
    
    # Train the model and predict anomalies
    anomaly_detector.fit(login_data)
    prediction = anomaly_detector.predict(login_data)
    
    # Get anomaly scores for detailed analysis
    scores = anomaly_detector.score_samples(login_data)
    
    # Calculate confidence score
    last_score = scores[-1]
    min_score = min(scores)
    max_score = max(scores)
    confidence = round(((last_score - min_score) / (max_score - min_score)) * 100, 2)
    
    # Check if the last activity is anomalous (-1 indicates anomaly)
    is_anomaly = prediction[-1] == -1
    status = "Suspicious" if is_anomaly else "Normal"
    
    # Generate detailed explanation for the prediction
    explanation = ""
    if status == "Suspicious":
        explanation = generate_anomaly_explanation(login_data, last_score, scores)
    else:
        explanation = "Login activity appears normal with no significant deviations from expected patterns."
    
    # Create the response with detailed information
    response_data = {
        "status": status,
        "confidence": confidence,
        "reason": explanation,
        "details": {
            "anomaly_score": round(last_score, 4),
            "score_range": {
                "min": round(min_score, 4),
                "max": round(max_score, 4)
            }
        }
    }
    
    # If suspicious activity detected, log it to the blockchain
    if status == "Suspicious":
        blockchain.add_block(
            event_type="Suspicious",
            data={
                "login_pattern": request.logins,
                "confidence": confidence,
                "reason": explanation,
                "anomaly_score": round(last_score, 4)
            }
        )
    
    return response_data

@app.get("/alerts")
async def get_alerts():
    """
    Endpoint to retrieve all security alerts from the blockchain.
    Provides a complete audit trail of security events.
    
    Returns:
        dict: Contains blockchain validity status and list of all alerts
    """
    # Verify the blockchain's integrity
    chain_valid = blockchain.verify_chain()
    
    # Get all blocks except the genesis block
    alerts = blockchain.get_chain()[1:]  # Skip genesis block
    
    # Format timestamps to be human-readable
    for alert in alerts:
        alert['timestamp'] = time.strftime('%Y-%m-%d %H:%M:%S', 
                                         time.localtime(alert['timestamp']))
    
    return {
        "chain_valid": chain_valid,
        "alerts": alerts
    }

@app.get("/stats")
async def get_stats():
    """
    Endpoint to provide dashboard statistics and timeline data.
    Summarizes security events for monitoring and reporting.
    
    Returns:
        dict: Contains event counts and chronological timeline
    """
    # Get all blocks except the genesis block
    alerts = blockchain.get_chain()[1:]
    
    # Initialize counters for different types of alerts
    phishing_count = 0
    suspicious_count = 0
    timeline = []
    
    # Process each alert to build statistics
    for alert in alerts:
        # Count events by type
        if alert['event_type'] == 'Phishing':
            phishing_count += 1
        elif alert['event_type'] == 'Suspicious':
            suspicious_count += 1
        
        # Add to chronological timeline
        timeline.append({
            'time': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(alert['timestamp'])),
            'type': alert['event_type']
        })
    
    return {
        "phishing_count": phishing_count,
        "suspicious_count": suspicious_count,
        "total_alerts": len(alerts),
        "timeline": timeline
    }

@app.post("/auto_response")
async def auto_response(request: AutoResponseRequest):
    """
    Endpoint to automatically respond to detected threats.
    Implements rule-based responses and logs actions to the blockchain.
    
    Args:
        request (AutoResponseRequest): Contains threat type and source
    
    Returns:
        dict: Details of the automated action taken
    """
    # Define response rules for different threat types
    response_rules = {
        "Phishing": {
            "action": "User temporarily blocked",
            "severity": "Critical",
            "color": "red"
        },
        "Suspicious": {
            "action": "Device activity monitored",
            "severity": "Warning",
            "color": "yellow"
        }
    }
    
    # Get the appropriate response based on threat type
    response = response_rules.get(request.type)
    if not response:
        return {"error": "Invalid threat type. Must be 'Phishing' or 'Suspicious'"}
    
    # Create blockchain record of the automated action
    timestamp = time.time()
    blockchain_record = {
        "timestamp": timestamp,
        "type": "Auto-Response",
        "threat_type": request.type,
        "source": request.source,
        "action": response["action"],
        "severity": response["severity"]
    }
    
    # Log the action to the blockchain for audit trail
    blockchain.add_block("Auto-Response", blockchain_record)
    print(f"Auto-Response triggered: {response['action']} for {request.source} due to {request.type} threat")
    
    # Return the response with full context
    return {
        "action": response["action"],
        "severity": response["severity"],
        "color": response["color"],
        "timestamp": timestamp,
        "source": request.source
    }

@app.get("/generate_report")
async def generate_report():
    """
    Generate a comprehensive security report based on blockchain data.
    Summarizes all security events, actions taken, and provides recommendations.
    
    Returns:
        dict: Contains the formatted security report as text
    """
    # Get all blocks except the genesis block
    alerts = blockchain.get_chain()[1:]
    
    # Initialize counters and data structures
    phishing_count = 0
    suspicious_count = 0
    auto_responses = []
    latest_timestamp = None
    
    # Process each alert to gather statistics
    for alert in alerts:
        timestamp = alert['timestamp']
        event_type = alert['event_type']
        
        # Track the most recent event
        if latest_timestamp is None or timestamp > latest_timestamp:
            latest_timestamp = timestamp
        
        # Count events by type
        if event_type == 'Phishing':
            phishing_count += 1
        elif event_type == 'Suspicious':
            suspicious_count += 1
        elif event_type == 'Auto-Response':
            auto_responses.append(alert['data'])
    
    # Generate the formatted report
    report = []
    report.append("CyberSentinel AI - Security Report")
    report.append("=" * 40)
    report.append("")
    
    # Add report timestamp and last event
    if latest_timestamp:
        report.append(f"Report Generated: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(time.time()))}")
        report.append(f"Last Alert: {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(latest_timestamp))}")
    report.append("")
    
    # Add threat statistics section
    report.append("Threat Statistics")
    report.append("-" * 20)
    report.append(f"Total Phishing Attempts: {phishing_count}")
    report.append(f"Suspicious Activities: {suspicious_count}")
    report.append(f"Total Security Events: {len(alerts)}")
    report.append("")
    
    # Add recent automated actions section
    if auto_responses:
        report.append("Recent Automated Actions")
        report.append("-" * 20)
        for response in auto_responses[-5:]:  # Show last 5 actions
            action_time = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(response['timestamp']))
            report.append(f"- {action_time}: {response['action']} ({response['source']})")
    report.append("")
    
    # Add security recommendations section
    report.append("Security Recommendations")
    report.append("-" * 20)
    if phishing_count > 0:
        report.append("- Maintain vigilance against phishing attempts")
        report.append("- Regularly update security training")
    if suspicious_count > 0:
        report.append("- Monitor for unusual login patterns")
        report.append("- Review access controls regularly")
    report.append("- Keep CyberSentinel AI system updated")
    report.append("")
    
    # Join all sections into a single report
    return {"report": "\n".join(report)}

@app.get("/")
async def root():
    """
    Root endpoint that provides information about the API.
    Serves as documentation for available endpoints and features.
    
    Returns:
        dict: API information including endpoints and model details
    """
    return {
        "name": "CyberSentinel AI API",
        "version": "1.0.0",
        "endpoints": [
            {"path": "/", "method": "GET", "description": "API information"},
            {"path": "/ping", "method": "GET", "description": "Health check endpoint"},
            {"path": "/detect_phishing", "method": "POST", "description": "Phishing detection endpoint"},
            {"path": "/detect_anomaly", "method": "POST", "description": "Anomaly detection endpoint"},
            {"path": "/alerts", "method": "GET", "description": "Security alerts ledger"},
            {"path": "/auto_response", "method": "POST", "description": "Automated threat response endpoint"},
            {"path": "/generate_report", "method": "GET", "description": "Generate security report"}
        ],
        "models": {
            "phishing_detection": {
                "training_examples": {
                    "phishing": len(phishing_examples),
                    "safe": len(safe_examples)
                }
            }
        }
    }

# Run the application with uvicorn when executed directly
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("backend:app", host="127.0.0.1", port=8000, reload=True)