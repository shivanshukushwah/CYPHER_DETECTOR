from flask import Flask, request, jsonify, render_template
from phishing_detection import PhishingDetector
import os
import json
from datetime import datetime, timedelta
import random

app = Flask(__name__)
detector = PhishingDetector()

# Load pre-trained model if it exists
model_path = 'phishing_detector_model.pkl'
if os.path.exists(model_path):
    detector.load_model(model_path)
else:
    # For demonstration, we'll create a small sample dataset
    # In a real application, you would train with a larger dataset
    sample_data = [
        {
            'email': {
                'subject': 'Your PayPal account has been limited',
                'body': 'Dear customer, your PayPal account has been limited due to suspicious activity. Please verify your information at http://paypa1-secure-login.com/verify'
            },
            'is_phishing': True
        },
        {
            'email': {
                'subject': 'Action required: Update your payment information',
                'body': 'Your Netflix subscription will expire soon. Please update your payment information at https://bit.ly/netflix-update'
            },
            'is_phishing': True
        },
        {
            'email': {
                'subject': 'Your Amazon order #12345',
                'body': 'Thank you for your order with Amazon. Your package will be delivered on March 15. Track your order at https://amazon.com/orders/12345'
            },
            'is_phishing': False
        },
        {
            'email': {
                'subject': 'Team meeting tomorrow',
                'body': 'Hi team, just a reminder that we have our weekly meeting tomorrow at 10am. See you there!'
            },
            'is_phishing': False
        },
        {
            'email': {
                'subject': 'Invoice for your recent purchase',
                'body': 'Please find attached the invoice for your recent purchase. If you have any questions, please contact our support team.'
            },
            'is_phishing': False
        },
        {
            'email': {
                'subject': 'URGENT: Your account will be suspended',
                'body': 'Your Microsoft account has been compromised. Click here to verify your identity: https://microsoft-secure.tk/verify'
            },
            'is_phishing': True
        },
        {
            'email': {
                'subject': 'Password Reset Request',
                'body': 'We received a request to reset your password. If you did not make this request, please ignore this email. Otherwise, click the link below to reset your password: https://secure-g00gle.com/reset'
            },
            'is_phishing': True
        },
        {
            'email': {
                'subject': 'Your subscription renewal',
                'body': 'Your subscription has been renewed successfully. The next billing date is April 15, 2023. Thank you for your continued support.'
            },
            'is_phishing': False
        }
    ]
    
    print("Training model with sample data...")
    detector.train(sample_data)
    detector.save_model(model_path)
    print("Model trained and saved.")

# Store detection history
detection_history = []
detection_log_path = 'detection_history.json'

# Load detection history if exists
if os.path.exists(detection_log_path):
    try:
        with open(detection_log_path, 'r') as f:
            detection_history = json.load(f)
    except:
        detection_history = []

def save_detection(email_subject, result):
    """Save detection result to history"""
    detection = {
        'date': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'subject': email_subject,
        'is_phishing': result['is_phishing'],
        'probability': round(result['probability'] * 100, 1),
        'risk_level': 'High' if result['probability'] > 0.75 else 'Medium' if result['probability'] > 0.4 else 'Low'
    }
    
    detection_history.append(detection)
    
    # Keep only the last 1000 detections
    if len(detection_history) > 1000:
        detection_history.pop(0)
    
    # Save to file
    with open(detection_log_path, 'w') as f:
        json.dump(detection_history, f)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/dashboard')
def dashboard():
    # For a real application, you would calculate these from actual data
    # For this example, we'll use the detection history or generate sample data
    
    if detection_history:
        total_emails = len(detection_history)
        phishing_detected = sum(1 for d in detection_history if d['is_phishing'])
        legitimate_emails = total_emails - phishing_detected
        detection_rate = round((phishing_detected / total_emails) * 100, 1) if total_emails > 0 else 0
        
        high_risk = sum(1 for d in detection_history if d['risk_level'] == 'High')
        medium_risk = sum(1 for d in detection_history if d['risk_level'] == 'Medium')
        low_risk = sum(1 for d in detection_history if d['risk_level'] == 'Low')
        
        # Sort by date (newest first) and take the last 10
        recent_detections = sorted(detection_history, key=lambda x: x['date'], reverse=True)[:10]
    else:
        # Generate sample data for demonstration
        total_emails = 1245
        phishing_detected = 328
        legitimate_emails = total_emails - phishing_detected
        detection_rate = round((phishing_detected / total_emails) * 100, 1)
        
        high_risk = 187
        medium_risk = 141
        low_risk = 917
        
        # Generate sample recent detections
        recent_detections = []
        subjects = [
            "Your account has been suspended",
            "Invoice #12345 for your recent purchase",
            "Password reset request",
            "Team meeting tomorrow",
            "Your Amazon order has shipped",
            "Urgent: Action required on your account",
            "Your subscription renewal",
            "Security alert: New login detected",
            "Your payment was successful",
            "Important update to our terms of service"
        ]
        
        for i in range(10):
            days_ago = random.randint(0, 10)
            is_phishing = random.random() > 0.7
            probability = random.uniform(0.8, 0.99) if is_phishing else random.uniform(0.01, 0.3)
            
            detection = {
                'date': (datetime.now() - timedelta(days=days_ago)).strftime('%Y-%m-%d %H:%M:%S'),
                'subject': subjects[i],
                'is_phishing': is_phishing,
                'probability': round(probability * 100, 1),
                'risk_level': 'High' if probability > 0.75 else 'Medium' if probability > 0.4 else 'Low'
            }
            recent_detections.append(detection)
    
    stats = {
        'total_emails': total_emails,
        'phishing_detected': phishing_detected,
        'legitimate_emails': legitimate_emails,
        'detection_rate': detection_rate,
        'model_accuracy': 92.5,  # In a real app, this would be calculated from model evaluation
        'high_risk': high_risk,
        'medium_risk': medium_risk,
        'low_risk': low_risk
    }
    
    return render_template('dashboard.html', stats=stats, recent_detections=recent_detections)

@app.route('/predict', methods=['POST'])
def predict():
    data = request.json
    
    if not data or 'subject' not in data or 'body' not in data:
        return jsonify({'error': 'Missing required fields: subject and body'}), 400
    
    email = {
        'subject': data['subject'],
        'body': data['body']
    }
    
    try:
        result = detector.predict(email)
        
        # Save detection to history
        save_detection(data['subject'], result)
        
        return jsonify({
            'is_phishing': result['is_phishing'],
            'probability': float(result['probability']),
            'risk_level': 'High' if result['probability'] > 0.75 else 'Medium' if result['probability'] > 0.4 else 'Low',
            'features': {
                'url_count': result['features']['url_count'],
                'suspicious_url_ratio': float(result['features']['suspicious_url_ratio']),
                'urgent_word_count': result['features']['urgent_word_count'],
                'misspelled_domain_count': result['features']['misspelled_domain_count'],
                'sensitive_info_requests': result['features']['sensitive_info_requests']
            }
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/train', methods=['POST'])
def train():
    data = request.json
    
    if not data or 'training_data' not in data:
        return jsonify({'error': 'Missing required field: training_data'}), 400
    
    try:
        accuracy = detector.train(data['training_data'])
        detector.save_model(model_path)
        return jsonify({
            'success': True,
            'accuracy': float(accuracy),
            'message': 'Model trained and saved successfully'
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)