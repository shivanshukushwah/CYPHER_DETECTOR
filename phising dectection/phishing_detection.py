import pickle
import re
from sklearn.feature_extraction.text import CountVectorizer
from sklearn.naive_bayes import MultinomialNB

class PhishingDetector:
    def __init__(self):
        self.vectorizer = CountVectorizer()
        self.model = MultinomialNB()

    def preprocess(self, email):
        """Preprocess email by combining subject and body and extracting features."""
        subject = email.get('subject', '').lower()
        body = email.get('body', '').lower()
        combined_text = f"{subject} {body}"
        return combined_text

    def extract_features(self, email):
        """Extract features from email for prediction."""
        combined_text = self.preprocess(email)
        return self.vectorizer.transform([combined_text])

    def train(self, training_data):
        """Train the model with the provided training data."""
        emails = [self.preprocess(item['email']) for item in training_data]
        labels = [item['is_phishing'] for item in training_data]

        # Fit the vectorizer and transform the emails
        features = self.vectorizer.fit_transform(emails)

        # Train the model
        self.model.fit(features, labels)

        # Return the accuracy on the training data
        accuracy = self.model.score(features, labels)
        return accuracy

    def predict(self, email):
        """Predict whether an email is phishing or not."""
        features = self.extract_features(email)
        is_phishing = self.model.predict(features)[0]
        probability = self.model.predict_proba(features)[0][1]

        # Extract additional features for explanation
        url_count = len(re.findall(r'http[s]?://', email['body']))
        suspicious_url_ratio = len(re.findall(r'(secure|login|verify|update|account)', email['body'].lower())) / (len(email['body'].split()) + 1)
        urgent_word_count = len(re.findall(r'(urgent|immediate|action required|important)', email['body'].lower()))
        misspelled_domain_count = len(re.findall(r'(paypa1|g00gle|microsoft-secure|bit\.ly)', email['body'].lower()))
        sensitive_info_requests = len(re.findall(r'(password|credit card|social security|ssn)', email['body'].lower()))

        return {
            'is_phishing': bool(is_phishing),
            'probability': probability,
            'features': {
                'url_count': url_count,
                'suspicious_url_ratio': suspicious_url_ratio,
                'urgent_word_count': urgent_word_count,
                'misspelled_domain_count': misspelled_domain_count,
                'sensitive_info_requests': sensitive_info_requests
            }
        }

    def save_model(self, filepath):
        """Save the trained model and vectorizer to a file."""
        with open(filepath, 'wb') as f:
            pickle.dump({'model': self.model, 'vectorizer': self.vectorizer}, f)

    def load_model(self, filepath):
        """Load the trained model and vectorizer from a file."""
        with open(filepath, 'rb') as f:
            data = pickle.load(f)
            self.model = data['model']
            self.vectorizer = data['vectorizer']