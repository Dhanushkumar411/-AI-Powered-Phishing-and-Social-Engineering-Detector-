"""
NLP & TF-IDF Machine Learning Inference Engine.
Loads trained pipeline, calculates classification probabilities,
and extracts token-level feature contributions for Explainable AI.
"""

import os
import joblib
import numpy as np

MODEL_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "model", "phishing_model.joblib")


class NLPAnalyzer:
    def __init__(self, model_path=MODEL_PATH):
        self.model_path = model_path
        self.pipeline = None
        self.tfidf = None
        self.classifier = None
        self.feature_names = None
        self.coefficients = None
        self.vocab_map = {}
        self.load_model()

    def load_model(self):
        """Loads the serialized TF-IDF + Logistic Regression pipeline."""
        if not os.path.exists(self.model_path):
            raise FileNotFoundError(f"Model file not found at: {self.model_path}. Please run model/train.py first.")
        
        self.pipeline = joblib.load(self.model_path)
        self.tfidf = self.pipeline.named_steps['tfidf']
        self.classifier = self.pipeline.named_steps['classifier']
        self.feature_names = self.tfidf.get_feature_names_out()
        self.coefficients = self.classifier.coef_[0]
        # Build reverse index for fast O(1) keyword weight lookup
        self.vocab_map = self.tfidf.vocabulary_

    def analyze_text(self, text):
        """
        Runs ML prediction and computes token-level Explainable AI feature attributions.
        """
        if not text or not text.strip():
            return {
                "phishing_probability": 0.0,
                "legitimate_probability": 1.0,
                "prediction": "LEGITIMATE",
                "risk_tier": "SAFE",
                "contributing_features": [],
                "text_stats": {
                    "word_count": 0,
                    "char_count": 0,
                    "uppercase_ratio": 0.0
                }
            }

        # Calculate text statistics (e.g., uppercase shout ratio)
        char_count = len(text)
        uppercase_chars = sum(1 for c in text if c.isupper())
        uppercase_ratio = round(uppercase_chars / char_count, 3) if char_count > 0 else 0.0
        words = text.split()

        # Predict probability
        probs = self.pipeline.predict_proba([text])[0]
        legit_prob = float(probs[0])
        phish_prob = float(probs[1])

        # Feature Attribution / Explainability (XAI):
        # We transform the single text into TF-IDF vector, then multiply each non-zero feature by its coefficient.
        tfidf_vec = self.tfidf.transform([text])
        feature_indices = tfidf_vec.nonzero()[1]
        
        contributions = []
        for idx in feature_indices:
            term = self.feature_names[idx]
            tfidf_val = tfidf_vec[0, idx]
            weight = self.coefficients[idx]
            impact = tfidf_val * weight  # Log-odds contribution
            
            contributions.append({
                "term": term,
                "tfidf": round(float(tfidf_val), 4),
                "weight": round(float(weight), 4),
                "impact": round(float(impact), 4),
                "direction": "phishing" if impact > 0 else "legitimate"
            })

        # Sort by absolute impact descending
        contributions.sort(key=lambda x: abs(x["impact"]), reverse=True)

        # Risk tier assignment based on ML probability
        if phish_prob >= 0.70:
            risk_tier = "CRITICAL_PHISHING"
        elif phish_prob >= 0.40:
            risk_tier = "SUSPICIOUS"
        else:
            risk_tier = "SAFE"

        return {
            "phishing_probability": round(phish_prob, 4),
            "legitimate_probability": round(legit_prob, 4),
            "prediction": "PHISHING" if phish_prob >= 0.50 else "LEGITIMATE",
            "risk_tier": risk_tier,
            "contributing_features": contributions[:15],  # Top 15 drivers
            "text_stats": {
                "word_count": len(words),
                "char_count": char_count,
                "uppercase_ratio": uppercase_ratio
            }
        }


# Singleton instance
_analyzer_instance = None

def get_nlp_analyzer():
    global _analyzer_instance
    if _analyzer_instance is None:
        _analyzer_instance = NLPAnalyzer()
    return _analyzer_instance


if __name__ == "__main__":
    analyzer = get_nlp_analyzer()
    sample = "URGENT: Your Microsoft 365 password will expire in 2 hours. Verify your account now at http://portal.xyz"
    res = analyzer.analyze_text(sample)
    print(f"Prediction: {res['prediction']} ({res['phishing_probability'] * 100:.1f}%)")
    print("Top contributing features:")
    for f in res["contributing_features"][:5]:
        print(f" - '{f['term']}': impact={f['impact']} (direction: {f['direction']})")
