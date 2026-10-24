"""
Model training script for AI-Powered Phishing Detector.
Trains a TF-IDF + Logistic Regression classification pipeline on the balanced dataset,
evaluates precision, recall, F1, ROC-AUC, and saves the trained pipeline and metrics.
"""

import os
import json
import joblib
import numpy as np
from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    roc_auc_score,
    confusion_matrix,
    classification_report
)

from dataset import generate_extended_dataset


def train_model(save_dir=None):
    if save_dir is None:
        save_dir = os.path.dirname(os.path.abspath(__file__))

    print("Generating dataset...")
    data = generate_extended_dataset(num_phishing=400, num_ham=400, seed=42)
    texts = [item["text"] for item in data]
    labels = np.array([item["label"] for item in data])

    print(f"Total samples: {len(texts)} (Phishing: {sum(labels)}, Legitimate: {len(labels) - sum(labels)})")

    # Split into train and test sets
    X_train, X_test, y_train, y_test = train_test_split(
        texts, labels, test_size=0.20, random_state=42, stratify=labels
    )

    print(f"Training set: {len(X_train)} samples, Test set: {len(X_test)} samples")

    # Define TF-IDF + Classifier Pipeline
    pipeline = Pipeline([
        ('tfidf', TfidfVectorizer(
            ngram_range=(1, 2),
            sublinear_tf=True,
            min_df=2,
            max_df=0.95,
            token_pattern=r'(?u)\b\w+\b|[!$?%]',
            lowercase=True
        )),
        ('classifier', LogisticRegression(
            C=2.0,
            penalty='l2',
            solver='liblinear',
            class_weight='balanced',
            random_state=42
        ))
    ])

    print("Training pipeline...")
    pipeline.fit(X_train, y_train)

    # 5-fold cross-validation on training set
    skf = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
    cv_scores = cross_val_score(pipeline, X_train, y_train, cv=skf, scoring='f1')
    print(f"5-Fold Cross Validation F1 Score: {cv_scores.mean():.4f} (+/- {cv_scores.std():.4f})")

    # Evaluate on test set
    y_pred = pipeline.predict(X_test)
    y_prob = pipeline.predict_proba(X_test)[:, 1]

    accuracy = float(accuracy_score(y_test, y_pred))
    precision = float(precision_score(y_test, y_pred, zero_division=0))
    recall = float(recall_score(y_test, y_pred, zero_division=0))
    f1 = float(f1_score(y_test, y_pred, zero_division=0))
    roc_auc = float(roc_auc_score(y_test, y_prob))
    cm = confusion_matrix(y_test, y_pred).tolist()

    print("\n--- Model Evaluation Results ---")
    print(f"Accuracy:  {accuracy:.4f}")
    print(f"Precision: {precision:.4f}")
    print(f"Recall:    {recall:.4f}")
    print(f"F1 Score:  {f1:.4f}")
    print(f"ROC AUC:   {roc_auc:.4f}")
    print("\nConfusion Matrix:")
    print(f"  TN: {cm[0][0]}  |  FP: {cm[0][1]}")
    print(f"  FN: {cm[1][0]}  |  TP: {cm[1][1]}")
    print("\nClassification Report:\n", classification_report(y_test, y_pred, target_names=["Legitimate", "Phishing"]))

    # Extract top indicative features (Explainability)
    tfidf = pipeline.named_steps['tfidf']
    clf = pipeline.named_steps['classifier']
    feature_names = tfidf.get_feature_names_out()
    coefficients = clf.coef_[0]

    # Top phishing keywords (highest positive coefficients)
    top_phish_idx = np.argsort(coefficients)[-30:][::-1]
    top_phishing_features = [
        {"feature": feature_names[i], "weight": round(float(coefficients[i]), 4)}
        for i in top_phish_idx
    ]

    # Top legitimate keywords (most negative coefficients)
    top_ham_idx = np.argsort(coefficients)[:30]
    top_legitimate_features = [
        {"feature": feature_names[i], "weight": round(float(coefficients[i]), 4)}
        for i in top_ham_idx
    ]

    # Save model artifact
    model_path = os.path.join(save_dir, "phishing_model.joblib")
    joblib.dump(pipeline, model_path)
    print(f"Trained model pipeline saved to: {model_path}")

    # Save metrics and vocabulary metadata
    metrics = {
        "accuracy": accuracy,
        "precision": precision,
        "recall": recall,
        "f1_score": f1,
        "roc_auc": roc_auc,
        "cv_f1_mean": float(cv_scores.mean()),
        "cv_f1_std": float(cv_scores.std()),
        "confusion_matrix": {
            "true_negative": cm[0][0],
            "false_positive": cm[0][1],
            "false_negative": cm[1][0],
            "true_positive": cm[1][1]
        },
        "vocabulary_size": len(feature_names),
        "total_samples": len(texts),
        "top_phishing_features": top_phishing_features,
        "top_legitimate_features": top_legitimate_features
    }

    metrics_path = os.path.join(save_dir, "metrics.json")
    with open(metrics_path, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)
    print(f"Evaluation metrics saved to: {metrics_path}")

    return pipeline, metrics


if __name__ == "__main__":
    train_model()
