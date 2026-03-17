import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, accuracy_score
import joblib
import os

from src.utils.config import TRAINING_DATA_FILE, MODEL_FILE
from src.utils.helpers import setup_logger

logger = setup_logger("train_model")

def train():
    logger.info(f"Loading training data from {TRAINING_DATA_FILE}")
    if not os.path.exists(TRAINING_DATA_FILE):
        logger.error(f"Training data not found at {TRAINING_DATA_FILE}. Please run generate_data.py first.")
        return
        
    df = pd.read_csv(TRAINING_DATA_FILE)
    
    # Features required: avg_packet_size, packet_frequency, session_duration, burst_rate, port
    X = df[["avg_packet_size", "packet_frequency", "session_duration", "burst_rate", "port"]]
    y = df["label"]
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    logger.info("Training RandomForestClassifier...")
    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    clf.fit(X_train, y_train)
    
    logger.info("Evaluating model...")
    y_pred = clf.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    logger.info(f"Model Accuracy: {accuracy:.4f}")
    
    # In a real scenario we'd log the full classification report, printing for terminal review here
    print(classification_report(y_test, y_pred))
    
    logger.info(f"Saving model to {MODEL_FILE}")
    joblib.dump(clf, MODEL_FILE)
    logger.info("Training complete.")

if __name__ == "__main__":
    train()
