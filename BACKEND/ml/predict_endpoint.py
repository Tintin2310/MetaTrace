import joblib
import pandas as pd
import os
from src.utils.config import MODEL_FILE
from src.utils.helpers import setup_logger

logger = setup_logger("predict_endpoint")

class EndpointPredictor:
    def __init__(self, model_path=MODEL_FILE):
        self.model_path = model_path
        self.model = None
        self.load_model()
        
    def load_model(self):
        if os.path.exists(self.model_path):
            self.model = joblib.load(self.model_path)
            logger.info("Loaded endpoint classifier model.")
        else:
            logger.error(f"Model not found at {self.model_path}. Train model first.")
            
    def predict(self, features):
        """Predicts the network label and returns probability distribution."""
        if self.model is None or features is None:
            return None, None
            
        # Extract features in the correct order for the model
        # avg_packet_size, packet_frequency, session_duration, burst_rate, port
        feature_vector = [[
            features.get("avg_packet_size", 0),
            features.get("packet_frequency", 0),
            features.get("session_duration", 0),
            features.get("burst_rate", 0),
            features.get("port", 0)
        ]]
        
        # We need a DataFrame with correct feature names to avoid Sklearn warnings
        df_features = pd.DataFrame(feature_vector, columns=[
            "avg_packet_size", "packet_frequency", "session_duration", "burst_rate", "port"
        ])
        
        prediction = str(self.model.predict(df_features)[0])
        probabilities = self.model.predict_proba(df_features)[0]
        classes = self.model.classes_
        
        prob_dist = {classes[i]: float(probabilities[i]) for i in range(len(classes))}
        
        return prediction, prob_dist

if __name__ == "__main__":
    predictor = EndpointPredictor()
    dummy_features = {
        "avg_packet_size": 150,
        "packet_frequency": 5.2,
        "session_duration": 350,
        "burst_rate": 12,
        "port": 443
    }
    pred, probs = predictor.predict(dummy_features)
    logger.info(f"Prediction: {pred}, Probabilities: {probs}")
