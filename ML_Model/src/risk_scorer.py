import pandas as pd
import numpy as np
import os
import joblib
import tensorflow as tf
import xgboost as xgb

# Define paths
MODELS_DIR = './models/saved_models/'
SCALERS_DIR = './models/scalers/'

class SecurityOrchestrator:
    def __init__(self, slice_name, lstm_threshold, time_steps=10):
        self.slice_name = slice_name
        self.time_steps = time_steps
        self.lstm_threshold = lstm_threshold
        
        print(f"Initializing Security Orchestrator for {slice_name}...")
        self._load_artifacts()

    def _load_artifacts(self):
        """Loads all 4 ML artifacts (Scaler, SVM, LSTM, XGBoost)."""
        scaler_path = os.path.join(SCALERS_DIR, f"{self.slice_name}_scaler.pkl")
        svm_path = os.path.join(MODELS_DIR, f"{self.slice_name}_ocsvm.pkl")
        lstm_path = os.path.join(MODELS_DIR, f"{self.slice_name}_lstm.keras")
        xgb_path = os.path.join(MODELS_DIR, f"{self.slice_name}_xgboost.json")
        
        try:
            self.scaler = joblib.load(scaler_path)
            self.svm_model = joblib.load(svm_path)
            self.lstm_model = tf.keras.models.load_model(lstm_path)
            
            # Load XGBoost
            self.xgb_model = xgb.XGBClassifier()
            self.xgb_model.load_model(xgb_path)
            
            print("Successfully loaded all ML artifacts (Frontline + Zero-Day).")
        except Exception as e:
            print(f"Failed to load artifacts: {e}")

    def evaluate_telemetry(self, raw_telemetry_window):
        """
        Evaluates a sliding window of live telemetry in real-time.
        raw_telemetry_window should be a DataFrame of shape (time_steps, features).
        """
        if len(raw_telemetry_window) != self.time_steps:
            print(f"Error: Expected {self.time_steps} time steps, got {len(raw_telemetry_window)}.")
            return

        print("\n--- INITIATING TELEMETRY SCAN ---")
        
        # -------------------------------------------------------------
        # LAYER 1: FRONTLINE SIGNATURE DETECTION (SUPERVISED - XGBOOST)
        # -------------------------------------------------------------
        # XGBoost doesn't need scaled data. We just pass the numeric features.
        numeric_window = raw_telemetry_window.select_dtypes(include=[np.number])
        
        # Check if any packet in this window matches a known attack signature
        xgb_preds = self.xgb_model.predict(numeric_window)
        if 1 in xgb_preds:
            print(">> ALERT: Known attack signature detected by XGBoost Classifier!")
            self._execute_policy(action_level="REACTIVE", reason="Known Threat Detected")
            return # Halt execution, threat confirmed

        print(">> XGBoost Cleared: No known signatures detected. Passing to Zero-Day engines...")

        # -------------------------------------------------------------
        # LAYER 2: ZERO-DAY ANOMALY DETECTION (UNSUPERVISED - SVM + LSTM)
        # -------------------------------------------------------------
        # Align features to what the scaler expects
        expected_features = self.scaler.feature_names_in_
        aligned_window = numeric_window[expected_features].copy()
        scaled_data = self.scaler.transform(aligned_window)
        
        # 2A. SVM Evaluation (Packet-Level Anomaly)
        svm_preds = self.svm_model.predict(scaled_data)
        anomaly_count = np.sum(svm_preds == -1)
        svm_risk = (anomaly_count / self.time_steps) * 100 

        # 2B. LSTM Evaluation (Flow-Level Temporal Anomaly)
        lstm_input = scaled_data.reshape(1, self.time_steps, scaled_data.shape[1])
        reconstruction = self.lstm_model.predict(lstm_input, verbose=0)
        
        mse = np.mean(np.power(lstm_input - reconstruction, 2))
        
        # Calculate Risk Score
        # If MSE exceeds our dynamically calculated 95th percentile threshold, risk is 100%
        lstm_risk = min((mse / self.lstm_threshold) * 100, 100) 
        
        # Combined Zero-Day Risk (Heavily weighted toward the LSTM)
        total_risk_score = (0.3 * svm_risk) + (0.7 * lstm_risk)

        print(f">> SVM Anomaly Ratio: {svm_risk:.1f}%")
        print(f">> LSTM Reconstruction MSE: {mse:.4f} (Threshold: {self.lstm_threshold:.4f})")
        print(f">> COMBINED ZERO-DAY RISK SCORE: {total_risk_score:.1f}/100")

        # Decide Action based on Zero-Day score
        if total_risk_score < 40:
            self._execute_policy(action_level="NONE", reason="Traffic within normal baseline")
        elif 40 <= total_risk_score < 80:
            self._execute_policy(action_level="PROACTIVE", reason="Anomalous behavior detected (Possible Zero-Day)")
        else:
            self._execute_policy(action_level="REACTIVE", reason="Severe baseline breach detected")

    def _execute_policy(self, action_level, reason):
        """Triggers the appropriate administrative response."""
        print("\n=== POLICY ENFORCEMENT DECISION ===")
        print(f"Reason: {reason}")
        
        if action_level == "NONE":
            print("ACTION: None. Status: LOW RISK. Continue monitoring.")
        elif action_level == "PROACTIVE":
            print("ACTION: PROACTIVE. Triggering Rate Limiting and requesting Re-authentication.")
        elif action_level == "REACTIVE":
            print("ACTION: REACTIVE CONTAINMENT. Revoking JWT Token, Isolating Slice, Restarting VNF.")
        print("===================================\n")

if __name__ == "__main__":
    os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'
    
    # Initialize the Orchestrator using the 95th percentile threshold we calculated earlier
    orchestrator = SecurityOrchestrator('eMBB', lstm_threshold=0.9177)
    
    # --- SIMULATION ---
    # Load the original raw dataset to test the pipeline
    raw_path = '/home/yashwanth-r/Capstone/ML_Model/data/raw/5G_SatoriDataset/eMBB.csv'
    if os.path.exists(raw_path):
        df = pd.read_csv(raw_path)
        df.columns = df.columns.str.strip()
        df.dropna(axis=1, how='all', inplace=True)
        df = df.loc[:, ~df.columns.str.contains('^Unnamed')]
        df.replace([np.inf, -np.inf], np.nan, inplace=True)
        numeric_cols = df.select_dtypes(include=[np.number]).columns
        df[numeric_cols] = df[numeric_cols].fillna(0)
        df.dropna(subset=['Label'], inplace=True)
        df['Label'] = df['Label'].astype(str).str.strip()

        print("\n[SIMULATION 1] Testing Benign Traffic Window...")
        benign_window = df[df['Label'] == 'Benign'].head(10).drop(columns=['Label', 'Timestamp', 'Flow ID', 'Src IP', 'Dst IP'], errors='ignore')
        orchestrator.evaluate_telemetry(benign_window)
        
        print("\n[SIMULATION 2] Testing Malicious Traffic Window...")
        malicious_window = df[df['Label'] == 'Malicious'].head(10).drop(columns=['Label', 'Timestamp', 'Flow ID', 'Src IP', 'Dst IP'], errors='ignore')
        if not malicious_window.empty:
            orchestrator.evaluate_telemetry(malicious_window)