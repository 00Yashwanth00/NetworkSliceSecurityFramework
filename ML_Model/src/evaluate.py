import pandas as pd
import numpy as np
import os
import joblib
import tensorflow as tf
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score
from sklearn.metrics import mean_squared_error

# Define paths
DATA_DIR = '/home/yashwanth-r/Capstone/NetworkSliceSecurityFramework/ML_Model/data/raw/5G_SatoriDataset/'
MODELS_DIR = './models/saved_models/'
SCALERS_DIR = './models/scalers/'

def evaluate_slice(slice_name, lstm_threshold=0.5):
    print(f"\n========================================")
    print(f"  EVALUATING MODELS FOR: {slice_name}")
    print(f"========================================\n")
    
    filepath = os.path.join(DATA_DIR, f"{slice_name}.csv")
    if not os.path.exists(filepath):
        print(f"Error: Raw dataset not found at {filepath}")
        return

    # 1. Load the Mixed Dataset (Benign + Malicious)
    print("Loading mixed testing dataset...")
    df = pd.read_csv(filepath)
    df.columns = df.columns.str.strip()
    df.dropna(axis=1, how='all', inplace=True)
    df = df.loc[:, ~df.columns.str.contains('^Unnamed')]
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    numeric_cols = df.select_dtypes(include=[np.number]).columns
    df[numeric_cols] = df[numeric_cols].fillna(0)
    df.dropna(subset=['Label'], inplace=True)
    df['Label'] = df['Label'].astype(str).str.strip()

    # 2. Prepare Ground Truth Labels
    # For anomaly detection metrics: 1 = Anomaly (Malicious), 0 = Normal (Benign)
    y_true = np.where(df['Label'] == 'Malicious', 1, 0)
    
    # 3. Clean and Scale Features
    print("Loading scaler...")
    scaler_path = os.path.join(SCALERS_DIR, f"{slice_name}_scaler.pkl")
    scaler = joblib.load(scaler_path)
    
    # Get the exact features the scaler expects (from training)
    expected_features = scaler.feature_names_in_
    
    # Check if any expected features are somehow missing from the test dataset
    missing_features = [f for f in expected_features if f not in df.columns]
    if missing_features:
        print(f"Warning: Test data is missing expected features: {missing_features}")
        # Fill missing features with 0 so the model doesn't crash
        for f in missing_features:
            df[f] = 0
            
    # Filter the raw data to match the EXACT columns and order the scaler expects
    X_raw = df[expected_features].copy()

    # Scale the data
    try:
        X_scaled = scaler.transform(X_raw)
        print(f"Successfully aligned and scaled {X_scaled.shape[1]} features.")
    except Exception as e:
        print(f"Scaling failed: {e}")
        return

    # ---------------------------------------------------------
    # EVALUATE ONE-CLASS SVM
    # ---------------------------------------------------------
    print("\n--- Evaluating One-Class SVM ---")
    svm_path = os.path.join(MODELS_DIR, f"{slice_name}_ocsvm.pkl")
    svm_model = joblib.load(svm_path)
    
    # SVM outputs -1 for anomalies, 1 for inliers. 
    # Convert to match our ground truth (1 = Anomaly, 0 = Normal)
    svm_raw_preds = svm_model.predict(X_scaled)
    y_pred_svm = np.where(svm_raw_preds == -1, 1, 0)
    
    print("\nSVM Confusion Matrix:")
    print(confusion_matrix(y_true, y_pred_svm))
    print("\nSVM Classification Report:")
    print(classification_report(y_true, y_pred_svm, target_names=['Benign', 'Malicious']))

    # ---------------------------------------------------------
    # EVALUATE LSTM AUTOENCODER
    # ---------------------------------------------------------
    print("\n--- Evaluating LSTM Autoencoder ---")
    lstm_path = os.path.join(MODELS_DIR, f"{slice_name}_lstm.keras")
    
    try:
        lstm_model = tf.keras.models.load_model(lstm_path)
        time_steps = 10
        
        # Recreate the sliding windows for the test data
        X_lstm = []
        y_true_lstm = []
        
        for i in range(len(X_scaled) - time_steps):
            X_lstm.append(X_scaled[i : i + time_steps])
            # The label for the window is the label of the last event in that window
            y_true_lstm.append(y_true[i + time_steps - 1])
            
        X_lstm = np.array(X_lstm)
        y_true_lstm = np.array(y_true_lstm)
        
        # Predict reconstructions
        reconstructions = lstm_model.predict(X_lstm, verbose=0)
        
        # Calculate MSE across features and time_steps to get one score per window
        mse = np.mean(np.power(X_lstm - reconstructions, 2), axis=(1, 2))
        
        # If MSE is higher than our threshold, flag as anomaly (1)
        y_pred_lstm = np.where(mse > lstm_threshold, 1, 0)
        
        print("\nLSTM Confusion Matrix:")
        print(confusion_matrix(y_true_lstm, y_pred_lstm))
        print("\nLSTM Classification Report:")
        print(classification_report(y_true_lstm, y_pred_lstm, target_names=['Benign', 'Malicious']))
        
    except Exception as e:
        print(f"LSTM Evaluation failed: {e}")

if __name__ == "__main__":
    os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'
    
    slices = ['eMBB', 'URLLC', 'mMTC']
    
    for s in slices:
        if s == 'eMBB':
            # 95th Percentile for eMBB
            evaluate_slice(s, lstm_threshold=0.9177)
        elif s == 'URLLC':
            # 95th Percentile for URLLC
            evaluate_slice(s, lstm_threshold=2.8485)
        elif s == 'mMTC':
            # 95th Percentile for mMTC
            evaluate_slice(s, lstm_threshold=1.1438)