import pandas as pd
import numpy as np
import os
import joblib
import xgboost as xgb
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix

# Define paths
DATA_DIR = '/home/yashwanth-r/Capstone/ML_Model/data/raw/5G_SatoriDataset/'
MODELS_DIR = './models/saved_models/'

def train_xgboost_slice(slice_name):
    print(f"\n========================================")
    print(f"  TRAINING XGBOOST FOR: {slice_name}")
    print(f"========================================\n")
    
    filepath = os.path.join(DATA_DIR, f"{slice_name}.csv")
    if not os.path.exists(filepath):
        print(f"Error: Raw dataset not found at {filepath}")
        return

    # 1. Load and Clean the Mixed Dataset
    print("Loading mixed dataset...")
    df = pd.read_csv(filepath)
    df.columns = df.columns.str.strip()
    df.dropna(axis=1, how='all', inplace=True)
    df = df.loc[:, ~df.columns.str.contains('^Unnamed')]
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    
    numeric_cols = df.select_dtypes(include=[np.number]).columns
    df[numeric_cols] = df[numeric_cols].fillna(0)
    df.dropna(subset=['Label'], inplace=True)
    df['Label'] = df['Label'].astype(str).str.strip()

    # 2. Prepare Labels (1 = Malicious, 0 = Benign)
    y = np.where(df['Label'] == 'Malicious', 1, 0)
    
    # 3. Prepare Features
    columns_to_drop = ['Label', 'Timestamp', 'Flow ID', 'Src IP', 'Dst IP']
    existing_drops = [col for col in columns_to_drop if col in df.columns]
    X_raw = df.drop(columns=existing_drops)
    
    # Filter to numeric only (XGBoost handles unscaled data perfectly)
    X = X_raw.select_dtypes(include=[np.number])
    
    # Note: We do NOT need to drop highly correlated features or scale the data 
    # for XGBoost. Decision tree ensembles are completely immune to feature 
    # scaling issues and naturally ignore redundant features!

    # 4. Train/Test Split (80% Training, 20% Testing)
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    print(f"Training shapes -> X: {X_train.shape}, y: {y_train.shape}")

    # 5. Initialize and Train XGBoost
    print("Training XGBoost Classifier...")
    # scale_pos_weight helps if the dataset has vastly more normal traffic than attack traffic
    model = xgb.XGBClassifier(
        n_estimators=100,
        learning_rate=0.1,
        max_depth=5,
        random_state=42,
        eval_metric='logloss',
        n_jobs=-1
    )
    
    model.fit(X_train, y_train)
    print("Training complete!")

    # 6. Evaluate the Model instantly on the 20% test holdout
    print("\n--- Evaluating XGBoost on 20% Test Set ---")
    y_pred = model.predict(X_test)
    
    print("\nConfusion Matrix:")
    print(confusion_matrix(y_test, y_pred))
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred, target_names=['Benign', 'Malicious']))

    # 7. Save the Model
    os.makedirs(MODELS_DIR, exist_ok=True)
    # XGBoost has its own optimized JSON format for saving
    model_path = os.path.join(MODELS_DIR, f"{slice_name}_xgboost.json")
    model.save_model(model_path)
    print(f"\nSaved XGBoost model to {model_path}")

if __name__ == "__main__":
    # You may need to run `pip install xgboost` in your virtual environment first
    slices = ['eMBB', 'URLLC', 'mMTC']
    for s in slices:
        train_xgboost_slice(s)