import pandas as pd
import numpy as np
import os
import joblib
from sklearn.preprocessing import StandardScaler

# Define your paths (Updated to match your terminal output)
DATA_DIR = '/home/yashwanth-r/Capstone/ML_Model/data/raw/5G_SatoriDataset/'
PROCESSED_DIR = './data/processed/'
MODELS_DIR = './models/scalers/'

def process_slice_data(slice_name, correlation_threshold=0.90):
    print(f"\n--- Processing {slice_name} ---")
    filepath = os.path.join(DATA_DIR, f"{slice_name}.csv")
    
    # 1. Load and Clean
    print("Loading dataset...")
    df = pd.read_csv(filepath)
    
    # Clean up column names by stripping leading/trailing whitespace
    df.columns = df.columns.str.strip()
    
    # NEW CLEANING LOGIC:
    # Drop columns that are 100% empty (e.g., trailing comma artifacts)
    df.dropna(axis=1, how='all', inplace=True)
    
    # Drop any "Unnamed" artifact columns
    df = df.loc[:, ~df.columns.str.contains('^Unnamed')]
    
    # Handle Inf values by converting them to NaN
    df.replace([np.inf, -np.inf], np.nan, inplace=True)
    
    # Fill numerical NaNs with 0 instead of dropping the entire row
    numeric_cols = df.select_dtypes(include=[np.number]).columns
    df[numeric_cols] = df[numeric_cols].fillna(0)
    
    # Only drop a row if the 'Label' itself is missing
    if 'Label' in df.columns:
        df.dropna(subset=['Label'], inplace=True)
    else:
        df.dropna(inplace=True)
        
    print(f"Data cleaned. Current shape: {df.shape}")
    
    # 2. Isolate Normal Traffic for Baseline Training
    if 'Label' in df.columns:
        df['Label'] = df['Label'].astype(str).str.strip()
        
        unique_labels = df['Label'].unique()
        print(f"Unique labels found in dataset: {unique_labels}")
        
        normal_df = df[df['Label'] == 'Benign'].copy()
        
        if normal_df.empty:
            print(f"CRITICAL ERROR: No rows matching 'Benign' found in {slice_name}.csv.")
            print("Cannot proceed to scaling with 0 rows. Skipping this slice.")
            return

        print(f"Isolated {normal_df.shape[0]} rows of Benign traffic for training.")
        
        columns_to_drop = ['Label', 'Timestamp', 'Flow ID', 'Src IP', 'Dst IP']
        existing_drops = [col for col in columns_to_drop if col in normal_df.columns]
        X = normal_df.drop(columns=existing_drops)
    else:
        print("Warning: 'Label' column not found. Processing all rows.")
        X = df.copy()

    # 3. Drop Zero-Variance Features (Features that never change)
    nunique = X.nunique()
    cols_to_drop = nunique[nunique == 1].index
    X.drop(columns=cols_to_drop, inplace=True)
    print(f"Dropped {len(cols_to_drop)} zero-variance features.")

    # 4. Correlation Matrix to drop highly correlated features
    print("Filtering out non-numeric columns...")
    X = X.select_dtypes(include=[np.number])
    print(f"Numeric features remaining: {X.shape[1]}")
    
    print("Calculating correlation matrix...")
    corr_matrix = X.corr().abs()
    upper = corr_matrix.where(np.triu(np.ones(corr_matrix.shape), k=1).astype(bool))
    
    to_drop_corr = [column for column in upper.columns if any(upper[column] > correlation_threshold)]
    X.drop(columns=to_drop_corr, inplace=True)
    print(f"Dropped {len(to_drop_corr)} highly correlated features (> {correlation_threshold}).")
    print(f"Remaining features for ML: {X.shape[1]}")

    # 5. Scale the Data
    print("Scaling features...")
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)
    X_scaled_df = pd.DataFrame(X_scaled, columns=X.columns)

    # 6. Save Artifacts
    os.makedirs(PROCESSED_DIR, exist_ok=True)
    os.makedirs(MODELS_DIR, exist_ok=True)
    
    processed_path = os.path.join(PROCESSED_DIR, f"{slice_name}_processed.csv")
    scaler_path = os.path.join(MODELS_DIR, f"{slice_name}_scaler.pkl")
    
    X_scaled_df.to_csv(processed_path, index=False)
    joblib.dump(scaler, scaler_path)
    print(f"Saved processed data to {processed_path}")
    print(f"Saved scaler to {scaler_path}")

if __name__ == "__main__":
    slices = ['eMBB', 'URLLC', 'mMTC']
    for s in slices:
        if os.path.exists(os.path.join(DATA_DIR, f"{s}.csv")):
            process_slice_data(s)
        else:
            print(f"File {s}.csv not found in {DATA_DIR}")