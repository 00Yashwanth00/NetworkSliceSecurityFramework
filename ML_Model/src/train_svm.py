import pandas as pd
import os
import joblib
from sklearn.svm import OneClassSVM

PROCESSED_DIR = './data/processed/'
MODELS_DIR = './models/saved_models/'

def train_ocsvm(slice_name, nu=0.01):
    """
    nu: An upper bound on the fraction of training errors and a lower bound of the fraction of support vectors.
    Since we trained on purely 'Benign' data, we set this low (1%).
    """
    print(f"\n--- Training One-Class SVM for {slice_name} ---")
    data_path = os.path.join(PROCESSED_DIR, f"{slice_name}_processed.csv")
    
    if not os.path.exists(data_path):
        print(f"Error: Processed data not found at {data_path}")
        return

    print("Loading scaled baseline data...")
    X_train = pd.read_csv(data_path)

    # Initialize and Train the One-Class SVM
    # RBF (Radial Basis Function) kernel is highly effective for non-linear network data
    print("Training model... (Optimizing Lagrangian Dual)")
    model = OneClassSVM(kernel='rbf', gamma='scale', nu=nu)
    model.fit(X_train)
    print("Training complete!")

    os.makedirs(MODELS_DIR, exist_ok=True)
    model_path = os.path.join(MODELS_DIR, f"{slice_name}_ocsvm.pkl")
    joblib.dump(model, model_path)
    print(f"Saved model to {model_path}")

if __name__ == "__main__":
    for s in ['eMBB', 'URLLC', 'mMTC']:
        train_ocsvm(s)