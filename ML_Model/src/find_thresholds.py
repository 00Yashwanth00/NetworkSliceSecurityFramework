import pandas as pd
import numpy as np
import os
import tensorflow as tf
import matplotlib.pyplot as plt

# Define paths
PROCESSED_DIR = './data/processed/'
MODELS_DIR = './models/saved_models/'
PLOTS_DIR = './models/plots/'

def find_and_plot_thresholds(slice_name, time_steps=10):
    print(f"\n========================================")
    print(f"  CALCULATING THRESHOLDS FOR: {slice_name}")
    print(f"========================================\n")
    
    data_path = os.path.join(PROCESSED_DIR, f"{slice_name}_processed.csv")
    lstm_path = os.path.join(MODELS_DIR, f"{slice_name}_lstm.keras")

    if not os.path.exists(data_path) or not os.path.exists(lstm_path):
        print(f"Error: Missing data or model for {slice_name}.")
        return

    # 1. Load the purely Benign data we used for training
    print("Loading scaled benign training data...")
    df = pd.read_csv(data_path)
    X_scaled = df.values

    # 2. Recreate the sliding windows
    print("Recreating sequences...")
    X_lstm = []
    for i in range(len(X_scaled) - time_steps):
        X_lstm.append(X_scaled[i : i + time_steps])
    X_lstm = np.array(X_lstm)

    # 3. Predict to get reconstruction errors
    print("Running data through LSTM to calculate baseline errors...")
    model = tf.keras.models.load_model(lstm_path)
    reconstructions = model.predict(X_lstm, verbose=0)

    # Calculate Mean Squared Error for every normal sequence
    mse = np.mean(np.power(X_lstm - reconstructions, 2), axis=(1, 2))

    # 4. Calculate Percentiles
    threshold_95 = np.percentile(mse, 95)
    threshold_99 = np.percentile(mse, 99)

    print("\n--- RESULTS ---")
    print(f"Maximum 'Normal' Error observed: {np.max(mse):.4f}")
    print(f"Recommended 95th Percentile Threshold: {threshold_95:.4f}")
    print(f"Recommended 99th Percentile Threshold: {threshold_99:.4f}")

    # 5. Plot the Distribution
    os.makedirs(PLOTS_DIR, exist_ok=True)
    plt.figure(figsize=(10, 6))
    
    # Histogram of normal errors
    plt.hist(mse, bins=50, alpha=0.75, color='#4A90E2', label='Benign MSE Distribution')
    
    # Threshold lines
    plt.axvline(threshold_95, color='orange', linestyle='dashed', linewidth=2, 
                label=f'95th Pctl: {threshold_95:.4f}')
    plt.axvline(threshold_99, color='red', linestyle='dashed', linewidth=2, 
                label=f'99th Pctl: {threshold_99:.4f}')
    
    plt.title(f'{slice_name} - LSTM Reconstruction Error (Benign Traffic)')
    plt.xlabel('Mean Squared Error (MSE)')
    plt.ylabel('Number of Sequences')
    plt.legend()
    plt.grid(True, alpha=0.3)

    plot_path = os.path.join(PLOTS_DIR, f'{slice_name}_threshold_distribution.png')
    plt.savefig(plot_path)
    print(f"\nSaved visual distribution plot to: {plot_path}")
    plt.close()

if __name__ == "__main__":
    os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'
    
    slices = ['eMBB', 'URLLC', 'mMTC']
    for s in slices:
        find_and_plot_thresholds(s)