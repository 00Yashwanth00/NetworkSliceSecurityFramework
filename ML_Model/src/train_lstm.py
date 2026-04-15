import pandas as pd
import numpy as np
import os
import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import LSTM, Dense, RepeatVector, TimeDistributed, Input
from tensorflow.keras.callbacks import EarlyStopping

# Define paths
PROCESSED_DIR = './data/processed/'
MODELS_DIR = './models/saved_models/'

def create_sequences(X, time_steps):
    """
    Transforms 2D tabular data into 3D sequence data for the LSTM.
    Uses a sliding window approach.
    """
    Xs = []
    # Slide the window across the dataset
    for i in range(len(X) - time_steps):
        Xs.append(X.iloc[i:(i + time_steps)].values)
    return np.array(Xs)

def build_lstm_autoencoder(time_steps, num_features):
    """
    Builds the Encoder-Decoder LSTM architecture.
    """
    model = Sequential([
        Input(shape=(time_steps, num_features)),
        
        # ENCODER: Compresses the sequence representation
        LSTM(32, activation='tanh', return_sequences=False),
        
        # BRIDGE: Repeats the compressed vector for the decoder
        RepeatVector(time_steps),
        
        # DECODER: Reconstructs the sequence
        LSTM(32, activation='tanh', return_sequences=True),
        
        # OUTPUT LAYER: Rebuilds back to the exact number of features
        TimeDistributed(Dense(num_features))
    ])
    
    # Adam optimizer is highly efficient for autoencoders (Unit 2 mapping)
    model.compile(optimizer='adam', loss='mse')
    return model

def train_lstm_for_slice(slice_name, time_steps=10):
    print(f"\n--- Training LSTM Autoencoder for {slice_name} ---")
    data_path = os.path.join(PROCESSED_DIR, f"{slice_name}_processed.csv")
    
    if not os.path.exists(data_path):
        print(f"Error: Processed data not found at {data_path}. Skipping.")
        return

    print("Loading scaled baseline data...")
    df = pd.read_csv(data_path)
    
    num_features = df.shape[1]
    print(f"Original shape: {df.shape}")

    # 1. Generate Sequences
    print(f"Generating sliding windows (Time Steps = {time_steps})...")
    X_seq = create_sequences(df, time_steps)
    print(f"Sequence data shape: {X_seq.shape} (Samples, Time Steps, Features)")

    # 2. Build the Model
    model = build_lstm_autoencoder(time_steps, num_features)
    
    # Early stopping prevents overfitting if the model stops improving (Unit 1 mapping)
    early_stop = EarlyStopping(monitor='val_loss', patience=3, restore_best_weights=True)

    # 3. Train the Model
    # We use X_seq as both input and target (autoencoder principle)
    print("Training model... (This will take a few minutes)")
    history = model.fit(
        X_seq, X_seq,
        epochs=20,
        batch_size=64,
        validation_split=0.1,
        callbacks=[early_stop],
        verbose=1
    )
    print("Training complete!")

    # 4. Save the Model
    os.makedirs(MODELS_DIR, exist_ok=True)
    # Keras recommended save format
    model_path = os.path.join(MODELS_DIR, f"{slice_name}_lstm.keras") 
    model.save(model_path)
    print(f"Successfully saved LSTM to {model_path}")

if __name__ == "__main__":
    # Disable overly verbose TensorFlow logging in Ubuntu terminal
    os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2' 
    
    slices = ['eMBB', 'URLLC', 'mMTC']
    for s in slices:
        train_lstm_for_slice(s, time_steps=10)