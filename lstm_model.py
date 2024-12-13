import numpy as np
import pandas as pd
import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import LSTM, Dense, Embedding, Dropout
from tensorflow.keras.preprocessing.sequence import pad_sequences
from sklearn.model_selection import train_test_split
import re
import os

# Step 1: Data Extraction
def extract_syscalls(log_file):
    with open(log_file, 'r') as file:
        data = file.read()
    match = re.search(r'Syscalls : \[(.*?)\]', data)
    if match:
        syscalls = list(map(int, match.group(1).split(',')))
        return syscalls
    return []

# Step 2: Preprocessing
def preprocess_data(log_files, labels):
    syscall_sequences = []
    for log_file in log_files:
        syscalls = extract_syscalls(log_file)
        if syscalls:
            syscall_sequences.append(syscalls)
    
    # Padding sequences to ensure they are of equal length
    max_len = max(len(seq) for seq in syscall_sequences)
    padded_sequences = pad_sequences(syscall_sequences, maxlen=max_len, padding='post', truncating='post')
    
    return np.array(padded_sequences), np.array(labels)

# Step 3: LSTM Model
def build_lstm_model(input_shape):
    model = Sequential()
    model.add(Embedding(input_dim=256, output_dim=128, input_length=input_shape[1]))
    model.add(LSTM(128, return_sequences=True))
    model.add(Dropout(0.2))
    model.add(LSTM(64))
    model.add(Dropout(0.2))
    model.add(Dense(1, activation='sigmoid'))
    model.compile(loss='binary_crossentropy', optimizer='adam', metrics=['accuracy'])
    return model

# Step 4: Training the Model
def train_model(log_files, labels):
    X, y = preprocess_data(log_files, labels)
    
    # Split the data into training and testing sets
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    model = build_lstm_model(X_train.shape)
    
    # Train the model
    model.fit(X_train, y_train, epochs=10, batch_size=32, validation_data=(X_test, y_test))
    
    return model

# Step 5: Prediction
def predict(log_file, model):
    syscalls = extract_syscalls(log_file)
    if not syscalls:
        return "No syscalls found in log file"
    
    # Padding the sequence
    max_len = model.input_shape[1]
    padded_sequence = pad_sequences([syscalls], maxlen=max_len, padding='post', truncating='post')
    
    # Predicting
    prediction = model.predict(padded_sequence)
    return "Dangerous" if prediction[0] > 0.5 else "Safe"

# Step 6: Main Logic
if __name__ == "__main__":
    # Sample log files and labels (1 for dangerous, 0 for safe)
    log_files = ['log_file1.txt', 'log_file2.txt', 'log_file3.txt']  # Add the actual paths
    labels = [1, 0, 0]  # Example labels

    # Train the model
    model = train_model(log_files, labels)

    # Test prediction on a new log file
    new_log_file = 'new_log_file.txt'  # Specify the path to the log file you want to classify
    result = predict(new_log_file, model)
    print(f"The log file is classified as: {result}")
