import os
import json

import numpy as np
from keras.src.utils import pad_sequences, to_categorical
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from tensorflow.python.keras.layers import LSTMV1, Dropout, Dense
from tensorflow.python.keras.models import Sequential


class SyscallDetector:
    def __init__(self, dangerous_log_dir='./log/dangerous', safe_log_dir='./log/safe'):
        """
        Initialize the SyscallDetector with directories containing log files

        Args:
            dangerous_log_dir (str): Path to directory with dangerous log files
            safe_log_dir (str): Path to directory with safe log files
        """
        # Validate directories exist
        if not os.path.exists(dangerous_log_dir):
            raise ValueError(f"Dangerous log directory not found: {dangerous_log_dir}")
        if not os.path.exists(safe_log_dir):
            raise ValueError(f"Safe log directory not found: {safe_log_dir}")

        self.dangerous_log_dir = dangerous_log_dir
        self.safe_log_dir = safe_log_dir
        self.model = None
        self.label_encoder = LabelEncoder()

    def parse_log_file(self, file_path):
        """
        Parse a single log file and extract syscall numbers

        Args:
            file_path (str): Path to the log file

        Returns:
            list: List of syscall numbers
        """
        if not os.path.exists(file_path):
            print(f"Warning: File not found {file_path}")
            return []

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                log_content = f.read()

                # Try to extract syscall numbers from JSON section
                try:
                    syscall_section = log_content.split('System Calls: ')[1]
                    syscalls = json.loads(syscall_section)
                    return [call['syscall_number'] for call in syscalls]
                except:
                    # Fallback to extracting syscall numbers from log lines
                    syscalls = []
                    for line in log_content.split('\n'):
                        if '[INFO] Syscall number:' in line:
                            try:
                                syscall = int(line.split('Syscall number:')[1].strip())
                                syscalls.append(syscall)
                            except:
                                pass
                    return syscalls
        except Exception as e:
            print(f"Error parsing file {file_path}: {e}")
            return []

    def load_dataset(self):
        """
        Load log files from dangerous and safe directories

        Returns:
            tuple: (X data, y labels)
        """
        X, y = [], []

        # Load dangerous logs
        print(f"Loading from dangerous log directory: {self.dangerous_log_dir}")
        for filename in os.listdir(self.dangerous_log_dir):
            if filename.endswith('.log'):
                file_path = os.path.join(self.dangerous_log_dir, filename)
                syscalls = self.parse_log_file(file_path)
                if syscalls:
                    X.append(syscalls)
                    y.append(1)  # Dangerous

        # Load safe logs
        print(f"Loading from safe log directory: {self.safe_log_dir}")
        for filename in os.listdir(self.safe_log_dir):
            if filename.endswith('.log'):
                file_path = os.path.join(self.safe_log_dir, filename)
                syscalls = self.parse_log_file(file_path)
                if syscalls:
                    X.append(syscalls)
                    y.append(0)  # Safe

        return X, y

    def preprocess_data(self, X, y, max_len=100):
        """
        Preprocess the data for LSTM

        Args:
            X (list): List of syscall sequences
            y (list): Labels
            max_len (int): Maximum sequence length

        Returns:
            tuple: Preprocessed (X_train, X_test, y_train, y_test)
        """
        # Pad sequences to uniform length
        X_padded = pad_sequences(X, maxlen=max_len, padding='post', truncating='post')

        # Convert labels to categorical
        y_categorical = to_categorical(y)

        # Split the data
        X_train, X_test, y_train, y_test = train_test_split(
            X_padded, y_categorical, test_size=0.2, random_state=42
        )

        return X_train, X_test, y_train, y_test

    def build_lstm_model(self, input_shape, num_classes):
        """
        Build LSTM model for syscall sequence classification

        Args:
            input_shape (tuple): Shape of input data
            num_classes (int): Number of output classes

        Returns:
            tf.keras.Model: Compiled LSTM model
        """
        model = Sequential([
            LSTMV1(64, input_shape=input_shape, return_sequences=True),
            Dropout(0.3),
            LSTMV1(32),
            Dropout(0.3),
            Dense(16, activation='relu'),
            Dense(num_classes, activation='softmax')
        ])

        model.compile(
            optimizer='adam',
            loss='categorical_crossentropy',
            metrics=['accuracy']
        )

        return model

    def train(self, epochs=50, batch_size=32):
        """
        Train the LSTM model

        Args:
            epochs (int): Number of training epochs
            batch_size (int): Training batch size

        Returns:
            History object from model training
        """
        # Load and preprocess data
        X, y = self.load_dataset()

        # Check if we have enough data
        if len(X) == 0:
            raise ValueError("No log files found in the specified directories")

        X_train, X_test, y_train, y_test = self.preprocess_data(X, y)

        # Build model
        input_shape = (X_train.shape[1], 1)
        num_classes = y_train.shape[1]

        self.model = self.build_lstm_model(input_shape, num_classes)

        # Reshape input for LSTM (add feature dimension)
        X_train_reshaped = X_train.reshape(X_train.shape[0], X_train.shape[1], 1)
        X_test_reshaped = X_test.reshape(X_test.shape[0], X_test.shape[1], 1)

        # Train the model
        history = self.model.fit(
            X_train_reshaped, y_train,
            validation_data=(X_test_reshaped, y_test),
            epochs=epochs,
            batch_size=batch_size,
            verbose=1
        )

        return history

    def predict(self, log_file_path):
        """
        Predict if a log file is dangerous

        Args:
            log_file_path (str): Path to the log file to predict

        Returns:
            tuple: (prediction, probability)
        """
        if self.model is None:
            raise ValueError("Model must be trained first")

        # Parse syscalls from the input log file
        syscalls = self.parse_log_file(log_file_path)

        if not syscalls:
            raise ValueError("No syscalls found in the log file")

        # Pad the sequence
        X_input = pad_sequences([syscalls], maxlen=100, padding='post', truncating='post')
        X_input_reshaped = X_input.reshape(X_input.shape[0], X_input.shape[1], 1)

        # Predict
        prediction = self.model.predict(X_input_reshaped)

        # Get the class with highest probability
        predicted_class = np.argmax(prediction, axis=1)[0]
        prediction_prob = prediction[0][predicted_class]

        return predicted_class, prediction_prob


def main():
    """
    Main function to demonstrate usage of SyscallDetector
    """
    # Initialize and train the model
    print("Starting main function ------> \n")
    try:
        detector = SyscallDetector()

        # Train the model
        print("Training the model...")
        history = detector.train(epochs=10)  # Reduced epochs for quicker testing

        # Save the model
        print("Saving the model...")
        detector.model.save('syscall_detection_lstm_model.h5')

        # Example prediction (make sure to replace with an actual log file path)
        test_log_path = './js1.js_20241207_033645.log'
        print(f"Predicting for log file: {test_log_path}")

        # Example prediction (commented out to prevent errors)
        # prediction, probability = detector.predict(test_log_path)
        # print(f"Prediction: {'Dangerous' if prediction == 1 else 'Safe'}")
        # print(f"Confidence: {probability * 100:.2f}%")

    except Exception as e:
        print(f"An error occurred: {e}")


if __name__ == '__main__':
    main()