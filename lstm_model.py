
import os
import re
import numpy as np
import json
import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import Dataset, DataLoader
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import ParameterGrid
import copy
from collections import Counter
from run_docker import SandboxRunner


class HyperparameterTuner:
    def __init__(self, analyzer):
        self.analyzer = analyzer
        
    def tune_parameters(self, X, y):
        param_grid = {
            'embedding_dim': [32, 64, 128],
            'lstm_units': [64, 128, 256],
            'batch_size': [16, 32, 64],
            'learning_rate': [0.01, 0.001, 0.0001],
            'dropout_rate': [0.3, 0.5, 0.7]
        }
        
        best_score = 0
        best_params = None
        
        for params in ParameterGrid(param_grid):
            # Update model parameters
            self.analyzer.embedding_dim = params['embedding_dim']
            self.analyzer.lstm_units = params['lstm_units']
            
            # Create new model with updated parameters
            vocab_size = len(self.analyzer.tokenizer)
            self.analyzer.model = SyscallLSTMClassifier(
                vocab_size=vocab_size,
                embedding_dim=params['embedding_dim'],
                lstm_units=params['lstm_units']
            )
            
            # Modify dropout rates
            self.analyzer.model.dropout1 = nn.Dropout(params['dropout_rate'])
            self.analyzer.model.dropout2 = nn.Dropout(params['dropout_rate'])
            
            # Train with current parameters
            X_train, X_val, y_train, y_val = train_test_split(X, y, test_size=0.2)
            self.analyzer.train(
                X_train, 
                y_train,
                batch_size=params['batch_size'],
                learning_rate=params['learning_rate'],
                epochs=30  # Reduced epochs for faster tuning
            )
            
            # Evaluate on validation set
            score = self.evaluate_model(X_val, y_val)
            
            if score > best_score:
                best_score = score
                best_params = params
                
            print(f"Params: {params}")
            print(f"Score: {score}")
            
        return best_params, best_score
    
    def evaluate_model(self, X_val, y_val):
        self.analyzer.model.eval()
        val_dataset = SyscallDataset(X_val, y_val)
        val_loader = DataLoader(val_dataset, batch_size=32)
        
        correct = 0
        total = 0
        
        with torch.no_grad():
            for batch_X, batch_y in val_loader:
                outputs = self.analyzer.model(batch_X)
                predicted = (outputs > 0.5).float()
                total += batch_y.size(0)
                correct += (predicted == batch_y).sum().item()
                
        return correct / total

class SyscallDataset(Dataset):
    def __init__(self, sequences, labels):
        self.sequences = torch.tensor(sequences, dtype=torch.long)
        self.labels = torch.tensor(labels, dtype=torch.float32)

    def __len__(self):
        return len(self.sequences)

    def __getitem__(self, idx):
        return self.sequences[idx], self.labels[idx]


class SyscallLSTMClassifier(nn.Module):
    def __init__(
        self, vocab_size, max_sequence_length=100000, embedding_dim=64, lstm_units=128
    ):
        super(SyscallLSTMClassifier, self).__init__()

        self.max_sequence_length = max_sequence_length
        self.embedding_dim = embedding_dim
        self.lstm_units = lstm_units

        self.embedding = nn.Embedding(vocab_size + 1, embedding_dim, padding_idx=0)
        self.lstm1 = nn.LSTM(
            embedding_dim, lstm_units, batch_first=True, bidirectional=True
        )
        self.dropout1 = nn.Dropout(0.5)
        self.lstm2 = nn.LSTM(lstm_units * 2, 64, batch_first=True)
        self.dropout2 = nn.Dropout(0.5)
        self.fc1 = nn.Linear(64, 32)
        self.relu = nn.ReLU()
        self.fc2 = nn.Linear(32, 1)
        self.sigmoid = nn.Sigmoid()

    def forward(self, x):
        x = self.embedding(x)
        x, _ = self.lstm1(x)
        x = self.dropout1(x)
        x, _ = self.lstm2(x)
        x = self.dropout2(x)
        x, _ = torch.max(x, dim=1)
        x = self.fc1(x)
        x = self.relu(x)
        x = self.fc2(x)
        x = self.sigmoid(x)
        return x


class SyscallAnalyzer:
    
    def __init__(self, max_sequence_length=100, embedding_dim=64, lstm_units=128, file_path = "/usr/src/linux-source-6.8.0/arch/x86/entry/syscalls/syscall_64.tbl"):
        self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        print(f"Using device: {self.device}")

        self.max_sequence_length = max_sequence_length
        self.embedding_dim = embedding_dim
        self.lstm_units = lstm_units
        self.tokenizer = {}
        self.reverse_tokenizer = {}
        self.label_encoder = LabelEncoder()
        self.model = None

        syscall_map = {}
        # Open the file and process it line by line
        with open(file_path, 'r') as file:
            for line in file:
                # Skip empty lines and comments
                if not line.strip() or line.strip().startswith('#'):
                    continue
            
                # Split the line by whitespace
                parts = re.split(r'\s+', line.strip())
            
                # Ensure the line has enough parts: <number> <abi> <name> <entry>
                if len(parts) >= 4:
                    syscall_number = parts[0]
                    syscall_name = parts[2]
                
                    # Add the syscall number and name to the dictionary
                    syscall_map[int(syscall_number)] = syscall_name

        self.syscall_behaviors = syscall_map

    def analyze_syscall_sequence(self,prediction, syscall_sequence):
        """Phân tích chuỗi syscall và trả về báo cáo đơn giản"""
        print(f"Kết quả dự đoán: {prediction}")
        syscalls = syscall_sequence.split(',')
        
        # Đếm số lần xuất hiện của mỗi syscall
        syscall_counts = Counter(syscalls)
        
        # Tạo báo cáo đơn giản
        report = {
            'prediction':prediction,
            'syscallFrequencies': {
                self.syscall_behaviors.get(int(syscall), f'Syscall {syscall}'): count
                for syscall, count in syscall_counts.items()
                if count > 5  # Chỉ hiển thị các syscall xuất hiện nhiều hơn 5 lần
            },
            'totalSyscalls': len(syscalls)
        }
        
        return report

    def augment_sequence(self, sequence):
        """Augment một syscall sequence"""
        augmented = sequence.copy()

        # Thêm noise ngẫu nhiên
        if np.random.random() < 0.1:
            noise = np.random.choice(list(self.tokenizer.keys()))
            insert_idx = np.random.randint(0, len(augmented))
            augmented.insert(insert_idx, noise)

        # Hoán đổi vị trí của 2 syscall ngẫu nhiên
        if np.random.random() < 0.1 and len(augmented) > 1:
            idx1, idx2 = np.random.choice(len(augmented), 2, replace=False)
            augmented[idx1], augmented[idx2] = augmented[idx2], augmented[idx1]

        return augmented


    def prepare_data(self, log_directory):
        X = []
        y = []

        subdirs = ["safe", "dangerous"]

        # Đọc dữ liệu
        for label in subdirs:
            current_dir = os.path.join(log_directory, label)

            if not os.path.exists(current_dir):
                print(f"Thư mục {current_dir} không tồn tại")
                continue

            log_files = [f for f in os.listdir(current_dir) if f.endswith(".log")]
            print(f"Tìm thấy {len(log_files)} tệp log trong thư mục {label}")

            for filename in log_files:
                syscalls = []
                filepath = os.path.join(current_dir, filename)

                try:
                    with open(filepath, "r") as f:
                        for line in f:
                            match = re.search(r"Syscall number:\s*(\d+)", line)
                            if match:
                                syscalls_str = match.group(1)
                                syscalls.append(syscalls_str)
                    if syscalls:
                        X.append(syscalls)
                        y.append(label)            
                except Exception as e:
                    print(f"Lỗi khi đọc tệp {filename}: {e}")

        print(
            f"Số lượng mẫu ban đầu - safe: {y.count('safe')}, dangerous: {y.count('dangerous')}"
        )

        # Khởi tạo tokenizer trước khi augment
        unique_syscalls = set(syscall for sequence in X for syscall in sequence)
        self.tokenizer = {syscall: i + 1 for i, syscall in enumerate(unique_syscalls)}
        self.reverse_tokenizer = {
            i + 1: syscall for i, syscall in enumerate(unique_syscalls)
        }

        # Thực hiện oversampling
        class_counts = Counter(y)
        max_samples = max(class_counts.values())

        X_oversampled = []
        y_oversampled = []

        for label in class_counts:
            indices = [i for i, y_label in enumerate(y) if y_label == label]
            n_samples = max_samples - len(indices)

            X_oversampled.extend([X[i] for i in indices])
            y_oversampled.extend([y[i] for i in indices])

            if n_samples > 0:
                augmented_indices = np.random.choice(indices, n_samples)
                for idx in augmented_indices:
                    aug_sequence = self.augment_sequence(X[idx])
                    X_oversampled.append(aug_sequence)
                    y_oversampled.append(y[idx])

        print(
            f"Số lượng mẫu sau oversampling - safe: {y_oversampled.count(
            'safe')}, dangerous: {y_oversampled.count('dangerous')}"
        )

        return X_oversampled, y_oversampled

    def preprocess_data(self, X, y):
        # Create tokenizer
        unique_syscalls = set(syscall for sequence in X for syscall in sequence)
        self.tokenizer = {syscall: i + 1 for i, syscall in enumerate(unique_syscalls)}
        self.reverse_tokenizer = {
            i + 1: syscall for i, syscall in enumerate(unique_syscalls)
        }

        # Convert syscall sequences to integer sequences
        X_seq = []
        for sequence in X:
            seq = [self.tokenizer.get(syscall, 0) for syscall in sequence]
            X_seq.append(seq)

        # Pad sequences
        X_padded = self._pad_sequences(X_seq)

        # Encode labels
        y_encoded = self.label_encoder.fit_transform(y)

        return X_padded, y_encoded

    def _pad_sequences(self, sequences):
        padded = np.zeros((len(sequences), self.max_sequence_length), dtype=int)
        for i, seq in enumerate(sequences):
            length = min(len(seq), self.max_sequence_length)
            padded[i, :length] = seq[-length:]
        return padded

    def train(self, X, y, test_size=0.2, epochs=50, batch_size=32, learning_rate=0.001):
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=test_size, stratify=y, random_state=42
        )

        print("Số lượng mỗi lớp ở tập train:", np.bincount(y_train))
        print("Số lượng mỗi lớp ở tập test:", np.bincount(y_test))

        # Create datasets and dataloaders
        train_dataset = SyscallDataset(X_train, y_train)
        test_dataset = SyscallDataset(X_test, y_test)

        train_loader = DataLoader(train_dataset, batch_size=batch_size, shuffle=True)
        test_loader = DataLoader(test_dataset, batch_size=batch_size)

        # Initialize model
        vocab_size = len(self.tokenizer)
        self.model = SyscallLSTMClassifier(
            vocab_size, self.max_sequence_length, self.embedding_dim, self.lstm_units
        ).to(self.device)

        # Loss and optimizer
        criterion = nn.BCELoss()
        optimizer = optim.Adam(self.model.parameters(), lr=learning_rate)

        # Early stopping parameters
        best_val_loss = float("inf")
        patience = 5
        patience_counter = 0
        best_model = None

        # Training loop
        for epoch in range(epochs):
            self.model.train()
            total_loss = 0

            for batch_X, batch_y in train_loader:
                batch_X = batch_X.to(self.device)
                batch_y = batch_y.unsqueeze(1).to(self.device)

                optimizer.zero_grad()
                outputs = self.model(batch_X)
                loss = criterion(outputs, batch_y)

                loss.backward()
                optimizer.step()

                total_loss += loss.item()

            # Validation
            self.model.eval()
            val_loss = 0
            all_preds = []
            all_labels = []

            with torch.no_grad():
                for batch_X, batch_y in test_loader:
                    batch_X = batch_X.to(self.device)
                    batch_y = batch_y.unsqueeze(1).to(self.device)

                    outputs = self.model(batch_X)
                    val_loss += criterion(outputs, batch_y).item()

                    preds = (outputs > 0.5).float()
                    all_preds.extend(preds.cpu().numpy())
                    all_labels.extend(batch_y.cpu().numpy())

            avg_val_loss = val_loss / len(test_loader)

            print(
                f"Epoch [{epoch+1}/{epochs}], "
                f"Train Loss: {total_loss/len(train_loader):.4f}, "
                f"Val Loss: {avg_val_loss:.4f}"
            )

            # Early stopping
            if avg_val_loss < best_val_loss:
                best_val_loss = avg_val_loss
                patience_counter = 0
                best_model = copy.deepcopy(self.model.state_dict())
            else:
                patience_counter += 1
                if patience_counter >= patience:
                    print("Early stopping triggered")
                    break

        # Load best model
        if best_model is not None:
            self.model.load_state_dict(best_model)

        # Final evaluation
        print("\nClassification Report:")
        print(
            classification_report(
                all_labels, all_preds, target_names=["safe", "dangerous"]
            )
        )

    def save_model(self, model_path="syscall_lstm_model"):
        os.makedirs(model_path, exist_ok=True)
        torch.save(self.model.state_dict(), os.path.join(model_path, "model.pth"))
        with open(os.path.join(model_path, "tokenizer.json"), "w") as f:
            json.dump(self.tokenizer, f)
        np.save(
            os.path.join(model_path, "label_classes.npy"), self.label_encoder.classes_
        )

    def predict(self, syscall_sequence):
        # Convert syscall sequence to padded sequence
        seq = syscall_sequence.split(",")
        seq = [self.tokenizer.get(syscall.strip(), 0) for syscall in seq]
        padded_seq = self._pad_sequences([seq])

        # Convert to tensor and move to device
        input_tensor = torch.tensor(padded_seq).to(self.device)

        # Predict
        with torch.no_grad():
            self.model.eval()
            prediction = self.model(input_tensor)

        # Convert prediction to label
        label_index = int(prediction.item() > 0.5)
        return self.label_encoder.classes_[label_index]

    def load_model(self, model_path="syscall_lstm_model"):
        if os.path.exists(os.path.join(model_path, "model.pth")):
            # Load the tokenizer first to get the correct vocab size
            with open(os.path.join(model_path, "tokenizer.json"), "r") as f:
                self.tokenizer = json.load(f)

            # Initialize the model with the correct vocab size
            vocab_size = len(self.tokenizer)
            self.model = SyscallLSTMClassifier(
                vocab_size, self.max_sequence_length, self.embedding_dim, self.lstm_units
            ).to(self.device)

            # Load the model weights
            self.model.load_state_dict(torch.load(os.path.join(model_path, "model.pth"),weights_only=True))

            # Load the label encoder
            self.label_encoder.classes_ = np.load(os.path.join(model_path, "label_classes.npy"))
            print("Model loaded successfully.")
            return True

        return False




    def predict_file(self,test_syscall_sequence):
        try:
            log_directory = "./log"
            if not self.load_model():
                print("No saved model found. Training a new model...")
                # tuner = HyperparameterTuner(self)
                X, y = self.prepare_data(log_directory)
                X_processed, y_processed = self.preprocess_data(X, y)
                # best_params, best_score = tuner.tune_parameters(X_processed, y_processed)
                # print(f"Best parameters: {best_params}")
                # print(f"Best score: {best_score}")
                self.train(X_processed, y_processed)
                self.save_model()

            prediction = self.predict(test_syscall_sequence)
            
            # Phân tích syscall
            analysis = self.analyze_syscall_sequence(prediction,test_syscall_sequence)
            
            # # Tạo và hiển thị báo cáo
            # report = self.generate_simple_report(prediction, analysis)
            # print("\n" + report)
            
            return analysis

        except Exception as e:
            import traceback

            print(f"Đã xảy ra lỗi: {e}")
            traceback.print_exc()
            return None


if __name__ == "__main__":
    # test_syscall_sequence = "59,12,9,21,257,5,9,3,257,0,5,9,9,9,9,3,257,0,5,9,9,9,9,3,257,0,5,9,9,9,9,3,257,0,5,9,9,9,9,3,257,0,5,9,9,9,9,9,3,257,0,5,9,9,9,9,9,3,257,0,5,9,9,9,9,9,3,257,0,5,9,9,9,9,3,257,0,5,9,9,9,9,3,257,0,5,9,9,9,9,3,257,0,5,9,9,9,9,3,257,0,5,9,9,9,9,9,3,257,0,5,9,9,9,9,9,3,257,0,5,9,9,9,9,9,3,257,0,5,9,9,9,9,3,257,0,5,9,9,9,9,3,257,0,5,9,9,9,9,3,257,0,17,5,9,17,9,9,9,9,9,3,257,0,5,9,9,9,9,3,257,0,5,9,9,9,9,9,3,257,0,5,9,9,9,9,9,3,257,0,5,9,9,9,9,3,257,0,5,9,9,9,9,9,9,3,257,0,5,9,9,9,9,3,257,0,5,9,9,9,9,3,257,0,5,9,9,9,9,3,257,0,5,9,9,9,9,3,257,0,5,9,9,9,9,9,3,257,0,5,9,9,9,9,9,3,257,0,5,9,9,9,9,9,3,257,0,5,9,9,9,9,3,257,0,5,9,9,9,9,3,257,0,5,9,9,9,9,9,3,257,0,5,9,9,9,9,3,257,0,5,9,9,9,9,3,257,0,5,9,9,9,9,3,257,0,5,9,9,9,9,3,257,0,5,9,9,9,9,3,257,0,5,9,9,9,9,9,3,257,0,5,9,9,9,9,3,257,0,5,9,9,9,9,3,257,0,5,9,9,9,9,3,257,0,5,9,9,9,9,3,257,0,5,9,9,9,9,9,3,257,0,5,9,9,9,9,3,257,0,5,9,9,9,9,3,257,0,5,9,9,9,9,3,257,0,5,9,9,9,9,3,257,0,5,9,9,9,9,3,257,0,5,9,9,9,9,9,3,257,0,5,9,9,9,9,3,257,0,5,9,9,9,9,3,257,0,5,9,9,9,9,3,257,0,5,9,9,9,9,3,257,0,5,9,9,9,9,9,3,257,0,5,9,9,9,9,3,257,0,5,9,9,9,9,3,257,0,5,9,9,9,9,3,257,0,5,9,9,9,9,3,257,0,5,9,9,9,9,9,3,257,0,5,9,9,9,9,9,3,257,0,5,9,9,9,9,9,3,257,0,5,9,9,9,9,3,257,0,5,9,9,9,9,9,3,257,0,5,9,9,3,20"
    runner = SandboxRunner()
    test_syscall_sequence,log_file  = runner.run(1, "./test")
    print(f"log file --> {log_file}")
    analyst = SyscallAnalyzer()
    analyst.predict_file(test_syscall_sequence)
