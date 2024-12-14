import os
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


class SyscallDataset(Dataset):
    def __init__(self, sequences, labels):
        """
        Custom PyTorch dataset for syscall sequences

        :param sequences: Preprocessed syscall sequences
        :param labels: Encoded labels
        """
        self.sequences = torch.tensor(sequences, dtype=torch.long)
        self.labels = torch.tensor(labels, dtype=torch.float32)

    def __len__(self):
        return len(self.sequences)

    def __getitem__(self, idx):
        return self.sequences[idx], self.labels[idx]


class SyscallLSTMClassifier(nn.Module):
    def __init__(self, vocab_size, max_sequence_length=100, embedding_dim=64, lstm_units=128):
        """
        Initialize the LSTM classifier for syscall log analysis

        :param vocab_size: Size of syscall vocabulary
        :param max_sequence_length: Maximum length of syscall sequences
        :param embedding_dim: Dimension of embedding layer
        :param lstm_units: Number of LSTM units
        """
        super(SyscallLSTMClassifier, self).__init__()

        self.max_sequence_length = max_sequence_length
        self.embedding_dim = embedding_dim
        self.lstm_units = lstm_units

        # Embedding layer
        self.embedding = nn.Embedding(
            vocab_size + 1, embedding_dim, padding_idx=0)

        # LSTM layers
        self.lstm1 = nn.LSTM(embedding_dim, lstm_units,
                             batch_first=True, bidirectional=True)
        self.dropout1 = nn.Dropout(0.5)

        self.lstm2 = nn.LSTM(lstm_units * 2, 64, batch_first=True)
        self.dropout2 = nn.Dropout(0.5)

        # Fully connected layers
        self.fc1 = nn.Linear(64, 32)
        self.relu = nn.ReLU()
        self.fc2 = nn.Linear(32, 1)
        self.sigmoid = nn.Sigmoid()

    def forward(self, x):
        """
        Forward pass of the model

        :param x: Input sequences
        :return: Model output
        """
        # Embedding
        x = self.embedding(x)

        # First LSTM layer
        x, _ = self.lstm1(x)
        x = self.dropout1(x)

        # Second LSTM layer
        x, _ = self.lstm2(x)
        x = self.dropout2(x)

        # Global max pooling
        x, _ = torch.max(x, dim=1)

        # Fully connected layers
        x = self.fc1(x)
        x = self.relu(x)
        x = self.fc2(x)
        x = self.sigmoid(x)

        return x


class SyscallAnalyzer:
    def __init__(self, max_sequence_length=100, embedding_dim=64, lstm_units=128):
        """
        Initialize the syscall analyzer

        :param max_sequence_length: Maximum length of syscall sequences
        :param embedding_dim: Dimension of embedding layer
        :param lstm_units: Number of LSTM units
        """
        # Device configuration
        self.device = torch.device(
            'cuda' if torch.cuda.is_available() else 'cpu')
        print(f"Using device: {self.device}")

        self.max_sequence_length = max_sequence_length
        self.embedding_dim = embedding_dim
        self.lstm_units = lstm_units

        # Tokenizer for converting syscall numbers to sequences
        self.tokenizer = {}
        self.reverse_tokenizer = {}

        # Label encoder
        self.label_encoder = LabelEncoder()

        # The model
        self.model = None

    # def prepare_data(self, log_directory):
    #     """
    #     Prepare training data from log files

    #     :param log_directory: Directory containing log files
    #     :return: X (syscall sequences), y (labels)
    #     """
    #     X = []
    #     y = []

    #     # Iterate through log files
    #     for filename in os.listdir(log_directory):
    #         if filename.endswith('.log'):
    #             filepath = os.path.join(log_directory, filename)

    #             # Determine label based on directory
    #             if 'safe' in filepath:
    #                 label = 'safe'
    #             elif 'dangerous' in filepath:
    #                 label = 'dangerous'
    #             else:
    #                 continue

    #             # Read syscalls from log file
    #             with open(filepath, 'r') as f:
    #                 for line in f:
    #                     if 'Syscalls' in line:
    #                         # Extract syscall list from log
    #                         syscalls_str = line.split(':')[1].strip()[1:-1]
    #                         syscalls = [s.strip() for s in syscalls_str.split(',') if s.strip()]

    #                         if syscalls:
    #                             X.append(','.join(syscalls))
    #                             y.append(label)

    #     return X, y

    def prepare_data(self, log_directory):
        """
        Prepare training data from log files
    
        :param log_directory: Directory containing subdirectories 'safe' and 'dangerous'
        :return: X (syscall sequences), y (labels)
        """
        X = []
        y = []

        # Các thư mục con chứa log
        subdirs = ['safe', 'dangerous']

        for label in subdirs:
            # Tạo đường dẫn đầy đủ tới thư mục con
            current_dir = os.path.join(log_directory, label)

            # Kiểm tra thư mục con có tồn tại không
            if not os.path.exists(current_dir):
                print(f"Thư mục {current_dir} không tồn tại")
                continue

            # Lọc các tệp .log
            log_files = [f for f in os.listdir(current_dir) if f.endswith('.log')]

            print(f"Tìm thấy {len(log_files)} tệp log trong thư mục {label}")

            # Duyệt qua các tệp log
            for filename in log_files:
                filepath = os.path.join(current_dir, filename)

                try:
                    with open(filepath, 'r') as f:
                        for line in f:
                            if 'Syscalls' in line:
                                # Trích xuất danh sách syscall từ log
                                syscalls_str = line.split(':')[1].strip()[1:-1]
                                syscalls = [s.strip()
                                            for s in syscalls_str.split(',') if s.strip()]

                                if syscalls:
                                    X.append(','.join(syscalls))
                                    y.append(label)
                except Exception as e:
                    print(f"Lỗi khi đọc tệp {filename}: {e}")

        # Kiểm tra xem có dữ liệu nào được tải không
        if not X:
            raise ValueError(
                "Không tìm thấy chuỗi syscall hợp lệ trong các tệp log")

        print(f"Đã tải {len(X)} chuỗi syscall")
        return X, y

    def preprocess_data(self, X, y):
        """
        Preprocess syscall sequences

        :param X: Syscall sequences
        :param y: Labels
        :return: Processed X, y
        """
        # Create tokenizer
        unique_syscalls = set(','.join(X).split(','))
        self.tokenizer = {syscall: i+1 for i,
                          syscall in enumerate(unique_syscalls)}
        self.reverse_tokenizer = {i+1: syscall for i,
                                  syscall in enumerate(unique_syscalls)}

        # Convert syscall sequences to integer sequences
        X_seq = []
        for sequence in X:
            seq = [self.tokenizer.get(syscall, 0)
                   for syscall in sequence.split(',')]
            X_seq.append(seq)

        # Pad sequences
        X_padded = self._pad_sequences(X_seq)

        # Encode labels
        y_encoded = self.label_encoder.fit_transform(y)

        return X_padded, y_encoded

    def _pad_sequences(self, sequences):
        """
        Pad sequences to a fixed length

        :param sequences: List of integer sequences
        :return: Padded sequences
        """
        padded = np.zeros(
            (len(sequences), self.max_sequence_length), dtype=int)
        for i, seq in enumerate(sequences):
            length = min(len(seq), self.max_sequence_length)
            padded[i, :length] = seq[:length]
        return padded

    def train(self, X, y, test_size=0.2, epochs=50, batch_size=32, learning_rate=0.001):
        """
        Train the LSTM model

        :param X: Preprocessed syscall sequences
        :param y: Encoded labels
        :param test_size: Proportion of test data
        :param epochs: Number of training epochs
        :param batch_size: Batch size for training
        :param learning_rate: Learning rate for optimizer
        """
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=test_size, random_state=42
        )

        # Create datasets and dataloaders
        train_dataset = SyscallDataset(X_train, y_train)
        test_dataset = SyscallDataset(X_test, y_test)

        train_loader = DataLoader(
            train_dataset, batch_size=batch_size, shuffle=True)
        test_loader = DataLoader(test_dataset, batch_size=batch_size)

        # Initialize model
        vocab_size = len(self.tokenizer)
        self.model = SyscallLSTMClassifier(vocab_size,
                                           self.max_sequence_length,
                                           self.embedding_dim,
                                           self.lstm_units).to(self.device)

        # Loss and optimizer
        criterion = nn.BCELoss()
        optimizer = optim.Adam(self.model.parameters(), lr=learning_rate)

        # Training loop
        for epoch in range(epochs):
            self.model.train()
            total_loss = 0

            for batch_X, batch_y in train_loader:
                # Move to device
                batch_X = batch_X.to(self.device)
                batch_y = batch_y.unsqueeze(1).to(self.device)

                # Zero gradients
                optimizer.zero_grad()

                # Forward pass
                outputs = self.model(batch_X)

                # Compute loss
                loss = criterion(outputs, batch_y)

                # Backward and optimize
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

            # Print epoch summary
            print(f'Epoch [{epoch+1}/{epochs}], '
                  f'Train Loss: {total_loss/len(train_loader):.4f}, '
                  f'Val Loss: {val_loss/len(test_loader):.4f}')

        # Final evaluation
        print("\nClassification Report:")
        print(classification_report(all_labels, all_preds,
              target_names=['safe', 'dangerous']))

    def save_model(self, model_path='syscall_lstm_model'):
        """
        Save trained model and associated components

        :param model_path: Path to save model
        """
        # Create directory if it doesn't exist
        os.makedirs(model_path, exist_ok=True)

        # Save model
        torch.save(self.model.state_dict(),
                   os.path.join(model_path, 'model.pth'))

        # Save tokenizer
        with open(os.path.join(model_path, 'tokenizer.json'), 'w') as f:
            json.dump(self.tokenizer, f)

        # Save label encoder classes
        np.save(os.path.join(model_path, 'label_classes.npy'),
                self.label_encoder.classes_)

    def predict(self, syscall_sequence):
        """
        Predict whether a syscall sequence is safe or dangerous

        :param syscall_sequence: Comma-separated syscall list
        :return: Prediction (safe/dangerous)
        """
        # Convert syscall sequence to padded sequence
        seq = [self.tokenizer.get(syscall, 0)
               for syscall in syscall_sequence.split(',')]
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


# def main():
#     try:
#         # Set random seeds for reproducibility
#         torch.manual_seed(42)
#         np.random.seed(42)

#         # Configuration
#         log_directory = './log'  # Directory containing log files

#         # Initialize analyzer
#         analyzer = SyscallAnalyzer()

#         # Prepare data
#         X, y = analyzer.prepare_data(log_directory)

#         # Preprocess data
#         X_processed, y_processed = analyzer.preprocess_data(X, y)

#         # Train model
#         analyzer.train(X_processed, y_processed)

#         # Save model
#         analyzer.save_model()

#         # Example prediction
#         test_syscall_sequence = "2,0,1,3,12,9"  # Example syscall sequence
#         prediction = analyzer.predict(test_syscall_sequence)
#         print(f"Prediction for test sequence: {prediction}")

#     except Exception as e:
#         import traceback
#         print(f"Đã xảy ra lỗi: {e}")
#         traceback.print_exc()
def main():
    try:
        # Cấu hình
        log_directory = './log'  # Thư mục chứa các thư mục con 'safe' và 'dangerous'
        
        # Khởi tạo analyzer
        analyzer = SyscallAnalyzer()
        
        # Chuẩn bị dữ liệu
        X, y = analyzer.prepare_data(log_directory)
        
        # Tiền xử lý dữ liệu
        X_processed, y_processed = analyzer.preprocess_data(X, y)
        
        # Huấn luyện mô hình
        analyzer.train(X_processed, y_processed)
        
        # Lưu mô hình
        analyzer.save_model()
        
        # Ví dụ dự đoán
        test_syscall_sequence = "2,0,1,3,12,9"  # Chuỗi syscall ví dụ
        prediction = analyzer.predict(test_syscall_sequence)
        print(f"Dự đoán cho chuỗi thử nghiệm: {prediction}")
    
    except Exception as e:
        import traceback
        print(f"Đã xảy ra lỗi: {e}")
        traceback.print_exc()


if __name__ == '__main__':
    main()
