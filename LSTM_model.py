import numpy as np
import tensorflow as tf
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import LSTM, Dense, Dropout
from tensorflow.keras.optimizers import Adam
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import json
import os
from constants import VECTOR_BENIGN_COMMITS_DIR, VECTOR_VULN_INTRO_COMMITS_DIR


def load_data(benign_dir, malicious_dir):
    def load_commits_from_dir(directory):
        all_commits = []
        for root, _, files in os.walk(directory):
            for filename in files:
                if filename.endswith(".json"):
                    with open(os.path.join(root, filename), "r") as f:
                        commits = json.load(f)
                        all_commits.extend(list(commits.values()))
        return np.array(all_commits)

    benign_commits = load_commits_from_dir(benign_dir)
    malicious_commits = load_commits_from_dir(malicious_dir)

    X = np.vstack((benign_commits, malicious_commits))
    y = np.concatenate([np.zeros(len(benign_commits)), np.ones(len(malicious_commits))])

    return X, y


# Load the data
X, y = load_data(VECTOR_BENIGN_COMMITS_DIR, VECTOR_VULN_INTRO_COMMITS_DIR)

# Print some information about the loaded data
print(f"Total number of samples: {len(X)}")
print(f"Number of benign samples: {np.sum(y == 0)}")
print(f"Number of malicious samples: {np.sum(y == 1)}")
print(f"Shape of each sample: {X[0].shape}")

# Check if we have enough data to proceed
if len(X) == 0:
    raise ValueError("No data was loaded. Please check your input directories.")

# Split the data
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

# Define model parameters
sequence_length = X.shape[1]
feature_dim = X.shape[2] if len(X.shape) > 2 else 1
lstm_units = 64
dropout_rate = 0.2
learning_rate = 0.001
batch_size = 32
epochs = 10

# Build the model
model = Sequential(
    [
        LSTM(
            lstm_units,
            input_shape=(sequence_length, feature_dim),
            return_sequences=True,
        ),
        Dropout(dropout_rate),
        LSTM(lstm_units),
        Dropout(dropout_rate),
        Dense(1, activation="sigmoid"),
    ]
)

# Compile the model
model.compile(
    optimizer=Adam(learning_rate=learning_rate),
    loss="binary_crossentropy",
    metrics=["accuracy"],
)

# Train the model
history = model.fit(
    X_train,
    y_train,
    batch_size=batch_size,
    epochs=epochs,
    validation_split=0.2,
    verbose=1,
)

# Evaluate the model
loss, accuracy = model.evaluate(X_test, y_test, verbose=0)
print(f"Test loss: {loss:.4f}")
print(f"Test accuracy: {accuracy:.4f}")

# Make predictions
y_pred = model.predict(X_test)
y_pred_classes = (y_pred > 0.5).astype(int).reshape(-1)

# Print classification report and confusion matrix
print("\nClassification Report:")
print(classification_report(y_test, y_pred_classes))
print("\nConfusion Matrix:")
print(confusion_matrix(y_test, y_pred_classes))

# Save the model
model.save("vulnerability_detection_model.h5")
print("\nModel saved as 'vulnerability_detection_model.h5'")
