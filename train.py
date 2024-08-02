import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, Dataset, random_split
import json
import os
from tqdm import tqdm
from constants import PADDED_VULN_INTRO_COMMITS_DIR, PADDED_BENIGN_COMMITS_DIR


class MalwareDataset(Dataset):
    def __init__(self, data_dir, target_value):
        self.features = []
        self.targets = []

        for root, _, files in os.walk(data_dir):
            for file in tqdm(files, desc=f"Loading data from {data_dir}"):
                if file.endswith(".json"):
                    file_path = os.path.join(root, file)
                    with open(file_path, "r") as f:
                        data = json.load(f)

                    # Flatten the structure
                    flattened_features = []
                    for vector in data.values():
                        flattened_features.extend(vector)

                    self.features.append(flattened_features)
                    self.targets.append(target_value)

        self.features = torch.tensor(self.features, dtype=torch.float32)
        self.targets = torch.tensor(self.targets, dtype=torch.float32).unsqueeze(1)

    def __len__(self):
        return len(self.features)

    def __getitem__(self, idx):
        return self.features[idx], self.targets[idx]


class RNN(nn.Module):
    def __init__(self, input_size, hidden_size, output_size, num_layers=1):
        super(RNN, self).__init__()
        self.rnn = nn.RNN(
            input_size=input_size,
            hidden_size=hidden_size,
            num_layers=num_layers,
            batch_first=True,
        )
        self.fc = nn.Linear(hidden_size, output_size)

    def forward(self, x):
        x = x.unsqueeze(1)
        h0 = torch.zeros(self.rnn.num_layers, x.size(0), self.rnn.hidden_size).to(
            x.device
        )
        out, _ = self.rnn(x, h0)
        out = self.fc(out[:, -1, :])
        return out


def train_model(dataloader, model, criterion, optimizer, device):
    model.train()
    total_loss = 0
    for features, targets in dataloader:
        features, targets = features.to(device), targets.to(device)

        outputs = model(features)
        loss = criterion(outputs, targets)

        optimizer.zero_grad()
        loss.backward()
        optimizer.step()

        total_loss += loss.item()

    return total_loss / len(dataloader)


def evaluate_model(dataloader, model, criterion, device):
    model.eval()
    total_loss = 0
    predictions = []
    true_labels = []

    with torch.no_grad():
        for features, targets in dataloader:
            features, targets = features.to(device), targets.to(device)

            outputs = model(features)
            loss = criterion(outputs, targets)

            total_loss += loss.item()
            predictions.extend(torch.sigmoid(outputs).cpu().numpy())
            true_labels.extend(targets.cpu().numpy())

    predictions = torch.tensor(predictions)
    true_labels = torch.tensor(true_labels)
    accuracy = ((predictions > 0.5) == true_labels).float().mean().item()

    return total_loss / len(dataloader), accuracy


def main():
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

    # Load and combine datasets
    vuln_dataset = MalwareDataset(PADDED_VULN_INTRO_COMMITS_DIR, target_value=1)
    benign_dataset = MalwareDataset(PADDED_BENIGN_COMMITS_DIR, target_value=0)

    full_dataset = torch.utils.data.ConcatDataset([vuln_dataset, benign_dataset])

    # Split dataset
    train_size = int(0.8 * len(full_dataset))
    test_size = len(full_dataset) - train_size
    train_dataset, test_dataset = random_split(full_dataset, [train_size, test_size])

    # Create data loaders
    train_loader = DataLoader(train_dataset, batch_size=32, shuffle=True)
    test_loader = DataLoader(test_dataset, batch_size=32, shuffle=False)

    # Initialize model
    input_size = vuln_dataset.features.shape[1]
    hidden_size = 64
    output_size = 1
    model = RNN(
        input_size=input_size, hidden_size=hidden_size, output_size=output_size
    ).to(device)

    # Training setup
    criterion = nn.BCEWithLogitsLoss()
    optimizer = optim.Adam(model.parameters(), lr=0.001)
    num_epochs = 10

    # Training loop
    for epoch in range(num_epochs):
        train_loss = train_model(train_loader, model, criterion, optimizer, device)
        test_loss, test_accuracy = evaluate_model(test_loader, model, criterion, device)

        print(
            f"Epoch [{epoch+1}/{num_epochs}], "
            f"Train Loss: {train_loss:.4f}, "
            f"Test Loss: {test_loss:.4f}, "
            f"Test Accuracy: {test_accuracy:.4f}"
        )

    # Final evaluation
    _, final_accuracy = evaluate_model(test_loader, model, criterion, device)
    print(f"Final Test Accuracy: {final_accuracy:.4f}")

    # Save the model
    torch.save(model.state_dict(), "model.pth")


if __name__ == "__main__":
    main()
