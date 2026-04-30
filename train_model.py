import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
import pickle
import os

# Load dataset
script_dir = os.path.dirname(os.path.abspath(__file__))
file_path = os.path.join(script_dir, "phishing_urls.csv")
data = pd.read_csv(file_path)

# Features
X = data.drop("target", axis=1)

# Target
y = data["target"]

# Split dataset
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42
)

# Train model
model = RandomForestClassifier()
model.fit(X_train, y_train)

# Ensure model folder exists in project directory
model_dir = os.path.join(script_dir, "model")
os.makedirs(model_dir, exist_ok=True)

# Save model inside model folder
model_path = os.path.join(model_dir, "phishing_model.pkl")
pickle.dump(model, open(model_path, "wb"))

print("Model saved at:", model_path)
print("Model trained successfully!")

print("Model trained successfully!")