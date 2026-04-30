import pandas as pd
import os
# Load dataset from dataset folder
script_dir = os.path.dirname(os.path.abspath(__file__))
file_path = os.path.join(script_dir, "dataset/phishing_urls.csv")
data = pd.read_csv(file_path)

# Show first 5 rows
print(data.head())

# Show column names
print("\nColumns in dataset:")
print(data.columns)