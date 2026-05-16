import pandas as pd
import os

# Load dataset from the project data folder.
script_dir = os.path.dirname(os.path.abspath(__file__))
project_root = os.path.dirname(script_dir)
file_path = os.path.join(project_root, "data", "phishing_urls.csv")
data = pd.read_csv(file_path)

# Show first 5 rows
print(data.head())

# Show column names
print("\nColumns in dataset:")
print(data.columns)
