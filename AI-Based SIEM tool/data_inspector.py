# step:0
import pandas as pd

print("=" * 25)
print("INSPECTING THE DATASET")
print("=" * 25)

# Load the data
df = pd.read_csv('data/rba-dataset.csv' , nrows=10000)

# Show basic info
print(f"\nDataset Shape: {df.shape[0]} rows, {df.shape[1]} columns")
print(f"\nColumn Names:")
for i, col in enumerate(df.columns, 1):
    print(f"  {i}. '{col}'")


# Show sample of unique values for first few columns
print(f"\nSample values from first 5 columns:")
for col in df.columns[:5]:
    print(f"\n{col}:")
    print(f"  unique values: {df[col].nunique()}")
    print(f"  Sample: {df[col].dropna().unique()[:5]}")