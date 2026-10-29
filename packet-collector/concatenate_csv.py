import pandas as pd

# Input files
file1 = "flow_dataset.csv"
file2 = "flow_dataset_2.csv"
file3 = "flow_dataset_3.csv"

# Output file
output_file = "flow_dataset_combined.csv"

# Read CSV files
df1 = pd.read_csv(file1)
df2 = pd.read_csv(file2)
df3 = pd.read_csv(file3)


# Concatenate rows
combined_df = pd.concat([df1, df2, df3], ignore_index=True)

# Save to a new CSV file
combined_df.to_csv(output_file, index=False)

print(f"Successfully concatenated:")
print(f"  - {file1}: {len(df1)} rows")
print(f"  - {file2}: {len(df2)} rows")
print(f"  - Output: {output_file}: {len(combined_df)} rows")
