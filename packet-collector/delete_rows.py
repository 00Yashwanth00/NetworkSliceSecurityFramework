from pathlib import Path
import shutil

file = Path("flow_dataset.csv")
backup = Path("flow_dataset.csv.bak")

start_row = 8001
end_row = 14065

# Backup
shutil.copy2(file, backup)
print(f"Backup created: {backup}")

# Remove rows 9000–11000, preserving the header
with file.open("r", encoding="utf-8", newline="") as f:
    lines = f.readlines()

# Assuming row 1 is the CSV header:
# CSV row N corresponds to lines[N-1]
new_lines = [
    line for i, line in enumerate(lines, start=1)
    if not (start_row <= i <= end_row)
]

with file.open("w", encoding="utf-8", newline="") as f:
    f.writelines(new_lines)

print(f"Deleted rows {start_row} through {end_row}.")
print(f"Rows deleted: {end_row - start_row + 1}")
print(f"Remaining lines: {len(new_lines)}")