#!/usr/bin/env python3

from pathlib import Path
import csv
import shutil

ROOT = Path(__file__).resolve().parent
SOURCE_DIR = ROOT / "pcaps"
OUTPUT_FILE = ROOT / "flow_dataset.csv"
BACKUP_FILE = ROOT / "flow_dataset.csv.bak"


def main():
    csv_files = sorted(SOURCE_DIR.rglob("*.csv"))

    if not csv_files:
        print(f"No CSV files found under: {SOURCE_DIR}")
        return

    # Don't accidentally include the output file if it is somewhere under pcaps/
    csv_files = [
        path for path in csv_files
        if path.resolve() != OUTPUT_FILE.resolve()
    ]

    if not csv_files:
        print("No source CSV files found.")
        return

    # Backup the existing dataset
    if OUTPUT_FILE.exists():
        shutil.copy2(OUTPUT_FILE, BACKUP_FILE)
        print(f"Backup created: {BACKUP_FILE}")

    # Read the existing header
    existing_header = None

    if OUTPUT_FILE.exists() and OUTPUT_FILE.stat().st_size > 0:
        with OUTPUT_FILE.open("r", newline="", encoding="utf-8") as f:
            reader = csv.reader(f)
            existing_header = next(reader, None)

    total_rows = 0
    processed_files = 0
    skipped_files = 0

    with OUTPUT_FILE.open("a", newline="", encoding="utf-8") as output:
        writer = None

        for csv_file in csv_files:
            print(f"Processing: {csv_file}")

            try:
                with csv_file.open("r", newline="", encoding="utf-8") as source:
                    reader = csv.reader(source)

                    header = next(reader, None)

                    if not header:
                        print("  Skipping empty CSV")
                        skipped_files += 1
                        continue

                    # First CSV establishes the header if output was empty
                    if existing_header is None:
                        existing_header = header

                        writer = csv.writer(output)
                        writer.writerow(existing_header)

                    # Make sure we have a writer
                    if writer is None:
                        writer = csv.writer(output)

                    # Verify columns match
                    if header != existing_header:
                        print("  WARNING: Column header mismatch!")
                        print(f"  Expected: {existing_header}")
                        print(f"  Found:    {header}")
                        print("  Skipping this file.")
                        skipped_files += 1
                        continue

                    file_rows = 0

                    for row in reader:
                        if not row:
                            continue

                        writer.writerow(row)
                        file_rows += 1
                        total_rows += 1

                    print(f"  Added {file_rows:,} rows")
                    processed_files += 1

            except Exception as e:
                print(f"  ERROR: {e}")
                skipped_files += 1

    print("\n========== DONE ==========")
    print(f"Files processed : {processed_files}")
    print(f"Files skipped   : {skipped_files}")
    print(f"Rows added      : {total_rows:,}")
    print(f"Output          : {OUTPUT_FILE}")
    print(f"Backup          : {BACKUP_FILE if BACKUP_FILE.exists() else 'None'}")


if __name__ == "__main__":
    main()