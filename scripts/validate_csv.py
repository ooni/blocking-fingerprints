import csv
from pathlib import Path

def validate_csv(csv_path : Path):
    with csv_path.open() as in_file:
        reader = csv.reader(in_file)
        header = next(reader)
        for idx, row in enumerate(reader):
            assert len(row) == len(header), f"Inconsistent row count in {csv_path}:{idx+1} {row}, expected {len(header)} got {len(row)}"

def main():
    validate_csv(Path("fingerprints_dns.csv"))
    validate_csv(Path("fingerprints_http.csv"))

if __name__ == "__main__":
    main()
