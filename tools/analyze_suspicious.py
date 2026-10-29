import csv
from collections import Counter

path = "syscall_dataset.csv"
counts = Counter()
sequences = Counter()

with open(path, newline="") as file:
    reader = csv.DictReader(file)

    for row in reader:
        if row["predicted_label"] != "SUSPICIOUS":
            continue

        process = row["process_name"]
        sequence = (
            row["syscall_1"],
            row["syscall_2"],
            row["syscall_3"],
        )

        counts[process] += 1
        sequences[(process, sequence)] += 1

print("Top processes by suspicious records")
for process, count in counts.most_common(15):
    print(f"{process:24} {count:8}")

print("\nTop suspicious sequences")
for (process, sequence), count in sequences.most_common(15):
    seq = " -> ".join(sequence)
    print(f"{process:24} {seq:20} {count:8}")