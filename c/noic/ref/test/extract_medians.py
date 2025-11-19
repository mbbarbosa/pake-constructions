import sys
import re

# Targets we want to extract
targets = {
    "initStart": None,
    "resp": None,
    "initEnd": None,
}

current_section = None
median_pattern = re.compile(r"median:\s*([0-9]+)")

for line in sys.stdin:
    line = line.strip().rstrip(":")
    if line in targets:
        current_section = line
        continue

    if current_section and "median" in line:
        match = median_pattern.search(line)
        if match:
            targets[current_section] = match.group(1)
        current_section = None  # Reset until next section

# Print results in requested order
for key in targets:
    if targets[key] is not None:
        print(targets[key])
        