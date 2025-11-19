import sys

executables = [
    "Kyber Crystals Ref",
    "Tempo Alg #1",
    "Tempo Alg #2",
    "Tempo Alg #3"
]

columns = [
    "initStart",
    "resp",
    "initEnd"
]

# Read all numbers from stdin
values = [line.strip() for line in sys.stdin if line.strip().isdigit()]

# Check number of entries
if len(values) != len(executables) * len(columns):
    raise ValueError("Unexpected number of median entries in input!")

# Group into rows of 3
rows = [values[i:i+3] for i in range(0, len(values), 3)]

# Print LaTeX table
print("\\begin{table}[h]")
print("\\centering")
print("\\begin{tabular}{lccc}")
print("\\hline")
print("Executable & {} & {} & {} \\\\".format(*columns))
print("\\hline")

for name, row in zip(executables, rows):
    print("{} & {} & {} & {} \\\\".format(name, *row))

print("\\hline")
print("\\end{tabular}")
print("\\caption{PAKE Median Cycle Counts}")
print("\\end{table}")