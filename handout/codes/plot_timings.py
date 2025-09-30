import matplotlib.pyplot as plt
import numpy as np

files = {
    "AES": "aes.txt",
    "RSA": "rsa.txt",
    "Kyber": "kyber.txt"
}

means = {}

for label, filename in files.items():
    with open(filename, "r") as f:
        data = [float(x.strip()) for x in f.readlines()]
        mean_val = np.mean(data)
        means[label] = mean_val

print("\n=== Timing Results (Mean CPU Cycles) ===")
for algo, val in means.items():
    print(f"{algo:6s}: {val:.2f}")
print("========================================\n")

# Bar chart
colors = {"AES": "blue", "RSA": "green", "Kyber": "red"}
bars = plt.bar(means.keys(), means.values(), color=[colors[x] for x in means.keys()])

# Add text labels
for bar, (algo, val) in zip(bars, means.items()):
    plt.text(bar.get_x() + bar.get_width()/2, bar.get_height(),
             f"{val:.2f}", ha="center", va="bottom", fontsize=10, fontweight="bold")

plt.yscale("log")
plt.ylabel("Average Time (Cycles)")
plt.title("Average Encryption Time Comparison (Log Scale)")
plt.savefig("average_comparison.png")
print("Saved plot -> average_comparison.png")
