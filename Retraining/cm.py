import numpy as np
import matplotlib.pyplot as plt
import matplotlib as mpl

# ── Data ──────────────────────────────────────────────────────────────────────
cm = np.array([[1088, 191],
               [1211, 6535]])

class_labels = ["Negative", "Attack"]

# ── Plot ──────────────────────────────────────────────────────────────────────
fig, ax = plt.subplots(figsize=(7, 5))

im = ax.imshow(cm, cmap="Blues", aspect="auto")

# Colour bar
cbar = fig.colorbar(im, ax=ax, fraction=0.046, pad=0.04)
cbar.ax.tick_params(labelsize=10)

# Cell annotations (count only, centered)
thresh = cm.max() / 2.0
for r in range(2):
    for c in range(2):
        color = "white" if cm[r, c] > thresh else "black"
        ax.text(c, r, f"{cm[r, c]:,}",
                ha="center", va="center",
                fontsize=14, color=color)

# Axes
ax.set_xticks([0, 1])
ax.set_yticks([0, 1])
ax.set_xticklabels(class_labels, fontsize=11)
ax.set_yticklabels(class_labels, fontsize=11, rotation=90, va="center")
ax.set_xlabel("Predicted", fontsize=12, labelpad=8)
ax.set_ylabel("Actual",    fontsize=12, labelpad=8)
ax.set_title("Inference Confusion Matrix", fontsize=13, pad=12)

ax.tick_params(length=0)

plt.tight_layout()
plt.savefig("confusion_matrix.png", dpi=150, bbox_inches="tight")
print("Saved → confusion_matrix.png")
plt.show()