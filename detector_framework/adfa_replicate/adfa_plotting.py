from pathlib import Path
import joblib
import matplotlib.pyplot as plt
from detector_framework import config

if __name__ == "__main__":
    config.set_seed()

    results_dir = Path("detector_framework/adfa_replicate/results")
    curve_files = list(results_dir.glob("*curve*.joblib"))

    # Mapping between curve filename (stem) and plotting label
    LABEL_MAP = {
        "adfa_data_curve": "ADFA-LD Data",
        "individual_behavior_curve": "OpenRansom Individual Behaviors",
        "exclude_encryption_compression_curve": "OpenRansom Lifecycles Exclude Enc/Comp",
        "partial_encryption_compression_curve": "OpenRansom Lifecycles Include Enc/Comp",
        "full_compression_curve": "OpenRansom Lifecycles Only Compression",
    }

    # Sort curve_files to match the order in LABEL_MAP
    label_keys = list(LABEL_MAP.keys())
    curve_files.sort(key=lambda x: label_keys.index(x.stem) if x.stem in label_keys else len(label_keys))

    plt.figure(figsize=(10, 8))
    
    for curve_file in curve_files:
        try:
            fpr, tpr, auc = joblib.load(curve_file)
            # Use label from map, fallback to formatted filename stem if not found
            label = LABEL_MAP.get(curve_file.stem, curve_file.stem.replace("_", " ").replace(" curve", ""))
            plt.plot(fpr, tpr, lw=4, label=f"{label} (AUC = {auc:.3f})")
        except Exception as e:
            print(f"Error loading {curve_file}: {e}")

    plt.plot([0, 1], [0, 1], color='gray', lw=2, linestyle='--')
    plt.xlim([-0.01, 1.01])
    plt.ylim([-0.01, 1.01])
    plt.xlabel('False Positive Rate')
    plt.ylabel('True Positive Rate')
    plt.title('ROC-AUC Curves')
    plt.legend(loc="lower right")
    plt.grid(True)
    
    plot_path = results_dir / "roc_auc_curves.png"
    plt.savefig(plot_path)
    print(f"Plot saved to {plot_path}")