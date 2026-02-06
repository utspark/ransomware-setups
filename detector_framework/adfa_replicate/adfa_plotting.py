from pathlib import Path
import joblib
import matplotlib.pyplot as plt
from detector_framework import config

if __name__ == "__main__":
    config.set_seed()
    plt.rcParams['font.size'] = 18

    results_dir = Path("detector_framework/adfa_replicate/results")
    curve_files = list(results_dir.glob("*curve*.joblib"))

    # Mapping between curve filename (stem) and plotting label
    LABEL_MAP = {
        "adfa_data_curve": "ADFA-LD Data",
        "individual_behavior_curve": "OR Behaviors",
        "exclude_encryption_curve": "Lifecycles Exclude Enc",
        "partial_encryption_curve": "Lifecycles Include Enc",
        "full_encryption_curve": "Lifecycles Only Enc",
        "lapd_exclude_encryption_curve": "LAPD Lifecycles Only Enc",
    }

    curve_plotting_params = {
        "adfa_data_curve": {"color": "darkorange", "linestyle": "--"},
        "individual_behavior_curve": {"color": "darkred", "linestyle": "--"},
        "exclude_encryption_curve": {"color": "darkgreen", "linestyle": "-"},
        "partial_encryption_curve": {"color": "darkblue", "linestyle": "-"},
        "full_encryption_curve": {"color": "purple", "linestyle": "-"},
        "lapd_exclude_encryption_curve": {"color": "purple", "linestyle": "-"},
    }

    # Sort curve_files to match the order in LABEL_MAP
    label_keys = list(LABEL_MAP.keys())
    curve_files.sort(key=lambda x: label_keys.index(x.stem) if x.stem in label_keys else len(label_keys))

    plt.figure(figsize=(8, 5))
    
    for curve_file in curve_files:
        try:
            fpr, tpr, auc = joblib.load(curve_file)
            # Use label from map, fallback to formatted filename stem if not found
            label = LABEL_MAP.get(curve_file.stem, curve_file.stem.replace("_", " ").replace(" curve", ""))
            # color = curve_plotting_params[curve_file.stem]["color"]
            linestyle = curve_plotting_params[curve_file.stem]["linestyle"]
            plt.plot(fpr, tpr, lw=4, label=f"{label}: {auc:.3f}", alpha=0.7, linestyle=linestyle)
        except Exception as e:
            print(f"Error loading {curve_file}: {e}")

    # plt.plot([0, 1], [0, 1], color='gray', lw=2, linestyle='--')
    plt.plot([0, 1], [0, 1], lw=2, color="black", alpha=0.5, linestyle='--')
    plt.xlim([-0.01, 1.01])
    plt.ylim([-0.01, 1.01])
    plt.xlabel('False Positive Rate')
    plt.ylabel('True Positive Rate')
    plt.legend(loc="lower right", fontsize=14, borderaxespad=1.0)
    plt.tight_layout()
    plt.grid()
    
    plot_path = results_dir / "roc_auc_curves.png"
    plt.savefig(plot_path)
    print(f"Plot saved to {plot_path}")

    plt.show(block=True)