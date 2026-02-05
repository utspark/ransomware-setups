import joblib
from pathlib import Path

import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns

from detector_framework import config

def calculate_accuracies(feature_dict, clf, benign_malware_dict, benign_keys, attack_stages):
    prefix_lookup = {}
    for key, val in benign_malware_dict.items():
        for prefix in val:
            prefix_lookup[prefix] = key

    accuracies = []
    for key in benign_keys:
        if key not in feature_dict or (key + "_") not in prefix_lookup:
            accuracies.append(0)
            continue

        X = feature_dict[key]
        class_labels = clf.predict(X)
        y_true = np.full(len(class_labels), prefix_lookup[key + "_"])
        acc = np.sum(y_true == class_labels) / len(class_labels)
        accuracies.append(acc)

    for stage, ttps in attack_stages.items():
        for ttp in ttps:
            if ttp not in feature_dict or (ttp + "_") not in prefix_lookup:
                accuracies.append(0)
                continue

            X = feature_dict[ttp]
            class_labels = clf.predict(X)
            y_true = np.full(len(class_labels), prefix_lookup[ttp + "_"])
            acc = np.sum(y_true == class_labels) / len(class_labels)
            accuracies.append(acc)

    return accuracies


if __name__ == "__main__":
    OMIT_BENIGN = True

    plt.rcParams['font.size'] = 18

    cwd = Path.cwd()
    feature_frames_path = cwd / "data/feature_frames.joblib"

    if not feature_frames_path.exists():
        print(f"Error: {feature_frames_path} does not exist.")

    print(f"Loading {feature_frames_path}...")
    feature_frames = joblib.load(feature_frames_path)
    print("Successfully loaded feature_frames.")

    # Optional: print some info about the loaded data
    if isinstance(feature_frames, dict):
        print(f"Keys in feature_frames: {list(feature_frames.keys())}")
    else:
        print(f"Loaded data type: {type(feature_frames)}")

    # Load classifiers
    models_dir = cwd / "data/models"
    classifiers = {}
    for clf_name in ["syscall", "network", "hpc"]:
        clf_path = models_dir / f"{clf_name}_clf.joblib"
        if clf_path.exists():
            print(f"Loading {clf_path}...")
            classifiers[clf_name] = joblib.load(clf_path)
            print(f"Successfully loaded {clf_name} classifier.")
        else:
            print(f"Warning: {clf_path} does not exist.")

    # Calculate accuracies for each classifier
    benign_keys = [] if OMIT_BENIGN else config.GENERATION_BENIGN
    attack_stages = config.GENERATION_ATTACK_STAGES

    all_accuracies = {}
    for clf_name in ["network", "syscall", "hpc"]:
        if clf_name not in classifiers:
            print(f"Skipping {clf_name} accuracy calculation (classifier not loaded).")
            continue

        print(f"Calculating accuracies for {clf_name}...")
        feature_dict = feature_frames[clf_name]
        clf = classifiers[clf_name][0]

        if clf_name == "syscall":
            bm_dict = config.SYSCALL_BENIGN_MALWARE_DICT
        elif clf_name == "network":
            bm_dict = config.NETWORK_BENIGN_MALWARE_DICT
        elif clf_name == "hpc":
            bm_dict = config.HPC_BENIGN_MALWARE_DICT
        else:
            continue

        accs = calculate_accuracies(feature_dict, clf, bm_dict, benign_keys, attack_stages)
        all_accuracies[clf_name] = accs
        print(f"Finished {clf_name} accuracies.")

    # Print summary
    for clf_name, accs in all_accuracies.items():
        print(f"\n{clf_name.upper()} Accuracies:")
        print(accs)

    # Prepare data for heatmap
    benign_keys = [] if OMIT_BENIGN else config.GENERATION_BENIGN
    attack_stages = config.GENERATION_ATTACK_STAGES
    
    ttps = []
    groups = []
    group_boundaries = [0]
    
    # Add benign TTPs
    if not OMIT_BENIGN:
        ttps.extend(benign_keys)
        groups.extend(["Benign"] * len(benign_keys))
        group_boundaries.append(len(benign_keys))
    
    # Add attack stage TTPs
    for stage, stage_ttps in attack_stages.items():
        ttps.extend(stage_ttps)
        groups.extend([stage] * len(stage_ttps))
        group_boundaries.append(group_boundaries[-1] + len(stage_ttps))

    signal_layers = list(all_accuracies.keys())
    data = np.array([all_accuracies[layer] for layer in signal_layers])

    # Plot heatmap
    fig, ax = plt.subplots(figsize=(8, 6))
    sns.heatmap(data, annot=True, fmt=".2f", cmap="YlOrRd",
                xticklabels=ttps, yticklabels=signal_layers, ax=ax, cbar=False,
                annot_kws={"size": 12}, linewidths=1, linecolor='black')
    
    # ax.set_title("Class Accuracies per TTP and Signal Layer", fontsize=16)
    # ax.set_xlabel("TTPs (Grouped by Stage)", fontsize=18)
    # ax.set_ylabel("Signal Layers", fontsize=14)
    plt.xticks(rotation=90, fontsize=12, ha='right')
    plt.yticks(rotation=45, fontsize=14)
    
    # Add second level of labels for groups
    # We can add them at the top
    for i in range(len(group_boundaries) - 1):
        start = group_boundaries[i]
        end = group_boundaries[i+1]
        center = (start + end) / 2
        
        # Position the group label above the heatmap
        if not OMIT_BENIGN:
            group_name = "Benign" if i == 0 else list(attack_stages.keys())[i-1]
        else:
            group_name = list(attack_stages.keys())[i]
            
        ax.text(center, 1.05, group_name, ha='center', va='bottom', transform=ax.get_xaxis_transform(),
                fontsize=12, color='darkblue')
        
    # Add vertical boundaries
    for boundary in group_boundaries:
        ax.vlines(boundary, -0.1, 1.1, colors='darkblue', linestyles='--', lw=4, transform=ax.get_xaxis_transform(), clip_on=False)

    plt.tight_layout()
    # Adjust layout to make room for second level labels
    plt.subplots_adjust(bottom=0.20, top=0.85)

    # Save heatmap
    heatmap_path = cwd / "cross_layer/heatmap.png"
    plt.savefig(heatmap_path)
    print(f"\nHeatmap saved to {heatmap_path}")
