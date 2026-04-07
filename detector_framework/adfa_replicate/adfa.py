import argparse
import os
from pathlib import Path

import joblib
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.svm import OneClassSVM, SVC
from sklearn.ensemble import IsolationForest
from sklearn.tree import DecisionTreeClassifier
from sklearn.neural_network import MLPClassifier

from detector_framework import config
from detector_framework.adfa_replicate.adfa_utils import (
    build_ngram_vocabulary,
    generate_multigram_phrases,
    get_features,
    evaluate,
)


# Constants
DEFAULT_ATTACK_DATA_PATH = Path("detector_framework/adfa_replicate/ADFA-IDS_DATASETS/ADFA-LD/Attack_Data_Master")
DEFAULT_TRAINING_DATA_PATH = Path("detector_framework/adfa_replicate/ADFA-IDS_DATASETS/ADFA-LD/Training_Data_Master")
DEFAULT_VALIDATION_DATA_PATH = Path("detector_framework/adfa_replicate/ADFA-IDS_DATASETS/ADFA-LD/Validation_Data_Master")
RESULTS_DIR = Path("detector_framework/adfa_replicate/results")

def load_data(base_path: str | Path, recursive: bool = False) -> list[np.ndarray] | dict[str, list[np.ndarray]]:
    """
    Loads syscall sequences from a directory.
    
    If recursive=False, it loads all .txt files from the base_path and returns a list of numpy arrays.
    If recursive=True, it traverses subdirectories and returns a dictionary where keys are 
    category names and values are lists of numpy arrays.
    """
    data_path = Path(base_path)
    if not data_path.is_absolute():
        # Try relative to the script location as a fallback
        script_dir = Path(__file__).resolve().parent.parent.parent
        if not data_path.exists():
            data_path = script_dir / base_path
        
    if not data_path.exists():
        raise FileNotFoundError(f"Could not find data at {data_path}")

    def load_files_from_dir(directory: Path) -> list[np.ndarray]:
        sequences = []
        for file_path in sorted(directory.glob("*.txt")):
            try:
                content = file_path.read_text().strip()
                if content:
                    seq = np.fromstring(content, dtype=int, sep=' ')
                    sequences.append(seq)
            except Exception as e:
                print(f"Error loading {file_path}: {e}")
        return sequences

    if recursive:
        data_dict = {}
        for category_dir in sorted(data_path.iterdir()):
            if category_dir.is_dir():
                sequences = load_files_from_dir(category_dir)
                if sequences:
                    data_dict[category_dir.name] = sequences
        return data_dict
    else:
        return load_files_from_dir(data_path)


def load_attack_data(base_path: str | Path = DEFAULT_ATTACK_DATA_PATH) -> dict[str, list[np.ndarray]]:
    """Loads Attack_Data_Master (recursive)."""
    return load_data(base_path, recursive=True)


def load_training_data(base_path: str | Path = DEFAULT_TRAINING_DATA_PATH) -> list[np.ndarray]:
    """Loads Training_Data_Master (non-recursive)."""
    return load_data(base_path, recursive=False)


def load_validation_data(base_path: str | Path = DEFAULT_VALIDATION_DATA_PATH) -> list[np.ndarray]:
    """Loads Validation_Data_Master (non-recursive)."""
    return load_data(base_path, recursive=False)


def convert_data_to_list(data: dict[str, list[np.ndarray]]) -> list[np.ndarray]:
    """Flattens a dictionary of lists of sequences into a single list of sequences."""
    return [seq for seqs in data.values() for seq in seqs]


def main(plot: bool = True):
    # --- Configuration ---
    word_length = 7  # Length of the system call word (range: 3-7)
    classifier_name = "mlp"  # "decision_tree", "svm", "mlp", "one_class_svm", or "isolation_forest"

    if word_length < 3 or word_length > 7:
        print(f"Warning: word_length {word_length} is outside the typical range [3, 7].")

    config.set_seed()
    n_workers = max(1, (os.cpu_count() or 1) - 4)

    try:
        train_data = load_training_data()
        print(f"Loaded {len(train_data)} training sequences.")
        
        val_data = load_validation_data()
        print(f"Loaded {len(val_data)} validation sequences.")
        
        attack_dict = load_attack_data()
        attack_data = convert_data_to_list(attack_dict)
        print(f"Loaded {len(attack_data)} attack sequences from {len(attack_dict)} categories.")
    except Exception as e:
        print(f"Failed to load data: {e}")
        return

    # Use a subset for faster demonstration if needed
    train_subset = train_data
    val_subset = val_data[:500]
    attack_subset = attack_data

    # n-call word dictionary
    array_n, _ = build_ngram_vocabulary(train_subset, word_length)

    # Generate multigram phrases (lengths 1 to 6)
    all_phrases = generate_multigram_phrases(train_subset, array_n, word_length, n_workers, max_length=6)

    # Feature extraction
    X_train_raw = get_features(train_subset, all_phrases, word_length, n_workers, "training data")
    X_val_raw = get_features(val_subset, all_phrases, word_length, n_workers, "validation data")
    X_attack_raw = get_features(attack_subset, all_phrases, word_length, n_workers, "attack data")

    # --- Normalize ---
    print("Normalizing features...")
    scaler = StandardScaler()
    X_train_norm = scaler.fit_transform(X_train_raw)
    X_val_norm = scaler.transform(X_val_raw)
    X_attack_norm = scaler.transform(X_attack_raw)

    X_all = np.concatenate([X_train_norm, X_attack_norm])
    y_all = np.concatenate([np.ones(len(X_train_norm)), np.zeros(len(X_attack_norm))])

    X_train, X_test, y_train, y_test = train_test_split(X_all, y_all, test_size=0.2, random_state=42)

    # --- Model Training ---
    print(f"\nTraining {classifier_name} on {len(X_train)} samples...")
    if classifier_name == "decision_tree":
        clf = DecisionTreeClassifier(random_state=42)
    elif classifier_name == "svm":
        clf = SVC(probability=True, random_state=42)
    elif classifier_name == "mlp":
        clf = MLPClassifier(hidden_layer_sizes=(100, 50), max_iter=1000, random_state=42)
    elif classifier_name == "one_class_svm":
        clf = OneClassSVM(kernel='rbf', gamma='auto')
        X_train = X_train[y_train == 1]
    elif classifier_name == "isolation_forest":
        clf = IsolationForest(random_state=42)
        X_train = X_train[y_train == 1]
    else:
        raise ValueError(f"Unknown classifier: {classifier_name}")

    clf.fit(X_train, y_train)

    # --- Evaluation ---
    fpr, tpr, auc = evaluate(clf, classifier_name.replace("_", " ").title(), classifier_name, X_test, y_test, plot=plot)
    
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    save_path = RESULTS_DIR / "adfa_data_curve.joblib"
    joblib.dump((fpr, tpr, auc), save_path)
    print(f"Results saved to {save_path}")


if __name__ == "__main__":
    main()













