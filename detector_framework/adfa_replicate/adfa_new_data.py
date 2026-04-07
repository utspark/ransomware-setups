import os
import multiprocessing
import random
from functools import partial
from pathlib import Path
from types import ModuleType
from typing import Iterable, Mapping, Any, Callable

import joblib
import numpy as np
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import StandardScaler
from tqdm import tqdm

from cross_layer import syscall_signals
from detector_framework import config
from detector_framework.adfa_replicate.adfa_utils import (
    build_ngram_vocabulary,
    generate_multigram_phrases,
    get_features,
    evaluate,
    sliding_window_sampling,
)

# Constants
WORD_LENGTH = 7
CLASSIFIER_TYPE = "mlp"
WINDOW_SIZE = 100
WINDOW_STRIDE = 75
MAX_WINDOWS = 50
RESULTS_DIR = Path("detector_framework/adfa_replicate/results")
DATA_DIR = Path("data/current_data/syscall_bucket")
N_TRACES = 50


def load_single_file(
        path: Path,
        malware_lookup: Mapping[str, int],
        signal_module: ModuleType | str,
        strict: bool = True
) -> tuple[np.ndarray, int, str] | None:
    """
    Loads a single syscall sequence file and matches it to a malware label.
    """
    if not path.is_file():
        return None

    label = None
    matched_prefix = None
    for malware, key in malware_lookup.items():
        if malware in path.name:
            label = key
            matched_prefix = malware
            break

    if label is None:
        if strict:
            raise KeyError(f"No label found in malware_map for file: {path.name}")
        return None

    if isinstance(signal_module, str):
        import importlib
        signal_module = importlib.import_module(signal_module)

    try:
        df = signal_module.get_file_df(path)
        return np.array(df), label, matched_prefix
    except Exception as e:
        print(f"Error loading {path}: {e}")
        return None


def load_files(
        paths: Iterable[Path],
        malware_map: Mapping[int, list],
        signal_module: ModuleType | str,
        strict: bool = True,
        n_workers: int = 1
) -> dict[str, list[np.ndarray]]:
    """
    Loads multiple syscall sequence files in parallel and groups them by malware prefix.
    """
    prefix_to_sequences = {}

    # Create a fast lookup map for malware labels
    malware_lookup = {}
    for key, malware_list in malware_map.items():
        for malware in malware_list:
            malware_lookup[malware] = key

    if n_workers <= 1:
        for p in tqdm(paths, desc="Loading files"):
            result = load_single_file(p, malware_lookup, signal_module, strict)
            if result:
                seq, label, prefix = result
                prefix_to_sequences.setdefault(prefix, []).append(seq)
    else:
        # Pass the module name if it's a module object to avoid pickling issues
        module_to_pass = signal_module
        if isinstance(signal_module, ModuleType):
            module_to_pass = signal_module.__name__

        worker = partial(load_single_file, malware_lookup=malware_lookup, signal_module=module_to_pass, strict=strict)
        with multiprocessing.Pool(processes=n_workers) as pool:
            results = list(tqdm(pool.imap(worker, paths), total=len(paths), desc=f"Loading files (parallel, n={n_workers})"))

        for res in results:
            if res:
                seq, label, prefix = res
                prefix_to_sequences.setdefault(prefix, []).append(seq)

    return prefix_to_sequences


def prefix_sliding_window(
        prefix_to_sequences: dict[str, list[np.ndarray]],
        window_size: int = 100,
        window_stride: int = 50,
        max_windows: int = 1000
) -> dict[str, np.ndarray]:
    """
    Applies sliding window sampling to sequences grouped by prefix.
    """
    prefix_to_windows = {}

    for prefix, sequences in prefix_to_sequences.items():
        prefix_windows = []
        for seq in sequences:
            # Assumes seq is 2D and we want the second column (syscall ID)
            if seq.ndim > 1:
                seq = seq[:, 1]
            windows = sliding_window_sampling(seq, window_size, window_stride)
            if windows.size > 0:
                prefix_windows.append(windows)

        if prefix_windows:
            prefix_windows_concat = np.concatenate(prefix_windows, axis=0)
            prefix_to_windows[prefix] = prefix_windows_concat[:max_windows]

    return prefix_to_windows


def prefix_train_test_split(
        prefix_to_windows: dict[str, np.ndarray],
        tts: float = 0.7
) -> tuple[dict[str, np.ndarray], dict[str, np.ndarray]]:
    """
    Splits windows into training and testing sets while maintaining prefix grouping.
    """
    X_train_dict = {}
    X_test_dict = {}

    for prefix, tmp_X in prefix_to_windows.items():
        n = tmp_X.shape[0]
        idx = int(np.floor(tts * n))
        X_train, X_test = np.split(tmp_X, [idx], axis=0)

        X_train_dict[prefix] = X_train
        X_test_dict[prefix] = X_test

    return X_train_dict, X_test_dict


def create_sampled_traces(
        n_traces: int,
        w_test_dict: dict[str, np.ndarray],
        time_choices: list[int],
        get_techniques_fn: Callable[[], list[str]]
) -> list[np.ndarray]:
    """
    Creates synthetic traces by sampling windows from different techniques.
    """
    trace_list = []
    for _ in range(n_traces):
        techniques = get_techniques_fn()
        stage_lens = [(technique, random.choice(time_choices)) for technique in techniques]

        sampled = []
        for technique, length in stage_lens:
            prefix = technique + "_"
            if prefix not in w_test_dict:
                # Handle cases where the technique might not have a trailing underscore in the dict
                if technique in w_test_dict:
                    prefix = technique
                else:
                    print(f"Warning: Technique {technique} not found in test dictionary.")
                    continue
            
            w = w_test_dict[prefix]
            if w.shape[0] < length:
                sampled_w = w
            else:
                start = np.random.choice(range(0, w.shape[0] - length + 1))
                sampled_w = w[start:start + length]
            sampled.append(sampled_w)

        if sampled:
            sampled_concat = np.concatenate(sampled, axis=0)
            trace_list.append(sampled_concat.reshape(-1))

    return trace_list


def generate_and_evaluate_combined(
    clf: MLPClassifier,
    scaler: StandardScaler,
    w_test_dict: dict[str, np.ndarray],
    all_phrases: list[np.ndarray],
    time_choices: list[int],
    n_workers: int,
    benign_techniques_fn: Callable[[], list[str]],
    malware_techniques_fn: Callable[[], list[str]],
    results_path: Path,
    description: str,
    plot: bool = True
):
    """
    Generates synthetic benign and malware traces, combines them, and evaluates the classifier.
    """
    print(f"\n--- Generating and Evaluating: {description} ---")
    
    print(f"Generating {N_TRACES} benign traces...")
    benign_trace_list = create_sampled_traces(N_TRACES, w_test_dict, time_choices, benign_techniques_fn)
    benign_features = get_features(benign_trace_list, all_phrases, WORD_LENGTH, n_workers, "benign traces")
    benign_norm = scaler.transform(benign_features)
    
    print(f"Generating {N_TRACES} malware traces...")
    malware_trace_list = create_sampled_traces(N_TRACES, w_test_dict, time_choices, malware_techniques_fn)
    malware_features = get_features(malware_trace_list, all_phrases, WORD_LENGTH, n_workers, "malware traces")
    malware_norm = scaler.transform(malware_features)
    
    print("Evaluating combined traces...")
    X_trace_test = np.concatenate([benign_norm, malware_norm], axis=0)
    # benign_norm label 1 (Benign), malware_norm label 0 (Attack)
    y_trace_test = np.concatenate([np.ones(len(benign_norm)), np.zeros(len(malware_norm))], axis=0)
    
    fpr, tpr, auc = evaluate(clf, "MLP Combined Traces", "mlp_combined", X_trace_test, y_trace_test, plot=plot)
    
    results_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump((fpr, tpr, auc), results_path)
    print(f"Saved results to {results_path}")


def main(plot: bool = True):
    config.set_seed()

    n_workers = max(1, (os.cpu_count() or 1) - 4)
    
    malware_map = config.SYSCALL_BENIGN_MALWARE_DICT
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    if not DATA_DIR.exists():
        print(f"Data directory {DATA_DIR} does not exist.")
        return

    data_paths = sorted([p for p in DATA_DIR.iterdir() if p.is_file()])
    
    # Filter data paths based on malware_map
    malware_keys = set(item for sublist in malware_map.values() for item in sublist)
    data_paths = [p for p in data_paths if any(key in p.name for key in malware_keys)]

    print(f"Loading {len(data_paths)} files from {DATA_DIR}...")
    prefix_to_sequences = load_files(data_paths, malware_map, syscall_signals, strict=False, n_workers=n_workers)
    
    print("Applying sliding window sampling...")
    prefix_to_windows = prefix_sliding_window(
        prefix_to_sequences, 
        window_size=WINDOW_SIZE, 
        window_stride=WINDOW_STRIDE, 
        max_windows=MAX_WINDOWS
    )
    
    w_train_dict, w_test_dict = prefix_train_test_split(prefix_to_windows)

    # Flatten dictionaries for training/testing
    w_train = np.concatenate(list(w_train_dict.values()), axis=0)
    w_test = np.concatenate(list(w_test_dict.values()), axis=0)
    
    # Create a lookup for label based on prefix
    malware_lookup = {}
    for key, malware_list in malware_map.items():
        for malware in malware_list:
            malware_lookup[malware] = key

    y_train_raw = np.concatenate([np.full(w.shape[0], malware_lookup[prefix]) for prefix, w in w_train_dict.items()], axis=0)
    y_test_raw = np.concatenate([np.full(w.shape[0], malware_lookup[prefix]) for prefix, w in w_test_dict.items()], axis=0)

    # Convert to binary labels: Benign is 1 (labels > 6), Attack is 0 (labels <= 6)
    y_train = (y_train_raw > 6).astype(int)
    y_test = (y_test_raw > 6).astype(int)

    # Feature extraction
    array_n, _ = build_ngram_vocabulary(list(w_train), WORD_LENGTH)
    all_phrases = generate_multigram_phrases(list(w_train), array_n, WORD_LENGTH, n_workers, max_length=4)

    X_train = get_features(w_train, all_phrases, WORD_LENGTH, n_workers, "training data")
    X_test = get_features(w_test, all_phrases, WORD_LENGTH, n_workers, "test data")

    print("Normalizing features...")
    scaler = StandardScaler()
    X_train_norm = scaler.fit_transform(X_train)
    X_test_norm = scaler.transform(X_test)

    print(f"\nTraining {CLASSIFIER_TYPE} classifier...")
    clf = MLPClassifier(hidden_layer_sizes=(100, 50), max_iter=1000, random_state=42)
    clf.fit(X_train_norm, y_train)
    
    # Evaluate individual behaviors
    fpr, tpr, auc = evaluate(clf, CLASSIFIER_TYPE.replace("_", " ").title(), CLASSIFIER_TYPE, X_test_norm, y_test, plot=plot)
    joblib.dump((fpr, tpr, auc), RESULTS_DIR / "individual_behavior_curve.joblib")

    # Synthetic trace generation parameters
    benign_stages = config.GENERATION_BENIGN
    attack_stages = config.GENERATION_ATTACK_STAGES
    
    start, stop, step = 2, 10, 1
    time_choices = np.arange(start, stop + step / 2, step, dtype=int).tolist()

    # Define malware technique selection function
    get_malware_techniques = lambda: [random.choice(ttp_choices) for _, ttp_choices in attack_stages.items()]

    # Case 1: Exclude encryption
    get_benign_exclude_enc = lambda: [random.choice(benign_stages) for _ in range(len(attack_stages))]
    generate_and_evaluate_combined(
        clf, scaler, w_test_dict, all_phrases, time_choices, n_workers,
        get_benign_exclude_enc, get_malware_techniques,
        RESULTS_DIR / "exclude_encryption_curve.joblib",
        "Baseline (Exclude Encryption)",
        plot=plot
    )

    # Case 2: Partial encryption
    new_benign = benign_stages + attack_stages["exec_2"]
    get_benign_partial_enc = lambda: [random.choice(new_benign) for _ in range(len(attack_stages))]
    generate_and_evaluate_combined(
        clf, scaler, w_test_dict, all_phrases, time_choices, n_workers,
        get_benign_partial_enc, get_malware_techniques,
        RESULTS_DIR / "partial_encryption_curve.joblib",
        "Partial Encryption",
        plot=plot
    )

    # Case 3: Encryption Only
    get_benign_full_enc = lambda: [random.choice(attack_stages["exec_2"]) for _ in range(len(attack_stages))]
    generate_and_evaluate_combined(
        clf, scaler, w_test_dict, all_phrases, time_choices, n_workers,
        get_benign_full_enc, get_malware_techniques,
        RESULTS_DIR / "full_encryption_curve.joblib",
        "Encryption Only",
        plot=plot
    )


if __name__ == "__main__":
    main()






