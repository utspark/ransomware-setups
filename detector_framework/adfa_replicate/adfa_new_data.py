import os
import multiprocessing
import random
from functools import partial
from pathlib import Path
from types import ModuleType
from typing import Iterable, Mapping, Any

import joblib
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import StandardScaler
from tqdm import tqdm

from cross_layer import syscall_signals
from detector_framework import config
from detector_framework.adfa_replicate.adfa import build_ngram_vocabulary, generate_multigram_phrases, get_features, \
    evaluate, sliding_window_sampling


def load_single_file(
        path: Path,
        malware_lookup: Mapping[str, int],
        signal_module: ModuleType | str,
        strict: bool = True
) -> tuple[np.ndarray, int, str] | None:
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

    df = signal_module.get_file_df(path)
    return np.array(df), label, matched_prefix


def load_files(
        paths: Iterable[Path],
        malware_map: Mapping[int, list],
        signal_module: ModuleType | str,
        strict: bool = True,
        n_workers: int = 1
) -> dict[str, list[np.ndarray]]:
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
                if prefix not in prefix_to_sequences:
                    prefix_to_sequences[prefix] = []
                prefix_to_sequences[prefix].append(seq)
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
                if prefix not in prefix_to_sequences:
                    prefix_to_sequences[prefix] = []
                prefix_to_sequences[prefix].append(seq)

    return prefix_to_sequences


def prefix_sliding_window(prefix_to_sequences: dict, window_size=100, window_stride=50, max_windows=1000) -> dict:
    prefix_to_windows = {}

    for prefix, sequences in prefix_to_sequences.items():
        prefix_windows = []
        for seq in sequences:
            seq = seq[:, 1]
            windows = sliding_window_sampling(seq, window_size, window_stride)
            prefix_windows.append(windows)

        prefix_windows = np.concatenate(prefix_windows, axis=0)
        prefix_to_windows[prefix] = prefix_windows[:max_windows]

    return prefix_to_windows


def prefix_train_test_split(prefix_to_windows: dict, tts: float = 0.7) -> tuple[dict[Any, Any], dict[Any, Any]]:
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
        get_techniques_fn: callable
) -> list[np.ndarray]:
    trace_list = []
    for _ in range(n_traces):
        techniques = get_techniques_fn()
        stage_lens = [(technique, random.choice(time_choices)) for technique in techniques]

        sampled = []
        for technique, length in stage_lens:
            prefix = technique + "_"
            w = w_test_dict[prefix]

            start = np.random.choice(range(0, w.shape[0] - length + 1))
            sampled_w = w[start:start + length]
            sampled.append(sampled_w)

        sampled = np.concatenate(sampled, axis=0)
        trace_list.append(sampled.reshape(-1))

    return trace_list





if __name__ == "__main__":
    config.set_seed()

    n_workers = os.cpu_count() - 4
    WORD_LENGTH = 7
    CLASSIFIER = "mlp"

    cwd = Path.cwd()
    data_dir = cwd / "data/current_data/syscall_bucket"
    malware_map = config.SYSCALL_BENIGN_MALWARE_DICT

    data_paths = [p for p in data_dir.iterdir() if p.is_file()]
    data_paths.sort()

    malware_keys = [item for sublist in malware_map.values() for item in sublist]
    malware_keys = set(malware_keys)

    malware_lookup = {}
    for key, malware_list in malware_map.items():
        for malware in malware_list:
            malware_lookup[malware] = key

    filtered = [
        path for path in data_paths
        if any(key in path.name for key in malware_keys)
    ]
    data_paths = filtered

    if not data_dir.exists():
        print(f"Data directory {data_dir} does not exist.")
        exit(1)

    print(f"Loading files from {data_dir}...")
    prefix_to_sequences = load_files(data_paths, malware_map, syscall_signals, strict=False, n_workers=n_workers)
    prefix_to_windows = prefix_sliding_window(prefix_to_sequences, window_size=100, window_stride=75, max_windows=50)
    w_train_dict, w_test_dict = prefix_train_test_split(prefix_to_windows)

    w_train = np.concatenate(list(w_train_dict.values()), axis=0)
    y_train = np.concatenate([np.full(w.shape[0], malware_lookup[prefix]) for prefix, w in w_train_dict.items()], axis=0)

    w_test = np.concatenate(list(w_test_dict.values()), axis=0)
    y_test = np.concatenate([np.full(w.shape[0], malware_lookup[prefix]) for prefix, w in w_test_dict.items()], axis=0)

    array_n, counts = build_ngram_vocabulary(list(w_train), WORD_LENGTH)
    all_phrases = generate_multigram_phrases(list(w_train), array_n, WORD_LENGTH, n_workers, max_length=4)

    X_train = get_features(w_train, all_phrases, WORD_LENGTH, n_workers, "training data")
    X_test = get_features(w_test, all_phrases, WORD_LENGTH, n_workers, "test data")

    # del w_train, w_test

    print("Normalizing features...")
    scaler = StandardScaler()
    X_train_norm = scaler.fit_transform(X_train)
    X_test_norm = scaler.transform(X_test)

    del X_train, X_test

    y_train = (y_train > 6).astype(int)
    y_test = (y_test > 6).astype(int)

    # In our label mapping: Benign is 1 (labels > 6), Attack is 0 (labels <= 6)
    target_names = ['Attack', 'Benign']

    clf = MLPClassifier(hidden_layer_sizes=(100, 50), max_iter=1000, random_state=42)
    clf.fit(X_train_norm, y_train)
    fpr, tpr, auc = evaluate(clf, CLASSIFIER.replace("_", " ").title(), CLASSIFIER, X_test_norm, y_test)
    filename = f"detector_framework/adfa_replicate/results/individual_behavior_curve.joblib"
    joblib.dump((fpr, tpr, auc), filename)

    benign_stages = config.GENERATION_BENIGN
    attack_stages = config.GENERATION_ATTACK_STAGES

    n_traces = 50
    start = 2  # 0.5
    stop = 10
    step = 1
    time_choices = np.arange(start, stop + step / 2, step, dtype=int).tolist()

    # baseline
    print(f"Generating {n_traces} benign traces...")
    get_benign_techniques = lambda: [random.choice(benign_stages) for _ in range(len(attack_stages))]
    benign_trace_list = create_sampled_traces(n_traces, w_test_dict, time_choices, get_benign_techniques)
    benign_features = get_features(benign_trace_list, all_phrases, WORD_LENGTH, n_workers, "benign traces")
    benign_norm = scaler.transform(benign_features)
    print(f"Generating {n_traces} malware traces...")
    get_malware_techniques = lambda: [random.choice(ttp_choices) for _, ttp_choices in attack_stages.items()]
    malware_trace_list = create_sampled_traces(n_traces, w_test_dict, time_choices, get_malware_techniques)
    malware_features = get_features(malware_trace_list, all_phrases, WORD_LENGTH, n_workers, "malware traces")
    malware_norm = scaler.transform(malware_features)
    print("Evaluating combined traces...")
    X_trace_test = np.concatenate([benign_norm, malware_norm], axis=0)
    # benign_norm should be label 1 (Benign), malware_norm should be label 0 (Attack)
    y_trace_test = np.concatenate([np.ones(len(benign_norm)), np.zeros(len(malware_norm))], axis=0)
    fpr, tpr, auc = evaluate(clf, "MLP Combined Traces", "mlp_combined", X_trace_test, y_trace_test)
    filename = f"detector_framework/adfa_replicate/results/exclude_encryption_curve.joblib"
    joblib.dump((fpr, tpr, auc), filename)

    # baseline
    print(f"Generating {n_traces} benign traces...")
    new_benign = benign_stages + attack_stages["exec_2"]
    get_benign_techniques = lambda: [random.choice(new_benign) for _ in range(len(attack_stages))]
    benign_trace_list = create_sampled_traces(n_traces, w_test_dict, time_choices, get_benign_techniques)
    benign_features = get_features(benign_trace_list, all_phrases, WORD_LENGTH, n_workers, "benign traces")
    benign_norm = scaler.transform(benign_features)
    print(f"Generating {n_traces} malware traces...")
    get_malware_techniques = lambda: [random.choice(ttp_choices) for _, ttp_choices in attack_stages.items()]
    malware_trace_list = create_sampled_traces(n_traces, w_test_dict, time_choices, get_malware_techniques)
    malware_features = get_features(malware_trace_list, all_phrases, WORD_LENGTH, n_workers, "malware traces")
    malware_norm = scaler.transform(malware_features)
    print("Evaluating combined traces...")
    X_trace_test = np.concatenate([benign_norm, malware_norm], axis=0)
    # benign_norm should be label 1 (Benign), malware_norm should be label 0 (Attack)
    y_trace_test = np.concatenate([np.ones(len(benign_norm)), np.zeros(len(malware_norm))], axis=0)
    fpr, tpr, auc = evaluate(clf, "MLP Combined Traces", "mlp_combined", X_trace_test, y_trace_test)
    filename = f"detector_framework/adfa_replicate/results/partial_encryption_curve.joblib"
    joblib.dump((fpr, tpr, auc), filename)

    # compression only
    print(f"Generating {n_traces} benign traces...")
    get_benign_techniques = lambda: [random.choice(attack_stages["exec_2"]) for _ in range(len(attack_stages))]
    benign_trace_list = create_sampled_traces(n_traces, w_test_dict, time_choices, get_benign_techniques)
    benign_features = get_features(benign_trace_list, all_phrases, WORD_LENGTH, n_workers, "benign traces")
    benign_norm = scaler.transform(benign_features)
    print(f"Generating {n_traces} malware traces...")
    get_malware_techniques = lambda: [random.choice(ttp_choices) for _, ttp_choices in attack_stages.items()]
    malware_trace_list = create_sampled_traces(n_traces, w_test_dict, time_choices, get_malware_techniques)
    malware_features = get_features(malware_trace_list, all_phrases, WORD_LENGTH, n_workers, "malware traces")
    malware_norm = scaler.transform(malware_features)
    print("Evaluating combined traces...")
    X_trace_test = np.concatenate([benign_norm, malware_norm], axis=0)
    # benign_norm should be label 1 (Benign), malware_norm should be label 0 (Attack)
    fpr, tpr, auc = evaluate(clf, "MLP Combined Traces", "mlp_combined", X_trace_test, y_trace_test)
    filename = f"detector_framework/adfa_replicate/results/full_encryption_curve.joblib"
    joblib.dump((fpr, tpr, auc), filename)






