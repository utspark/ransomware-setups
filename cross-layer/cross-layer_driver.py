from copy import deepcopy
from pathlib import Path

from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier

import network_signals
import syscall_signals
import hpc_signals
import ml_pipelines.config
import numpy as np
import pandas as pd
import seaborn as sns
import joblib

from sklearn.utils import compute_class_weight, compute_sample_weight
from sklearn.preprocessing import LabelBinarizer
from sklearn.metrics import roc_curve, auc

from sklearn.metrics import roc_auc_score, confusion_matrix, roc_curve, classification_report, log_loss
from typing import Iterable, Mapping, Tuple, Optional, Dict, Literal, Any
from types import ModuleType

from copy import deepcopy

from typing import Iterable, Tuple, Sequence
from collections import defaultdict

import random

import matplotlib

from ml_pipelines import global_detector


matplotlib.use("Qt5Agg")
import matplotlib.pyplot as plt
plt.ion()


def files_and_labels_to_X_y(
    paths: Iterable[Path],
    signal_module: ModuleType,
    malware_map: Mapping[int, list],
    window_size_time: float,
    window_stride_time: float,
    *,
    strict: bool = True,
) -> Tuple[np.ndarray, np.ndarray]:
    """
    Build (X, y) from a collection of files.

    - Each file is turned into a feature matrix X_i via `signal_module.file_df_feature_extraction`.
    - Its label is taken from `malware_map[file_path.name]` and broadcast to the number of rows in X_i.
    - All X_i are concatenated along axis 0; same for y_i.

    Parameters
    ----------
    paths : iterable of Path
        Files to process.
    signal_module : module or object
        Must provide `get_file_df(Path)` and `file_df_feature_extraction(df, window_size_time, window_stride_time)`.
    malware_map : dict-like
        Maps filename (str) → integer label.
    window_size_time, window_stride_time : floats
        Feature extraction parameters.
    strict : bool
        If True, raise on missing label/file issues; if False, skip problematic files.
    dataframe_subsample : int
        stride for which to subsample collected dataframes

    Returns
    -------
    X : np.ndarray
        Feature matrix of shape (total_windows, n_features).
    y : np.ndarray
        Integer labels of shape (total_windows,).
    """
    X_list: list[np.ndarray] = []
    y_list: list[np.ndarray] = []
    label = None

    for p in paths:
        for key, malware_list in malware_map.items():
            if any(malware in p.name for malware in malware_list):
                label = key
                break

        if strict and label is None:
            raise KeyError(f"No label found in malware_map for file: {p.name}")

        df = signal_module.get_file_df(p)

        extract = getattr(signal_module, "file_df_feature_extraction_parallel", None)
        if extract is None:
            extract = getattr(signal_module, "file_df_feature_extraction")

        X_i = extract(df, window_size_time, window_stride_time)

        # Skip files that produced zero windows (optional)
        if X_i is None or X_i.size == 0:
            if strict:
                # If strict, consider zero-window an error
                raise ValueError(f"Feature extraction produced no rows for: {p}")
            else:
                continue

        y_i = np.full(X_i.shape[0], label, dtype=np.int32)
        X_list.append(X_i)
        y_list.append(y_i)

    if not X_list:
        # No data; return empty shapes
        return np.empty((0, 0), dtype=float), np.empty((0,), dtype=np.int32)

    X = np.concatenate(X_list, axis=0)
    y = np.concatenate(y_list, axis=0)

    # Ensure y is integer-typed
    if not np.issubdtype(y.dtype, np.integer):
        y = y.astype(np.int32, copy=False)

    return X, y


def train_model(
    X_train: np.ndarray,
    y_train: np.ndarray,
    sample_weight: np.ndarray,
    *,
    max_depth: int = 7,
    random_state: Optional[int] = 42,
) -> Tuple[DecisionTreeClassifier, LabelBinarizer]:
    """
    Train a DecisionTreeClassifier with required per-sample weights.

    Parameters
    ----------
    X_train : array-like, shape (n_samples, n_features)
    y_train : array-like, shape (n_samples,)
    sample_weight : array-like, shape (n_samples,)
        Per-sample weights (must be non-negative and not all zero).
    max_depth : int
    random_state : int or None

    Returns
    -------
    (DecisionTreeClassifier, LabelBinarizer)
    """
    # normalize inputs
    y_arr = np.asarray(y_train).ravel()
    n_samples = np.shape(X_train)[0]

    w = np.asarray(sample_weight, dtype=float).ravel()
    if w.shape[0] != n_samples or y_arr.shape[0] != n_samples:
        raise ValueError(
            f"Inconsistent lengths: X={n_samples}, y={y_arr.shape[0]}, sample_weight={w.shape[0]}"
        )
    if np.any(w < 0):
        raise ValueError("sample_weight must be non-negative.")
    if not np.isfinite(w).all():
        raise ValueError("sample_weight must be finite.")
    if w.sum() == 0:
        raise ValueError("sample_weight must not sum to zero.")

    lb = LabelBinarizer().fit(y_arr)

    clf = DecisionTreeClassifier(max_depth=max_depth, random_state=random_state)
    clf.fit(X_train, y_arr, sample_weight=w)

    return clf, lb


def compute_train_test_sample_weights(
    y_train: np.ndarray,
    y_test: np.array,
) -> Tuple[np.ndarray, np.ndarray, Dict[int, float]]:
    """
    Compute class-balanced sample weights for train/test.

    We derive class weights from the *training* distribution, then apply
    those weights to both y_train and y_test to get per-sample weights.

    Returns
    -------
    train_sample_weights : (n_train,) float array
    test_sample_weights  : (n_test,) float array
    class_weight_map     : dict[label -> weight]
    """
    y_train = np.asarray(y_train).ravel()
    y_test  = np.asarray(y_test).ravel()

    classes = np.unique(y_train)
    class_weights = compute_class_weight(
        class_weight="balanced",
        classes=classes,
        y=y_train,
    )  # shape: (n_classes,)

    class_weight_map: Dict[int, float] = {
        int(label): float(w) for label, w in zip(classes, class_weights)
    }

    # Optional: sanity-check that test set doesn't contain unseen labels
    unseen = np.setdiff1d(np.unique(y_test), classes)
    if unseen.size > 0:
        raise ValueError(
            f"y_test contains labels not seen in y_train: {unseen.tolist()}"
        )

    train_sample_weights = compute_sample_weight(class_weight=class_weight_map, y=y_train)
    test_sample_weights  = compute_sample_weight(class_weight=class_weight_map, y=y_test)

    return train_sample_weights, test_sample_weights, class_weight_map


def prediction_analysis(
    y_true: np.ndarray,                  # (n,) labels OR (n,k) one-hot
    y_proba: np.ndarray,                 # (n,k) predicted probabilities
    *,
    lb: LabelBinarizer,                  # fitted on the same class set
    sample_weight: Optional[np.ndarray] = None,
    plot: bool = False,
    normalize: Literal['true','pred','all', None] = 'true',
    ax: Optional[plt.Axes] = None,
    title: str = "Confusion Matrix",
) -> Dict[str, Any]:
    """
    Compute log-loss, classification report, and (optionally) plot a confusion matrix.
    Returns a dict with 'log_loss', 'classification_report', and 'confusion_matrix'.

    Notes:
    - y_proba must be probabilities (rows ~ sum to 1), not hard one-hot.
    - If y_true is one-hot, it will be inverted to labels via lb.
    """
    # --- normalize y_true to labels and one-hot ---
    y_true = np.asarray(y_true)
    if y_true.ndim == 2:
        y_true_ohe = y_true
        y_true_labels = lb.inverse_transform(y_true_ohe)
    else:
        y_true_labels = y_true.ravel()
        y_true_ohe = lb.transform(y_true_labels)

    y_proba = np.asarray(y_proba, dtype=float)

    # --- sanity checks ---
    if y_proba.ndim != 2:
        raise ValueError("y_proba must be 2D (n_samples, n_classes).")
    if y_proba.shape != y_true_ohe.shape:
        raise ValueError(
            f"Shape mismatch: y_proba {y_proba.shape} vs y_true (one-hot) {y_true_ohe.shape}."
        )

    # --- metrics ---
    loss = log_loss(y_true_ohe, y_proba, sample_weight=sample_weight)
    y_pred_labels = lb.inverse_transform(y_proba)
    report = classification_report(
        y_true_labels, y_pred_labels, sample_weight=sample_weight
    )
    cm = confusion_matrix(
        y_true_labels, y_pred_labels,
        labels=lb.classes_,
        sample_weight=sample_weight,
        normalize=normalize
    )

    # --- optional plot ---
    if plot:
        class_names = [str(c) for c in lb.classes_]
        cm_df = pd.DataFrame(cm, index=class_names, columns=class_names)
        if ax is None:
            _, ax = plt.subplots(figsize=(8, 6))
        sns.heatmap(
            cm_df,
            annot=True,
            fmt='.2f' if normalize else 'd',
            cmap='Blues',
            cbar_kws={'label': 'Normalized' if normalize else 'Count'},
            ax=ax
        )
        ax.set_ylabel('Actual')
        ax.set_xlabel('Predicted')
        ax.set_title(title)
        plt.tight_layout()
        plt.show(block=True)

    return {"log_loss": float(loss), "classification_report": report, "confusion_matrix": cm}


def train_and_test_report(X: np.ndarray, y: np.ndarray) -> None:
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.3, random_state=42, stratify=y
    )
    train_sample_weights, test_sample_weights, _ = compute_train_test_sample_weights(y_train, y_test)

    dtree_model, lb = train_model(X_train, y_train, train_sample_weights)
    y_pred_ohe = dtree_model.predict_proba(X_test)

    results = prediction_analysis(y_test, y_pred_ohe, lb=lb, sample_weight=test_sample_weights, plot=True)
    print(f"Log Loss: {results['log_loss']}")
    print(f"Classification Report: {results['classification_report']}")

    return


def train_and_save_model(X: np.ndarray, y: np.ndarray, save_path: Path) -> None:
    y = np.asarray(y).ravel()

    classes = np.unique(y)
    class_weights = compute_class_weight(class_weight="balanced", classes=classes, y=y)

    class_weight_map: Dict[int, float] = {
        int(label): float(w) for label, w in zip(classes, class_weights)
    }

    sample_weights = compute_sample_weight(class_weight=class_weight_map, y=y)

    dtree_model, lb = train_model(X, y, sample_weights)

    joblib.dump((dtree_model, lb), save_path)

    return


def correct_feature_vector_times(feature_dict: dict):
    for signal in feature_dict:
        for action in feature_dict[signal]:
            fv_list = feature_dict[signal][action]

            for tmp_X in fv_list[1:]:

                prior_X = feature_dict[signal][action][-1]
                prior_max = prior_X["time"].iloc[-1]
                deltas = prior_X["time"].diff()  # Timedelta Series; first is NaT
                prior_mean_delta = deltas.mean(skipna=True)

                tmp_X["time"] += prior_max + prior_mean_delta

    return


def correct_feature_vector_times_2(feature_dict: dict):
    actions = feature_dict["syscall"].keys()

    for action in actions:
        syscall_batches = feature_dict["syscall"][action]
        network_batches = feature_dict["network"][action]
        hpc_batches = feature_dict["hpc"][action]

        num_batches = len(syscall_batches)

        for batch in range(1, num_batches):
            prior_syscall_batch = syscall_batches[batch-1]
            prior_network_batch = network_batches[batch-1]
            prior_hpc_batch = hpc_batches[batch-1]

            max_time = np.max([
                prior_syscall_batch["time"].iloc[-1],
                prior_network_batch["time"].iloc[-1],
                prior_hpc_batch["time"].iloc[-1]
            ])

            deltas = prior_syscall_batch["time"].diff()
            prior_syscall_mean_delta = deltas.mean(skipna=True)
            syscall_batches[batch]["time"] = syscall_batches[batch]["time"] + max_time + prior_syscall_mean_delta

            deltas = prior_network_batch["time"].diff()
            prior_network_mean_delta = deltas.mean(skipna=True)
            network_batches[batch]["time"] = network_batches[batch]["time"] + max_time + prior_network_mean_delta

            deltas = prior_hpc_batch["time"].diff()
            prior_hpc_mean_delta = deltas.mean(skipna=True)
            hpc_batches[batch]["time"] = hpc_batches[batch]["time"] + max_time + prior_hpc_mean_delta

    return


def build_features(signal_df_dict, signal_modules, window_size_time, window_stride_time, feature_dict=None, *,
                   preserve_time=True):
    if feature_dict is None:
        feature_dict = {}

    for signal, actions in signal_df_dict.items():
        mod = signal_modules[signal]
        # Prefer a parallel extractor if the module provides one; else fall back
        extract = getattr(mod, "file_df_feature_extraction_parallel", None)
        if extract is None:
            extract = getattr(mod, "file_df_feature_extraction")
        for action, df_list in actions.items():
            rows = [extract(df, window_size_time, window_stride_time, preserve_time=preserve_time)
                    for df in df_list]

            feature_dict.setdefault(signal, {})
            feature_dict[signal].setdefault(action, [])
            out = feature_dict[signal][action]
            out.extend(rows)

    return feature_dict


def build_cross_layer_X(
        feature_dict: dict[str, dict[str, pd.DataFrame]],
        attack_lens: Iterable[Tuple[str, float]],
        window_size_time: float,
        window_stride_time: float,
        rng: np.random.Generator,
        signals: Sequence[str] = ("syscall", "network", "hpc"),
) -> list[list[pd.DataFrame]]:
    cross_layer_X = []

    for attack, t in attack_lens:
        # Compute desired window count from duration, then clamp to the shortest signal length
        desired = int((t - window_size_time) / window_stride_time)
        if desired <= 0:
            continue  # nothing to sample for this attack

        # Gather per-signal frames once and compute min length
        sig_frames = [feature_dict[signal][attack] for signal in signals]
        sig_lengths = [len(df) for df in sig_frames]
        if not sig_lengths:
            continue
        num_windows = min(desired, min(sig_lengths))
        if num_windows <= 0:
            continue

        # Sample aligned windows for each signal
        X_list = []
        for df, n in zip(sig_frames, sig_lengths):
            start = rng.integers(0, n - num_windows + 1)
            X_list.append(df.iloc[start:start + num_windows])

        cross_layer_X.append(X_list)

    return cross_layer_X


def form_signal_dict(behaviors: dict, signal_modules: dict) -> dict:
    # signal_df_dict = defaultdict(lambda: defaultdict(list))
    #
    # for action, signals in behaviors.items():
    #     for signal, file_paths in signals.items():
    #         mod = signal_modules[signal]
    #         dfs = [mod.get_file_df(fp) for fp in file_paths]
    #
    #         for df in dfs:
    #             signal_df_dict[signal][action].append(df)

    signal_df_dict = {}

    for action, signals in behaviors.items():
        for signal, file_paths in signals.items():
            mod = signal_modules[signal]
            dfs = [mod.get_file_df(fp) for fp in file_paths]

            # Ensure nested dict and list exist
            signal_df_dict.setdefault(signal, {})
            signal_df_dict[signal].setdefault(action, [])
            signal_df_dict[signal][action].extend(dfs)

    return signal_df_dict


def form_feature_frames(feature_dict: dict) -> dict:
    feature_frames = {}

    for signal, actions in feature_dict.items():
        for action, X_list in actions.items():
            pruned = [df.drop(columns='time', errors='ignore') for df in X_list]

            feature_frames.setdefault(signal, {})
            feature_frames[signal][action] = pd.concat(pruned, ignore_index=True, sort=False, copy=False)

    return feature_frames


def cross_layer_concatenate(attack_X: list):
    syscall_X, network_X, hpc_X = zip(*attack_X)
    syscall_X = np.concatenate(syscall_X)
    network_X = np.concatenate(network_X)
    hpc_X = np.concatenate(hpc_X)
    cross_layer_X = (syscall_X, network_X, hpc_X)

    return cross_layer_X


if __name__ == "__main__":
    cwd = Path.cwd()
    SYSCALL = False
    NETWORK = False
    HPC = False
    TRAIN = False
    REPROCESS_DATA = True

    window_size_time = 0.1 / 2  # / 2  # 10
    window_stride_time = window_size_time / 3
    rng = np.random.default_rng(seed=1337)  # optional seed


    if SYSCALL:
        syscall_dir = cwd / "../data/current_data/syscall_bucket"
        syscall_paths = [p for p in syscall_dir.iterdir() if p.is_file()]
        syscall_paths.sort()

        # MALWARE_DICT = ml_pipelines.config.SYSCALL_MALWARE_DICT
        MALWARE_DICT = ml_pipelines.config.SYSCALL_BENIGN_MALWARE_DICT
        malware_keys = [item for sublist in MALWARE_DICT.values() for item in sublist]
        malware_keys = set(malware_keys)

        filtered = [
            path for path in syscall_paths
            if any(key in path.name for key in malware_keys)
        ]
        syscall_paths = filtered

        # TODO uncomment this
        # subsampled = []
        # for key in malware_keys:
        #     tmp_list = [path for path in syscall_paths if key in str(path)]
        #     subsample = int(len(tmp_list) * 0.6)
        #     subsampled.extend(tmp_list[:subsample])
        # syscall_paths = subsampled

        X, y = files_and_labels_to_X_y(
            syscall_paths, syscall_signals, MALWARE_DICT, window_size_time, window_stride_time,
        )
        print(np.unique(y, return_counts=True))

        if TRAIN:
            save_path = cwd / "../data/models/syscall_clf.joblib"
            train_and_save_model(X, y, save_path)
        else:
            train_and_test_report(X, y)

    if NETWORK:
        network_dir = cwd / "../data/current_data/network_bucket"
        network_paths = [p for p in network_dir.iterdir() if p.is_file()]
        network_paths.sort()

        # MALWARE_DICT = ml_pipelines.config.NETWORK_MALWARE_DICT
        MALWARE_DICT = ml_pipelines.config.NETWORK_BENIGN_MALWARE_DICT
        malware_keys = [item for sublist in MALWARE_DICT.values() for item in sublist]
        malware_keys = set(malware_keys)

        filtered = [
            path for path in network_paths
            if any(key in path.name for key in malware_keys)
        ]
        network_paths = filtered

        # TODO uncomment this
        # subsampled = []
        # for key in malware_keys:
        #     tmp_list = [path for path in network_paths if key in str(path)]
        #     subsample = int(len(tmp_list) * 0.6)
        #     subsampled.extend(tmp_list[:subsample])
        # network_paths = subsampled

        X, y = files_and_labels_to_X_y(
            network_paths, network_signals, MALWARE_DICT, window_size_time, window_stride_time,
        )
        print(np.unique(y, return_counts=True))

        if TRAIN:
            save_path = cwd / "../data/models/network_clf.joblib"
            train_and_save_model(X, y, save_path)
        else:
            train_and_test_report(X, y)

    if HPC:
        # window_size_time = 0.5
        # window_stride_time = 0.2

        hpc_dir = cwd / "../data/current_data/hpc_bucket"
        hpc_paths = [p for p in hpc_dir.iterdir() if p.is_file()]
        hpc_paths.sort()

        # MALWARE_DICT = ml_pipelines.config.HPC_MALWARE_DICT
        MALWARE_DICT = ml_pipelines.config.HPC_BENIGN_MALWARE_DICT
        malware_keys = [item for sublist in MALWARE_DICT.values() for item in sublist]
        malware_keys = set(malware_keys)

        filtered = [
            path for path in hpc_paths
            if any(key in path.name for key in malware_keys)
        ]
        hpc_paths = filtered

        subsampled = []
        for key in malware_keys:
            tmp_list = [path for path in hpc_paths if key in str(path)]
            subsample = int(len(tmp_list) * 0.6)
            subsampled.extend(tmp_list[:subsample])
        hpc_paths = subsampled

        X, y = files_and_labels_to_X_y(
            hpc_paths, hpc_signals, MALWARE_DICT, window_size_time, window_stride_time,
        )
        print(np.unique(y, return_counts=True))

        if TRAIN:
            save_path = cwd / "../data/models/hpc_clf.joblib"
            train_and_save_model(X, y, save_path)
        else:
            train_and_test_report(X, y)


    syscall_dir = cwd / "../data/current_data/syscall_bucket"
    network_dir = cwd / "../data/current_data/network_bucket"
    hpc_dir = cwd / "../data/current_data/hpc_bucket"

    signal_modules = {
        "syscall": syscall_signals,
        "network": network_signals,
        "hpc": hpc_signals,
    }

    behaviors = deepcopy(ml_pipelines.config.BEHAVIOR_FILES)

    feature_frames_path = cwd / "../data/feature_frames.joblib"

    if REPROCESS_DATA:

        for behavior in behaviors:
            for signal_dir, signal in zip([syscall_dir, network_dir, hpc_dir], signal_modules.keys()):
                behaviors[behavior][signal] = [signal_dir / file_path for file_path in behaviors[behavior][signal]]


        # raise Exception

        signal_df_dict = form_signal_dict(behaviors, signal_modules)
        feature_dict = build_features(
            signal_df_dict, signal_modules, window_size_time, window_stride_time, preserve_time=True
        )

        #  TODO there should be time alignment of various signals
        #   - because there is not, no use in below functions
        #   - ask Prateek for time alignment; a trace of some action
        #   - should take the same length across all signals
        #   e.g. AES_128 takes 15 seconds in syscalls and hpc
        # correct_feature_vector_times_2(feature_dict)
        # correct_feature_vector_times(feature_dict)

        feature_frames = form_feature_frames(feature_dict)
        joblib.dump(feature_frames, feature_frames_path)

    else:
        feature_frames = joblib.load(feature_frames_path)

    #  form attack data
    # gd = global_detector.LifecycleDetector()
    #
    # print("")
    # attack_lens = [
    #     ("symm_AES_128t", 0.9),
    #     ("symm_AES_256t", 0.6),
    # ]
    #
    # attack_proba = []
    # for i in range(5):
    #     attack_X = build_attack_windows(feature_frames, attack_lens, window_size_time, window_stride_time, rng)
    #     cross_layer_X = cross_layer_concatenate(attack_X)
    #     preds = cross_layer_class_preds(cross_layer_X)
    #     preds = collate_preds(preds)
    #
    #     proba = np.exp(gd.hmm.score(np.array(preds).reshape(-1, 1)))
    #     proba = np.power(proba, 1 / len(preds))  # normalization
    #
    #     attack_proba.append(proba)
    #     print(proba)
    #
    # print("")
    # attack_lens = [
    #     ("browser_compute", 0.9),
    #     ("browser_download", 0.6),
    # ]
    #
    # benign_proba = []
    # for i in range(5):
    #     attack_X = build_attack_windows(feature_frames, attack_lens, window_size_time, window_stride_time, rng)
    #     cross_layer_X = cross_layer_concatenate(attack_X)
    #     preds = cross_layer_class_preds(cross_layer_X)
    #     preds = collate_preds(preds)
    #
    #     proba = np.exp(gd.hmm.score(np.array(preds).reshape(-1, 1)))
    #     proba = np.power(proba, 1 / len(preds))  # normalization
    #
    #     benign_proba.append(proba)
    #     print(proba)
    #
    #
    # y_scores = attack_proba + benign_proba
    # y_true = np.zeros(len(y_scores))
    # y_true[:len(attack_proba)] = 1
    #
    # fpr, tpr, thresholds = roc_curve(y_true, y_scores)
    # roc_auc = auc(fpr, tpr)
    #
    # plt.figure()
    # plt.plot(fpr, tpr, lw=2, label=f'ROC curve (AUC = {roc_auc:.2f})')
    # plt.plot([0, 1], [0, 1], lw=1, linestyle='--', label='Random guess')
    # plt.xlim([-0.01, 1.0])
    # plt.ylim([0.0, 1.05])
    # plt.xlabel('False Positive Rate')
    # plt.ylabel('True Positive Rate')
    # plt.title('Receiver Operating Characteristic (ROC)')
    # plt.legend(loc="lower right")
    # plt.tight_layout()
    # plt.grid()

    raise Exception

    attack_stages = ml_pipelines.config.GENERATION_ATTACK_STAGES

    start = 0.5
    stop = 3
    step = 0.5
    time_choices = np.arange(start, stop + step / 2, step, dtype=float).tolist()

    gd = global_detector.LifecycleDetector(
        cwd / "../data/models/syscall_clf.joblib",
        cwd / "../data/models/network_clf.joblib",
        cwd / "../data/models/hpc_clf.joblib"
    )

    malware_scores = []
    for _ in range(5):
        techniques = [random.choice(ttp_choices) for _, ttp_choices in attack_stages.items()]
        stage_lens = [(technique, random.choice(time_choices)) for technique in techniques]

        attack_X = build_cross_layer_X(feature_frames, stage_lens, window_size_time, window_stride_time, rng)
        cross_layer_X = cross_layer_concatenate(attack_X)

        proba = gd.score_cross_layer(cross_layer_X)
        malware_scores.append(proba)
        print(proba)

    benign_scores = []
    for _ in range(5):
        benign_stages = ml_pipelines.config.GENERATION_BENIGN
        techniques = [random.choice(benign_stages) for _ in range(4)]
        stage_lens = [(technique, random.choice(time_choices)) for technique in techniques]

        attack_X = build_cross_layer_X(feature_frames, stage_lens, window_size_time, window_stride_time, rng)
        cross_layer_X = cross_layer_concatenate(attack_X)

        proba = gd.score_cross_layer(cross_layer_X)
        benign_scores.append(proba)
        print(proba)


    # malware_scores = []
    # for _ in range(150):
    #     techniques = [random.choice(ttp_choices) for _, ttp_choices in attack_stages.items()]
    #     stage_lens = [(technique, random.choice(time_choices)) for technique in techniques]
    #
    #     attack_X = build_cross_layer_X(feature_frames, stage_lens, window_size_time, window_stride_time, rng)
    #     cross_layer_X = cross_layer_concatenate(attack_X)
    #
    #     proba = gd.score_cross_layer(cross_layer_X)
    #     malware_scores.append(proba)
    #
    #
    # # raise Exception
    #
    # length_check = 10
    # length_samples = 15
    # distance_measures = [[] for i in range(1, length_check)]
    # benign_scores = []
    #
    # for i in range(1, length_check):
    #     for j in range(length_samples):
    #
    #         benign_stages = ml_pipelines.config.GENERATION_BENIGN
    #         techniques = [random.choice(benign_stages) for _ in range(i)]
    #         stage_lens = [(technique, random.choice(time_choices)) for technique in techniques]
    #
    #         attack_X = build_cross_layer_X(feature_frames, stage_lens, window_size_time, window_stride_time, rng)
    #         cross_layer_X = cross_layer_concatenate(attack_X)
    #
    #         proba = gd.score_cross_layer(cross_layer_X)
    #         distance_measures[i-1].append(proba)
    #         benign_scores.append(proba)
    #
    # distance_measures = np.array(distance_measures)
    #
    # fig, ax = plt.subplots(figsize=(6, 4))
    # for i in range(distance_measures.shape[0]):
    #     x_values = [i + 1 for _ in range(distance_measures.shape[1])]
    #     sc = ax.scatter(x_values, distance_measures[i], cmap="viridis", alpha=0.75, edgecolors='none')
    #
    # # cb = plt.colorbar(sc, ax=ax)
    # # cb.set_label("Distance (c)")
    # ax.set_title("Scatter with Colorbar", pad=10)
    # ax.set_xlabel("X")
    # ax.set_ylabel("Y")
    # ax.grid(True, alpha=0.3)
    # fig.tight_layout()
    # plt.show(block=True)
    #
    #
    # y_scores = malware_scores + benign_scores
    # y_true = np.zeros(len(y_scores))
    # y_true[:len(malware_scores)] = 1
    #
    # fpr, tpr, thresholds = roc_curve(y_true, y_scores)
    # roc_auc = auc(fpr, tpr)
    #
    # plt.figure()
    # plt.plot(fpr, tpr, lw=2, label=f'ROC curve (AUC = {roc_auc:.2f})')
    # plt.plot([0, 1], [0, 1], lw=1, linestyle='--', label='Random guess')
    # plt.xlim([-0.01, 1.0])
    # plt.ylim([0.0, 1.05])
    # plt.xlabel('False Positive Rate')
    # plt.ylabel('True Positive Rate')
    # plt.title('Receiver Operating Characteristic (ROC)')
    # plt.legend(loc="lower right")
    # plt.tight_layout()
    # plt.grid()



    # TODO map classes of each clf back to attack_lifecycle classes
    #  - filter class stream
    #  - pull recycle hmm
    # TODO start here










