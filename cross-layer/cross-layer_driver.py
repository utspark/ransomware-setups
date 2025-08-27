from pathlib import Path

from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier

import network_signals
import syscall_signals
import ml_pipelines.config
import numpy as np
import pandas as pd
import seaborn as sns

from sklearn.utils import compute_class_weight, compute_sample_weight
from sklearn.preprocessing import LabelBinarizer

from sklearn.metrics import roc_auc_score, confusion_matrix, roc_curve, classification_report, log_loss
from typing import Iterable, Mapping, Tuple, Optional, Dict, Literal, Any
from types import ModuleType

import matplotlib
matplotlib.use("Qt5Agg")
import matplotlib.pyplot as plt
plt.ion()


def files_and_labels_to_X_y(
    paths: Iterable[Path],
    signal_module: ModuleType,
    malware_map: Mapping[str, int],
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

    Returns
    -------
    X : np.ndarray
        Feature matrix of shape (total_windows, n_features).
    y : np.ndarray
        Integer labels of shape (total_windows,).
    """
    X_list: list[np.ndarray] = []
    y_list: list[np.ndarray] = []

    for p in paths:
        try:
            label = malware_map[p.name]
        except KeyError:
            if strict:
                raise KeyError(f"No label found in malware_map for file: {p.name}")
            else:
                continue

        try:
            df = signal_module.get_file_df(p)
            X_i = signal_module.file_df_feature_extraction(df, window_size_time, window_stride_time)
        except Exception as e:
            if strict:
                raise RuntimeError(f"Failed processing {p}") from e
            else:
                continue

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


if __name__ == "__main__":
    cwd = Path.cwd()
    SYSCALL = True
    NETWORK = False

    window_size_time = 0.1 / 10
    window_stride_time = 0.05 / 10

    if SYSCALL:
        syscall_dir = cwd / "../data/syscall_ints"
        syscall_paths = [p for p in syscall_dir.iterdir() if p.is_file()]
        syscall_paths.sort()

        MALWARE_DICT = ml_pipelines.config.MALWARE_DICT
        malware_keys = set(MALWARE_DICT.keys())
        filtered = [path for path in syscall_paths if path.name in malware_keys]
        syscall_paths = filtered

        X, y = files_and_labels_to_X_y(syscall_paths, syscall_signals, MALWARE_DICT, window_size_time,
                                       window_stride_time)

        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.3, random_state=42, stratify=y
        )
        train_sample_weights, test_sample_weights, _ = compute_train_test_sample_weights(y_train, y_test)

        dtree_model, lb = train_model(X_train, y_train, train_sample_weights)
        y_pred_ohe = dtree_model.predict_proba(X_test)

        results = prediction_analysis(y_test, y_pred_ohe, lb=lb, sample_weight=test_sample_weights, plot=True)
        print(f"Log Loss: {results['log_loss']}")
        print(f"Classification Report: {results['classification_report']}")


    if NETWORK:
        network_dir = cwd / "../data/v4_results/out_exec"
        network_paths = [p for p in network_dir.iterdir() if p.is_file()]
        network_paths.sort()

        MALWARE_DICT = ml_pipelines.config.MALWARE_DICT
        malware_keys = set(MALWARE_DICT.keys())
        filtered = [path for path in network_paths if path.name in malware_keys]
        network_paths = filtered

        X, y = files_and_labels_to_X_y(network_paths, syscall_signals, MALWARE_DICT, window_size_time,
                                       window_stride_time)

        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.3, random_state=42, stratify=y
        )
        train_sample_weights, test_sample_weights, _ = compute_train_test_sample_weights(y_train, y_test)

        dtree_model, lb = train_model(X_train, y_train, train_sample_weights)
        y_pred_ohe = dtree_model.predict_proba(X_test)

        results = prediction_analysis(y_test, y_pred_ohe, lb=lb, sample_weight=test_sample_weights, plot=True)
        print(f"Log Loss: {results['log_loss']}")
        print(f"Classification Report: {results['classification_report']}")



    # TODO
    #  - make sure files are matching between signal sources


