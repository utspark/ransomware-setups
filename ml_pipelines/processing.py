import matplotlib
from xgboost import XGBClassifier

matplotlib.use("Qt5Agg")
import matplotlib.pyplot as plt
plt.ion()

import os
import io

from pathlib import Path

import numpy as np
from sklearn.metrics import roc_auc_score, confusion_matrix, roc_curve, classification_report
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.utils import compute_class_weight

import tensorflow as tf
from tensorflow.keras.datasets import imdb
from tensorflow.keras.models import Sequential, load_model
from tensorflow.keras.layers import Dense
from tensorflow.keras.layers import LSTM, Reshape, Input
from tensorflow.keras.layers import Embedding
from tensorflow.keras.callbacks import EarlyStopping
from tensorflow.keras.preprocessing import sequence




def form_windows(array, window_size, window_stride, future_size=0, future_stride=1):
    """
    Returns Numpy array of sliding windows of a Numpy array (timeseries).
    https://towardsdatascience.com/fast-and-robust-sliding-window-vectorization-with-numpy-3ad950ed62f5
    """

    last_window = len(array) - window_size - future_size * future_stride + 1

    future_idxs = (
            np.expand_dims(np.arange(0, future_size * future_stride, future_stride), 0)
            + np.expand_dims(np.arange(window_size, window_size + last_window, window_stride), 1)
    )
    futures = array[future_idxs]

    window_idxs = (
            np.expand_dims(np.arange(window_size), 0)
            + np.expand_dims(np.arange(0, last_window, window_stride), 1)
    )
    windows = array[window_idxs]

    return windows, futures


def form_array_from_files(child_path, file_subsample=-1) -> np.array:
    if file_subsample == -1:
        file_subsample = 40

    files = [p for p in child_path.iterdir() if p.is_file()]
    files.sort()

    trace_list = []
    # TODO use all files
    for file_name in files[0:file_subsample]:
        print(file_name.name)
        file_path = str(file_name)

        with open(file_path, "r", newline="") as f:
            arr = np.loadtxt(f, dtype=int)
            trace_list.append(arr)

    # trace_list = trace_list[50]
    max_len = max(a.shape[0] for a in trace_list)

    # TODO think of proper padding approach
    padded = [
        np.pad(a,
               pad_width=(0, max_len - a.shape[0]),
               mode='constant',
               constant_values=0)
        for a in trace_list
    ]

    padded_matrix = np.vstack(padded)

    return padded_matrix


def form_one_hot_encoder(benign_array: np.array) -> OneHotEncoder:
    max_syscall = np.max(benign_array)
    one_hot_array = np.array(range(max_syscall))
    one_hot_array = one_hot_array.reshape(-1, 1)
    enc = OneHotEncoder(handle_unknown='ignore')
    enc.fit(one_hot_array)

    return enc


def increase_padding(pad_target, max_len) -> np.array:
    pad_len = max_len - pad_target.shape[1]
    pad_array = np.zeros((pad_target.shape[0], pad_len))
    padded = np.concatenate((pad_target, pad_array), axis=1)

    return padded


def unsupervised_preproc(mode: str) -> (np.array, np.array, np.array):
    benign, malware = preproc_transform(mode)

    X = benign
    y = np.zeros(len(X)) + 1

    X_train, X_test, _, y_test = train_test_split(
        X, y, test_size=0.3, random_state=42, stratify=y
    )

    X_test = np.concatenate((X_test, malware))

    malware_labels = np.zeros((len(malware))) - 1
    y_test = np.concatenate((y_test, malware_labels))

    return X_train, X_test, y_test


def preproc_transform_2(mode: str, regression=False) -> (np.array, np.array):
    VALID_MODES = {"zero-padded_trace", "syscall_frequency", "windowed_features", "windowed"}

    if mode not in VALID_MODES:
        raise ValueError(f"mode must be one of {sorted(VALID_MODES)!r}, got {mode!r}")

    if mode == "zero-padded_trace":
        benign, malware = full_trace_samples()

    elif mode == "syscall_frequency":
        benign, malware = full_trace_samples()
        syscalls = np.unique(benign)
        syscalls = np.sort(syscalls)

        benign = np.sum(benign[..., None] == syscalls, axis=1)
        malware = np.sum(malware[..., None] == syscalls, axis=1)

    elif mode == "windowed_features":
        benign, malware = window_samples()

        tmp_benign = np.zeros((benign.shape[0], 6))
        tmp_malware = np.zeros((malware.shape[0], 6))

        tmp_benign[:, 0] = np.max(benign, axis=1)
        tmp_benign[:, 1] = np.min(benign, axis=1)
        tmp_benign[:, 2] = np.median(benign, axis=1)
        tmp_benign[:, 3] = np.mean(benign, axis=1)
        tmp_benign[:, 4] = np.ptp(benign, axis=1)
        tmp_benign[:, 5] = np.std(benign, axis=1)

        tmp_malware[:, 0] = np.max(malware, axis=1)
        tmp_malware[:, 1] = np.min(malware, axis=1)
        tmp_malware[:, 2] = np.median(malware, axis=1)
        tmp_malware[:, 3] = np.mean(malware, axis=1)
        tmp_malware[:, 4] = np.ptp(malware, axis=1)
        tmp_malware[:, 5] = np.std(malware, axis=1)

        benign = tmp_benign
        malware = tmp_malware

    else:  # mode == "windowed"
        benign, malware = window_samples()

    return benign, malware


def full_trace_samples_2() -> (np.array, np.array):
    cwd = Path.cwd()
    benign_path = cwd / "ADFA-IDS_DATASETS/ADFA-LD/Training_Data_Master"
    benign_array = mpp.form_array_from_files(benign_path)
    benign_array = mpp.increase_padding(benign_array, MAX_LEN)


    trace_list = get_file_arrays(file_path, file_list)
    max_len = max(a.shape[0] for a in trace_list)

    # TODO think of proper padding approach
    padded = [
        np.pad(a,
               pad_width=(0, max_len - a.shape[0]),
               mode='constant',
               constant_values=0)
        for a in trace_list
    ]

    padded_matrix = np.vstack(padded)



    attack_dir = [
        "ADFA-IDS_DATASETS/ADFA-LD/Attack_Data_Master/Adduser_1",
        "ADFA-IDS_DATASETS/ADFA-LD/Attack_Data_Master/Adduser_2",
        "ADFA-IDS_DATASETS/ADFA-LD/Attack_Data_Master/Adduser_3"

    ]

    malware_array = []
    for dir in attack_dir:
        malware_path = cwd / dir
        tmp = mpp.form_array_from_files(malware_path)
        tmp = mpp.increase_padding(tmp, MAX_LEN)
        malware_array.append(tmp)
    malware_array = np.concatenate(malware_array)

    return benign_array, malware_array





from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional

@dataclass
class RegressionData:
    """
    A simple data container for four NumPy arrays.
    Each array defaults to an empty 1D float array if not provided.
    """
    benign_windows: np.ndarray = field(default_factory=lambda: np.empty((0,)))
    benign_futures: np.ndarray = field(default_factory=lambda: np.empty((0,)))
    malware_windows: np.ndarray = field(default_factory=lambda: np.empty((0,)))
    malware_futures: np.ndarray = field(default_factory=lambda: np.empty((0,)))


@dataclass
class ModelSettings:
    """
    A simple data container for model preprocessing settings.
    """
    problem_formulation: str = "regression"
    preproc_approach: str = None
    window_length: int = 20
    future_length: int = 1
    max_trace_length: int = None
    system_calls: np.ndarray = field(default_factory=lambda: np.empty((0,)))
    model_path: Path = None
    model_type: str = None
    new_model: bool = False
    plot: bool = False


def regression_error(model_settings: ModelSettings, regression_data: RegressionData):
    benign_wdws = regression_data.benign_windows
    benign_futures = regression_data.benign_futures
    malware_wdws = regression_data.malware_windows
    malware_futures = regression_data.malware_futures

    unique_vals = np.unique(benign_wdws.reshape(-1))
    new_labels = np.arange(len(unique_vals))
    max_val = unique_vals.max()
    lookup = np.full(max_val + 1, -1, dtype=int)
    lookup[unique_vals] = new_labels

    mapped_benign_wdws = lookup[benign_wdws]
    mapped_benign_futures = lookup[benign_futures]
    mapped_malware_wdws = lookup[malware_wdws]
    mapped_malware_futures = lookup[malware_futures]

    X_train, X_test, y_train, y_test = train_test_split(
        mapped_benign_wdws, mapped_benign_futures, test_size=0.3, random_state=42
    )

    X_test = np.concatenate((X_test, mapped_malware_wdws))
    y_test = np.concatenate((y_test, mapped_malware_futures))

    enc = form_one_hot_encoder(X_train)

    a, b = X_train.shape
    X_train = enc.transform(X_train.reshape(-1, 1)).toarray()
    X_train = X_train.reshape(a, b, -1)

    a, b = X_test.shape
    X_test = enc.transform(X_test.reshape(-1, 1)).toarray()
    X_test = X_test.reshape(a, b, -1)

    a, b = y_train.shape
    y_train = enc.transform(y_train.reshape(-1, 1)).toarray()
    y_train = y_train.reshape(a, b, -1)

    a, b = y_test.shape
    y_test = enc.transform(y_test.reshape(-1, 1)).toarray()
    y_test = y_test.reshape(a, b, -1)

    scaler = StandardScaler().fit(X_train.reshape(-1, 1))

    original_shape = X_train.shape
    X_train = scaler.transform(X_train.reshape(-1, 1))
    X_train = X_train.reshape(original_shape)

    original_shape = X_test.shape
    X_test = scaler.transform(X_test.reshape(-1, 1))
    X_test = X_test.reshape(original_shape)

    original_shape = y_train.shape
    y_train = scaler.transform(y_train.reshape(-1, 1))
    y_train = y_train.reshape(original_shape)

    original_shape = y_test.shape
    y_test = scaler.transform(y_test.reshape(-1, 1))
    y_test = y_test.reshape(original_shape)

    if not model_settings.new_model and os.path.exists(model_settings.model_path):
        print(f"Loading model from {model_settings.model_path}")
        model = load_model(model_settings.model_path)

    else:
        tf.random.set_seed(42)

        split = int(0.8 * len(X_train))
        X_train, X_val = X_train[:split], X_train[split:]
        y_train, y_val = y_train[:split], y_train[split:]

        early_stop = EarlyStopping(
            monitor='val_loss',  # which metric to watch
            patience=5,  # how many epochs with no improvement to wait
            min_delta=1e-4,  # minimum change to qualify as improvement
            restore_best_weights=True  # at end of training, restore the best weights
        )

        model = Sequential([
            # 1) Declare your input shape: 20 timesteps, num encoding features
            Input(shape=(model_settings.window_length, len(enc.categories_[0]))),
            # 2) (Optional) a Dense layer on each timestep
            #    This will output (batch, 20, 64)
            Dense(64, activation='relu'),
            # 3) LSTM over the 20 timesteps → returns (batch, 64)
            LSTM(64),
            # 4) Project that 64-vector up to 73 outputs → (batch, 73)
            Dense(len(enc.categories_[0]), activation='linear'),
            # 5) Re-insert the time dimension → (batch, 1, 73)
            Reshape((1, len(enc.categories_[0])))
        ])

        model.compile(loss='mean_squared_error', optimizer='adam')

        history = model.fit(
            X_train, y_train,
            validation_data=(X_val, y_val),
            epochs=300, batch_size=64, verbose=2,
            callbacks=[early_stop]
        )
        model.save(model_settings.model_path)

    y_pred = model.predict(X_test)
    deltas = np.abs(y_pred - y_test)
    deltas = np.sum(deltas, axis=2)

    if model_settings.plot:
        len_benign = len(y_test) - len(mapped_malware_wdws)
        benign_x = [i for i in range(len_benign)]
        benign_y = deltas[benign_x]

        len_malware = len(mapped_malware_wdws)
        malware_x = [i for i in range(len_benign, len_benign + len_malware)]
        malware_y = deltas[malware_x]

        fig, ax = plt.subplots(1, 1, figsize=(10, 4), sharey=True)
        # ax.plot(range(0, len(len_benign)), deltas[:len_benign], color="blue")
        ax.plot(benign_x, benign_y, color="blue")
        ax.plot(malware_x, malware_y, color="red")
        plt.tight_layout()
        plt.show()

    y_discrete = np.zeros((len(y_test)))
    y_discrete[len(y_discrete) - len(malware_futures):] = 1
    classes = np.unique(y_discrete)
    class_weights = compute_class_weight('balanced', classes=classes, y=y_discrete)
    sample_weights = class_weights[y_discrete.astype(int)]
    auc = roc_auc_score(y_discrete, deltas, sample_weight=sample_weights)
    print(f"ROC AUC Score: {auc:.3f}")


def trace_list_to_windows(model_settings: ModelSettings, trace_list: list):
    wdw_list = []
    future_list = []

    for trace in trace_list:
        wdws, futures = form_windows(
            trace,
            model_settings.window_length,
            1,
            model_settings.future_length,
            future_stride=1)

        wdw_list.append(wdws)
        future_list.append(futures)

    if len(wdw_list) > 1:
        wdws = np.concatenate(wdw_list)
        futures = np.concatenate(future_list)

    else:
        wdws = wdw_list[0]
        futures = future_list[0]

    return wdws, futures


def get_file_arrays(file_path: Path, file_list=None) -> list:
    trace_list = []

    paths = [p for p in file_path.iterdir() if p.is_file()]
    paths.sort()

    if file_list is not None:
        file_set = set(file_list)
        filtered = [path for path in paths if path.name in file_set]
        paths = filtered

    for file_name in paths:
        print(file_name.name)
        file_path = str(file_name)

        with open(file_path, "r", newline="") as f:
            lines = f.readlines()
            arr1 = np.loadtxt(io.StringIO(lines[0]), dtype=int)
            # arr2 = np.loadtxt(io.StringIO(lines[1]), dtype=float)
            trace_list.append(arr1)

    return trace_list


def get_windows_and_futures(model_settings: ModelSettings, file_dir: Path, file_list=None):
    trace_list = get_file_arrays(file_dir, file_list)
    windows, futures = trace_list_to_windows(model_settings, trace_list)

    return windows, futures


def full_trace_samples(model_settings: ModelSettings, file_dir: Path, file_list=None):
    trace_list = get_file_arrays(file_dir, file_list)
    trace_list = [arr[:model_settings.max_trace_length] for arr in trace_list]

    # TODO think of proper padding approach
    padded = [
        np.pad(a,
               pad_width=(0, model_settings.max_trace_length - a.shape[0]),
               mode='constant',
               constant_values=0)
        for a in trace_list
    ]

    padded_matrix = np.vstack(padded)

    return padded_matrix


def get_system_call_map(model_settings: ModelSettings, file_dir: Path, file_list=None) -> np.array:
    transformed = full_trace_samples(model_settings, file_dir, file_list)
    system_calls = np.unique(transformed)

    return np.sort(system_calls)


def preproc_transform(model_settings: ModelSettings, file_dir: Path, file_list=None) -> tuple:
    mode = model_settings.preproc_approach
    VALID_MODES = {"zero-padded_trace", "syscall_frequency", "windowed_features", "windowed"}

    if mode not in VALID_MODES:
        raise ValueError(f"mode must be one of {sorted(VALID_MODES)!r}, got {mode!r}")

    if mode == "zero-padded_trace":
        transformed = full_trace_samples(model_settings, file_dir, file_list)

    elif mode == "syscall_frequency":
        transformed = full_trace_samples(model_settings, file_dir, file_list)
        transformed = np.sum(transformed[..., None] == model_settings.syscalls, axis=1)

    elif mode == "windowed_features":
        windows, _ = get_windows_and_futures(model_settings, file_dir, file_list)

        feature_array = np.zeros((windows.shape[0], 6))
        feature_array[:, 0] = np.max(windows, axis=1)
        feature_array[:, 1] = np.min(windows, axis=1)
        feature_array[:, 2] = np.median(windows, axis=1)
        feature_array[:, 3] = np.mean(windows, axis=1)
        feature_array[:, 4] = np.ptp(windows, axis=1)
        feature_array[:, 5] = np.std(windows, axis=1)

        transformed = feature_array

    else:  # mode == "windowed"
        windows, futures = get_windows_and_futures(model_settings, file_dir, file_list)
        transformed = (windows, futures)

    return transformed


# def supervised_preproc(mode: str) -> (np.array, np.array):
#     benign, malware = preproc_transform(mode)
#
#     X = np.concatenate((benign, malware))
#     y = np.zeros((len(benign) + len(malware)))
#     y[len(benign):] = 1
#
#     return X, y


def supervised_error(model_settings: ModelSettings, benign: np.array, malware: np.array):
    model = model_settings.model_type

    VALID_MODELS = {"svc", "xgb", "lstm"}

    if model not in VALID_MODELS:
        raise ValueError(f"mode must be one of {sorted(VALID_MODELS)!r}, got {model!r}")

    X = np.concatenate((benign, malware))
    y = np.zeros((len(benign) + len(malware)))
    y[len(benign):] = 1

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.3, random_state=42, stratify=y
    )

    if model == "xgb":
        pipeline = XGBClassifier(
            objective='binary:logistic',  # logistic loss for binary classification
            n_estimators=100,  # number of trees
            max_depth=4,  # tree depth
            learning_rate=0.1,  # step size shrinkage
            subsample=0.8,  # row subsampling
            colsample_bytree=0.8,  # feature subsampling per tree
            use_label_encoder=False,  # disable legacy label encoder
            eval_metric='logloss',  # evaluation metric
            random_state=42
        )

    elif model == "svc":
        pipeline = make_pipeline(
            StandardScaler(),  # SVMs benefit from feature scaling
            SVC(
                kernel='rbf',  # radial basis function kernel
                C=1.0,  # regularization parameter
                gamma='scale',  # kernel coefficient
                probability=True,  # allow probability estimates
                class_weight="balanced",
            )
        )

    else: # model == "lstm"
        tf.random.set_seed(42)

        pipeline = LSTMWrapper(X_train)

        # embedding_vector_length = 32
        # model = Sequential()
        # model.add(Embedding(int(np.max(X)) + 1, embedding_vector_length))
        # model.add(LSTM(100))
        # model.add(Dense(1, activation='sigmoid'))
        # model.compile(loss='binary_crossentropy', optimizer='adam', metrics=['accuracy'])
        # model.fit(X_train, y_train, validation_data=(X_test, y_test), epochs=10, batch_size=64)
        # print(model.summary())


    pipeline.fit(X_train, y_train)

    y_pred = pipeline.predict(X_test)
    print("Confusion matrix:\n", confusion_matrix(y_test, y_pred))
    print("\nClassification report:\n", classification_report(y_test, y_pred))

    y_scores = pipeline.predict_proba(X_test)

    if y_scores.shape[1] > 1:
        y_scores = y_scores[:, 1]

    classes = np.unique(y)
    class_weights = compute_class_weight('balanced', classes=classes, y=y)
    sample_weights = class_weights[y_test.astype(int)]
    auc = roc_auc_score(y_test, y_scores, sample_weight=sample_weights)
    print(f"ROC AUC Score: {auc:.3f}")

    if model_settings.plot:
        fpr, tpr, thresholds = roc_curve(y_test, y_scores)

        plt.figure()
        plt.plot(fpr, tpr, label=f"ROC curve (area = {auc:.3f})")
        plt.plot([0, 1], [0, 1], linestyle="--", label="Random chance")
        plt.xlabel("False Positive Rate")
        plt.ylabel("True Positive Rate")
        plt.title("Receiver Operating Characteristic (ROC) Curve")
        plt.legend(loc="lower right")
        plt.grid(True)
        plt.show()




