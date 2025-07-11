import matplotlib
import numpy as np
# from PyQt5.QtSql import password
from fontTools.ttLib.tables.S__i_l_f import content_string
from sklearn.covariance import EllipticEnvelope
from sklearn.ensemble import IsolationForest
from sklearn.metrics import confusion_matrix, classification_report, roc_auc_score, roc_curve
from sklearn.model_selection import train_test_split
from sklearn.neighbors import LocalOutlierFactor
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.svm import SVC, OneClassSVM
from sklearn.utils import compute_class_weight

import keras

import tensorflow as tf
from tensorflow.keras.datasets import imdb
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import Dense
from tensorflow.keras.layers import LSTM
from tensorflow.keras.layers import Embedding
from tensorflow.keras.preprocessing import sequence

matplotlib.use("Qt5Agg")
import matplotlib.pyplot as plt
plt.ion()

from pathlib import Path

import os

import ml_pipelines.processing as mpp

os.environ["QT_QPA_PLATFORM"] = "wayland"

import xgboost as xgb
from xgboost import XGBClassifier


def regression_preproc_transform():
    def trace_list_to_windows(trace_list):
        wdw_list = []
        future_list = []

        for trace in trace_list:
            wdws, futures = form_windows(trace, 10, 1, future_size=3, future_stride=1)
            wdw_list.append(wdws)
            future_list.append(futures)

        wdws = np.concatenate(wdw_list)
        futures = np.concatenate(future_list)

        return wdws, futures

    def get_file_arrays(files, file_subsample=-1) -> list:
        if file_subsample == -1:
            file_subsample = 40

        trace_list = []

        for file_name in files[0:file_subsample]:
            print(file_name.name)
            file_path = str(file_name)

            with open(file_path, "r", newline="") as f:
                arr = np.loadtxt(f, dtype=int)
                trace_list.append(arr)

        return trace_list

    cwd = Path.cwd()
    benign_path = cwd / "ADFA-IDS_DATASETS/ADFA-LD/Training_Data_Master"

    child_path = benign_path
    files = [p for p in child_path.iterdir() if p.is_file()]
    files.sort()

    trace_list = get_file_arrays(files)
    benign_wdws, benign_futures = trace_list_to_windows(trace_list)

    attack_dir = [
        "ADFA-IDS_DATASETS/ADFA-LD/Attack_Data_Master/Adduser_1",
        "ADFA-IDS_DATASETS/ADFA-LD/Attack_Data_Master/Adduser_2",
        "ADFA-IDS_DATASETS/ADFA-LD/Attack_Data_Master/Adduser_3"

    ]

    files = []
    for dir in attack_dir:
        malware_path = cwd / dir

        child_path = malware_path
        files += [p for p in child_path.iterdir() if p.is_file()]
        files.sort()

    trace_list = get_file_arrays(files)
    malware_wdws, malware_futures = trace_list_to_windows(trace_list)

    return benign_wdws, benign_futures, malware_wdws, malware_futures


def preproc_transform(mode: str, regression=False) -> (np.array, np.array):
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


def full_trace_samples() -> (np.array, np.array):
    cwd = Path.cwd()
    benign_path = cwd / "ADFA-IDS_DATASETS/ADFA-LD/Training_Data_Master"
    benign_array = mpp.form_array_from_files(benign_path)
    benign_array = mpp.increase_padding(benign_array, MAX_LEN)

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


def window_samples():
    def trace_list_to_windows(trace_list):
        wdw_list = []

        for trace in trace_list:
            wdws, _ = form_windows(trace, 10, 1, future_size=0, future_stride=1)
            wdw_list.append(wdws)

        wdws = np.concatenate(wdw_list)

        return wdws

    def get_file_arrays(files, file_subsample=-1) -> list:
        if file_subsample == -1:
            file_subsample = 40

        trace_list = []

        for file_name in files[0:file_subsample]:
            print(file_name.name)
            file_path = str(file_name)

            with open(file_path, "r", newline="") as f:
                arr = np.loadtxt(f, dtype=int)
                trace_list.append(arr)

        return trace_list

    cwd = Path.cwd()
    benign_path = cwd / "ADFA-IDS_DATASETS/ADFA-LD/Training_Data_Master"

    child_path = benign_path
    files = [p for p in child_path.iterdir() if p.is_file()]
    files.sort()

    trace_list = get_file_arrays(files)
    benign_wdws = trace_list_to_windows(trace_list)

    attack_dir = [
        "ADFA-IDS_DATASETS/ADFA-LD/Attack_Data_Master/Adduser_1",
        "ADFA-IDS_DATASETS/ADFA-LD/Attack_Data_Master/Adduser_2",
        "ADFA-IDS_DATASETS/ADFA-LD/Attack_Data_Master/Adduser_3"

    ]

    files = []
    for dir in attack_dir:
        malware_path = cwd / dir

        child_path = malware_path
        files += [p for p in child_path.iterdir() if p.is_file()]
        files.sort()

    trace_list = get_file_arrays(files)
    malware_wdws = trace_list_to_windows(trace_list)

    return benign_wdws, malware_wdws


def supervised_preproc(mode: str) -> (np.array, np.array):
    benign, malware = preproc_transform(mode)

    X = np.concatenate((benign, malware))
    y = np.zeros((len(benign) + len(malware)))
    y[len(benign):] = 1

    return X, y


class LSTMWrapper:
    """
    A simple example class.

    Attributes:
        name (str): a descriptive name.
        value (int): some numeric value.
    """

    def __init__(self, X_train: np.array):
        embedding_vector_length = 32
        self.model = Sequential()
        self.model.add(Embedding(int(np.max(X_train)) + 100, embedding_vector_length))
        self.model.add(LSTM(100))
        self.model.add(Dense(1, activation='sigmoid'))
        self.model.compile(loss='binary_crossentropy', optimizer='adam', metrics=['accuracy'])

    def fit(self, X: np.array, y: np.array) -> None:
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.3, random_state=42, stratify=y
        )
        self.model.fit(X_train, y_train, validation_data=(X_test, y_test), epochs=5, batch_size=64)

    def predict(self, X_test: np.array) -> np.array:
        probas = self.model.predict(X_test)
        return (probas > 0.5).astype(int).reshape(-1)

    def predict_probas(self, X_test: np.array) -> np.array:
        return self.model.predict(X_test)


def supervised_detector(preproc_mode: str, model: str):
    VALID_MODELS = {"svc", "xgb", "lstm"}

    if model not in VALID_MODELS:
        raise ValueError(f"mode must be one of {sorted(VALID_MODELS)!r}, got {model!r}")

    X, y = supervised_preproc(preproc_mode)

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
        tf.random.set_seed(7)

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

    y_scores = pipeline.predict_probas(X_test)

    if y_scores.shape[1] > 1:
        y_scores = y_scores[:, 1]

    classes = np.unique(y)
    class_weights = compute_class_weight('balanced', classes=classes, y=y)
    sample_weights = class_weights[y_test.astype(int)]
    auc = roc_auc_score(y_test, y_scores, sample_weight=sample_weights)
    print(f"ROC AUC Score: {auc:.3f}")

    # Compute ROC curve points
    fpr, tpr, thresholds = roc_curve(y_test, y_scores)

    # Plot the ROC curve
    plt.figure()
    plt.plot(fpr, tpr, label=f"ROC curve (area = {auc:.3f})")
    plt.plot([0, 1], [0, 1], linestyle="--", label="Random chance")
    plt.xlabel("False Positive Rate")
    plt.ylabel("True Positive Rate")
    plt.title("Receiver Operating Characteristic (ROC) Curve")
    plt.legend(loc="lower right")
    plt.grid(True)
    plt.show()


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


def unsupervised_detector(preproc_mode: str, model: str):
    VALID_MODELS = {
        "isolation_forest",
        "minimum_covariance_determinant",
        "local_outlier_factor",
        "svc",
        "lstm"
    }

    if model not in VALID_MODELS:
        raise ValueError(f"mode must be one of {sorted(VALID_MODELS)!r}, got {model!r}")

    if preproc_mode != "windowed" and model == "lstm":
        raise ValueError(f"preproc mode must be one of windowed when using lstm")

    X_train, X_test, y_test = unsupervised_preproc(preproc_mode)

    scaler = StandardScaler().fit(X_train)
    X_train = scaler.transform(X_train)
    X_test = scaler.transform(X_test)


    if model == "isolation_forest":
        model = IsolationForest(contamination=0.01)

    elif model == "minimum_covariance_determinant":
        model = EllipticEnvelope(contamination=0.01)

    elif model == "local_outlier_factor":
        model = LocalOutlierFactor(contamination=0.01, novelty=True)

    elif model == "lstm":
        pass

    else: # model == "svc"
        model = OneClassSVM(kernel='rbf', gamma='scale', nu=0.05)

    model.fit(X_train)
    y_pred = model.score_samples(X_test)

    classes = np.unique(y_test)
    class_weights = compute_class_weight('balanced', classes=classes, y=y_test)
    sample_weights = class_weights[y_test.astype(int)]
    auc = roc_auc_score(y_test, y_pred, sample_weight=sample_weights)
    print(f"ROC AUC Score: {auc:.3f}")

    fig, ax = plt.subplots(1, 1, figsize=(10, 4), sharey=True)
    ax.plot(y_pred, marker='o', linestyle="None")
    plt.tight_layout()
    plt.show()


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




if __name__ == "__main__":
    MAX_LEN = 1560

    # {"zero-padded_trace", "syscall_frequency", "windowed_features","windowed"}

    # {"svc", "xgb", "lstm"}
    # supervised_detector(preproc_mode="windowed", model="lstm")

    # {
    #     "isolation_forest",
    #     "minimum_covariance_determinant",
    #     "local_outlier_factor",
    #     "svc"
    #     "lstm"
    # }
    # unsupervised_detector(preproc_mode="windowed_features", model="isolation_forest")

    # benign, malware = preproc_transform("windowed")
    # benign, malware = window_samples()
    benign_wdws, benign_futures, malware_wdws, malware_futures = regression_preproc_transform()

    X_train, X_test, y_train, y_test = train_test_split(
        benign_wdws, benign_futures, test_size=0.3, random_state=42
    )

    X_test = np.concatenate((X_test, malware_wdws))
    y_test = np.concatenate((y_test, malware_futures))


    # input_scaler = StandardScaler().fit(X_train)
    # output_scaler
    # X_train = scaler.transform(X_train)
    # X_test = scaler.transform(X_test)

    # embedding_vector_length = 32
    # model = Sequential()
    # model.add(Embedding(int(np.max(X_train)) + 100, embedding_vector_length))
    # model.add(LSTM(100))
    # model.add(Dense(1, activation='sigmoid'))
    # model.compile(loss='mean_squared_error', optimizer='adam', metrics=['accuracy'])

    # from tensorflow.keras.layers import Input
    # input_tensor = Input(shape=(10,))


    window_len = X_train.shape[1]
    future_len = y_train.shape[1]

    scaler = StandardScaler().fit(X_train.reshape(-1, 1))

    X_train = scaler.transform(X_train.reshape(-1, 1))
    X_train = X_train.reshape(-1, window_len)

    X_test = scaler.transform(X_test.reshape(-1, 1))
    X_test = X_test.reshape(-1, window_len)

    y_train = scaler.transform(y_train.reshape(-1, 1))
    y_train = y_train.reshape(-1, future_len)

    y_test = scaler.transform(y_test.reshape(-1, 1))
    y_test = y_test.reshape(-1, future_len)


    model = Sequential()
    model.add(keras.Input(shape=(10, 1)))
    model.add(LSTM(32))
    model.add(Dense(3))
    model.compile(loss='mean_squared_error', optimizer='adam')

    model.fit(X_train, y_train, epochs=150, batch_size=32, verbose=2)

    y_pred = model.predict(X_test)



    raise Exception


    # TODO
    #  - START HERE
    #  - ADFA-IDS LD dictionary approach
    #  - one-hot-encode then temporal models




    # max_len = benign_array.shape[1]
    # padded_matrix = benign_array.reshape(-1, 1)
    # padded_matrix = padded_matrix.reshape(-1, max_len)
    # enc = mpp.form_one_hot_encoder(benign_array)
    # X = enc.transform(padded_matrix).toarray()
    # X = X.reshape(-1, max_len, max_syscall)


    # """
    # The words have been replaced by integers that indicate the ordered frequency of each word in the dataset.
    # The sentences in each review are therefore comprised of a sequence of integers.
    # """
    # from collections import Counter
    # all_vals = X.ravel()
    # counts = Counter(all_vals)
    # sorted_vals = [val for val, _ in counts.most_common()]
    # mapping = {val: rank for rank, val in enumerate(sorted_vals)}
    # X = np.vectorize(mapping.__getitem__)(X)





