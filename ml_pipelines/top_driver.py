import matplotlib
import numpy as np
import tensorflow as tf
# from PyQt5.QtSql import password
from sklearn.covariance import EllipticEnvelope
from sklearn.ensemble import IsolationForest
from sklearn.metrics import confusion_matrix, classification_report, roc_auc_score, roc_curve
from sklearn.model_selection import train_test_split
from sklearn.neighbors import LocalOutlierFactor
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.svm import SVC, OneClassSVM
from sklearn.utils import compute_class_weight
from tensorflow.keras.callbacks import EarlyStopping
from tensorflow.keras.layers import Dense
from tensorflow.keras.layers import Embedding
from tensorflow.keras.layers import LSTM, Reshape, Input
from tensorflow.keras.models import Sequential, load_model

matplotlib.use("Qt5Agg")
import matplotlib.pyplot as plt
plt.ion()

from pathlib import Path

import os

import ml_pipelines.processing as mpp

os.environ["QT_QPA_PLATFORM"] = "wayland"

from xgboost import XGBClassifier


def regression_preproc_transform():
    def trace_list_to_windows(trace_list):
        wdw_list = []
        future_list = []

        for trace in trace_list:
            wdws, futures = form_windows(trace, WDW_LEN, 1, future_size=FUTURE_LEN, future_stride=1)
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
            wdws, _ = mpp.form_windows(trace, 10, 1, future_size=0, future_stride=1)
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
        "svc"
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


def regression_error():
    benign_wdws, benign_futures, malware_wdws, malware_futures = regression_preproc_transform()

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

    enc = mpp.form_one_hot_encoder(X_train)

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

    if LOAD_SAVED and os.path.exists(model_path):
        print(f"Loading model from {model_path}")
        model = load_model(model_path)

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
            # 1) Declare your input shape: 20 timesteps, 73 features
            Input(shape=(WDW_LEN, 73)),
            # 2) (Optional) a Dense layer on each timestep
            #    This will output (batch, 20, 64)
            Dense(64, activation='relu'),
            # 3) LSTM over the 20 timesteps → returns (batch, 64)
            LSTM(64),
            # 4) Project that 64-vector up to 73 outputs → (batch, 73)
            Dense(73, activation='linear'),
            # 5) Re-insert the time dimension → (batch, 1, 73)
            Reshape((1, 73))
        ])

        model.compile(loss='mean_squared_error', optimizer='adam')

        history = model.fit(
            X_train, y_train,
            validation_data=(X_val, y_val),
            epochs=300, batch_size=64, verbose=2,
            callbacks=[early_stop]
        )
        model.save(model_path)

    y_pred = model.predict(X_test)
    deltas = np.abs(y_pred - y_test)
    deltas = np.sum(deltas, axis=2)

    fig, ax = plt.subplots(1, 1, figsize=(10, 4), sharey=True)
    ax.plot(deltas, color="blue")
    plt.tight_layout()
    plt.show()

    y_discrete = np.zeros((len(y_test)))
    y_discrete[len(y_discrete) - len(malware_futures):] = 1
    classes = np.unique(y_discrete)
    class_weights = compute_class_weight('balanced', classes=classes, y=y_discrete)
    sample_weights = class_weights[y_discrete.astype(int)]
    auc = roc_auc_score(y_discrete, deltas, sample_weight=sample_weights)
    print(f"ROC AUC Score: {auc:.3f}")








if __name__ == "__main__":
    MAX_LEN = 1560
    WDW_LEN = 20  # 10
    FUTURE_LEN = 1  # 3
    LOAD_SAVED = True
    cwd = Path.cwd()
    model_path = cwd / "basic_lstm.h5"


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

    # regression_error()

    # raise Exception

    # TODO start here
    # https://huggingface.co/blog/time-series-transformers
    # https://docs.pytorch.org/tutorials/beginner/basics/quickstart_tutorial.html
    # https://www.geeksforgeeks.org/python/start-learning-pytorch-for-beginners/


    # raise Exception
    from datasets import load_dataset

    dataset = load_dataset("monash_tsf", "tourism_monthly")

    """As can be seen, the dataset contains 3 splits: train, validation and test."""

    dataset

    """Each example contains a few keys, of which `start` and `target` are the most important ones. Let us have a look at the first time series in the dataset:"""

    train_example = dataset["train"][0]
    train_example.keys()

    """The `start` simply indicates the start of the time series (as a datetime), and the `target` contains the actual values of the time series.

    The `start` will be useful to add time related features to the time series values, as extra input to the model (such as "month of year"). Since we know the frequency of the data is `monthly`, we know for instance that the second value has the timestamp `1979-02-01`, etc.
    """

    print(train_example["start"])
    print(train_example["target"])

    """The validation set contains the same data as the training set, just for a `prediction_length` longer amount of time. This allows us to validate the model's predictions against the ground truth.

    The test set is again one `prediction_length` longer data compared to the validation set (or some multiple of  `prediction_length` longer data compared to the training set for testing on multiple rolling windows).
    """

    validation_example = dataset["validation"][0]
    validation_example.keys()

    """The initial values are exactly the same as the corresponding training example:"""

    print(validation_example["start"])
    print(validation_example["target"])

    """However, this example has `prediction_length=24` additional values compared to the training example. Let us verify it."""

    freq = "1M"
    prediction_length = 24

    assert len(train_example["target"]) + prediction_length == len(
        validation_example["target"]
    )

    """Let's visualize this:"""

    import matplotlib.pyplot as plt

    figure, axes = plt.subplots()
    axes.plot(train_example["target"], color="blue")
    axes.plot(validation_example["target"], color="red", alpha=0.5)

    plt.show()

    """Let's split up the data:"""

    train_dataset = dataset["train"]
    test_dataset = dataset["test"]

    """## Update `start` to `pd.Period`

    The first thing we'll do is convert the `start` feature of each time series to a pandas `Period` index using the data's `freq`:
    """

    from functools import lru_cache

    import pandas as pd
    import numpy as np


    @lru_cache(10_000)
    def convert_to_pandas_period(date, freq):
        return pd.Period(date, freq)


    def transform_start_field(batch, freq):
        batch["start"] = [convert_to_pandas_period(date, freq) for date in batch["start"]]
        return batch


    """We now use `datasets`' [`set_transform`](https://huggingface.co/docs/datasets/v2.7.0/en/package_reference/main_classes#datasets.Dataset.set_transform) functionality to do this on-the-fly in place:"""

    from functools import partial

    # raise Exception

    train_dataset.set_transform(partial(transform_start_field, freq=freq))
    test_dataset.set_transform(partial(transform_start_field, freq=freq))

    """## Define the model

    Next, let's instantiate a model. The model will be trained from scratch, hence we won't use the `from_pretrained` method here, but rather randomly initialize the model from a [`config`](https://huggingface.co/docs/transformers/model_doc/time_series_transformer#transformers.TimeSeriesTransformerConfig).

    We specify a couple of additional parameters to the model:
    - `prediction_length` (in our case, `24` months): this is the horizon that the decoder of the Transformer will learn to predict for;
    - `context_length`: the model will set the `context_length` (input of the encoder) equal to the `prediction_length`, if no `context_length` is specified;
    - `lags` for a given frequency: these specify how much we "look back", to be added as additional features. e.g. for a `Daily` frequency we might consider a look back of `[1, 2, 7, 30, ...]` or in other words look back 1, 2, ... days while for `Minute` data we might consider `[1, 30, 60, 60*24, ...]` etc.;
    - the number of time features: in our case, this will be `2` as we'll add `MonthOfYear` and `Age` features;
    - the number of static categorical features: in our case, this will be just `1` as we'll add a single "time series ID" feature;
    - the cardinality: the number of values of each static categorical feature, as a list which for our case will be `[366]` as we have 366 different time series
    - the embedding dimension: the embedding dimension for each static categorical feature, as a list, for example `[3]` meaning the model will learn an embedding vector of size `3` for each of the `366` time series (regions).

    Let's use the default lags provided by GluonTS for the given frequency ("monthly"):
    """

    from gluonts.time_feature import get_lags_for_frequency

    lags_sequence = get_lags_for_frequency(freq)
    print(lags_sequence)

    """This means that we'll look back up to 37 months for each time step, as additional features.

    Let's also check the default time features which GluonTS provides us:
    """

    from gluonts.time_feature import time_features_from_frequency_str

    time_features = time_features_from_frequency_str(freq)
    print(time_features)

    """In this case, there's only a single feature, namely "month of year". This means that for each time step, we'll add the month as a scalar value (e.g. `1` in case the timestamp is "january", `2` in case the timestamp is "february", etc.).

    We now have everything to define the model:
    """

    from transformers import TimeSeriesTransformerConfig, TimeSeriesTransformerForPrediction

    config = TimeSeriesTransformerConfig(
        prediction_length=prediction_length,
        # context length:
        context_length=prediction_length * 2,
        # lags coming from helper given the freq:
        lags_sequence=lags_sequence,
        # we'll add 2 time features ("month of year" and "age", see further):
        num_time_features=len(time_features) + 1,
        # we have a single static categorical feature, namely time series ID:
        num_static_categorical_features=1,
        # it has 366 possible values:
        cardinality=[len(train_dataset)],
        # the model will learn an embedding of size 2 for each of the 366 possible values:
        embedding_dimension=[2],

        # transformer params:
        encoder_layers=4,
        decoder_layers=4,
        d_model=32,
    )

    model = TimeSeriesTransformerForPrediction(config)

    """Note that, similar to other models in the 🤗 Transformers library, [`TimeSeriesTransformerModel`](https://huggingface.co/docs/transformers/model_doc/time_series_transformer#transformers.TimeSeriesTransformerModel) corresponds to the encoder-decoder Transformer without any head on top, and [`TimeSeriesTransformerForPrediction`](https://huggingface.co/docs/transformers/model_doc/time_series_transformer#transformers.TimeSeriesTransformerForPrediction) corresponds to `TimeSeriesTransformerModel` with a **distribution head** on top. By default, the model uses a Student-t distribution (but this is configurable):"""

    model.config.distribution_output

    """This is an important difference with Transformers for NLP, where the head typically consists of a fixed categorical distribution implemented as an `nn.Linear` layer.

    ## Define Transformations

    Next, we define the transformations for the data, in particular for the creation of the time features (based on the dataset or universal ones).

    Again, we'll use the GluonTS library for this. We define a `Chain` of transformations (which is a bit comparable to `torchvision.transforms.Compose` for images). It allows us to combine several transformations into a single pipeline.
    """

    from gluonts.time_feature import (
        time_features_from_frequency_str,
        TimeFeature,
        get_lags_for_frequency,
    )
    from gluonts.dataset.field_names import FieldName
    from gluonts.transform import (
        AddAgeFeature,
        AddObservedValuesIndicator,
        AddTimeFeatures,
        AsNumpyArray,
        Chain,
        ExpectedNumInstanceSampler,
        InstanceSplitter,
        RemoveFields,
        SelectFields,
        SetField,
        TestSplitSampler,
        Transformation,
        ValidationSplitSampler,
        VstackFeatures,
        RenameFields,
    )

    """The transformations below are annotated with comments, to explain what they do. At a high level, we will iterate over the individual time series of our dataset and add/remove fields or features:"""

    from transformers import PretrainedConfig


    def create_transformation(freq: str, config: PretrainedConfig) -> Transformation:
        remove_field_names = []
        if config.num_static_real_features == 0:
            remove_field_names.append(FieldName.FEAT_STATIC_REAL)
        if config.num_dynamic_real_features == 0:
            remove_field_names.append(FieldName.FEAT_DYNAMIC_REAL)
        if config.num_static_categorical_features == 0:
            remove_field_names.append(FieldName.FEAT_STATIC_CAT)

        # a bit like torchvision.transforms.Compose
        return Chain(
            # step 1: remove static/dynamic fields if not specified
            [RemoveFields(field_names=remove_field_names)]
            # step 2: convert the data to NumPy (potentially not needed)
            + (
                [
                    AsNumpyArray(
                        field=FieldName.FEAT_STATIC_CAT,
                        expected_ndim=1,
                        dtype=int,
                    )
                ]
                if config.num_static_categorical_features > 0
                else []
            )
            + (
                [
                    AsNumpyArray(
                        field=FieldName.FEAT_STATIC_REAL,
                        expected_ndim=1,
                    )
                ]
                if config.num_static_real_features > 0
                else []
            )
            + [
                AsNumpyArray(
                    field=FieldName.TARGET,
                    # we expect an extra dim for the multivariate case:
                    expected_ndim=1 if config.input_size == 1 else 2,
                ),
                # step 3: handle the NaN's by filling in the target with zero
                # and return the mask (which is in the observed values)
                # true for observed values, false for nan's
                # the decoder uses this mask (no loss is incurred for unobserved values)
                # see loss_weights inside the xxxForPrediction model
                AddObservedValuesIndicator(
                    target_field=FieldName.TARGET,
                    output_field=FieldName.OBSERVED_VALUES,
                ),
                # step 4: add temporal features based on freq of the dataset
                # month of year in the case when freq="M"
                # these serve as positional encodings
                AddTimeFeatures(
                    start_field=FieldName.START,
                    target_field=FieldName.TARGET,
                    output_field=FieldName.FEAT_TIME,
                    time_features=time_features_from_frequency_str(freq),
                    pred_length=config.prediction_length,
                ),
                # step 5: add another temporal feature (just a single number)
                # tells the model where in the life the value of the time series is
                # sort of running counter
                AddAgeFeature(
                    target_field=FieldName.TARGET,
                    output_field=FieldName.FEAT_AGE,
                    pred_length=config.prediction_length,
                    log_scale=True,
                ),
                # step 6: vertically stack all the temporal features into the key FEAT_TIME
                VstackFeatures(
                    output_field=FieldName.FEAT_TIME,
                    input_fields=[FieldName.FEAT_TIME, FieldName.FEAT_AGE]
                                 + (
                                     [FieldName.FEAT_DYNAMIC_REAL]
                                     if config.num_dynamic_real_features > 0
                                     else []
                                 ),
                ),
                # step 7: rename to match HuggingFace names
                RenameFields(
                    mapping={
                        FieldName.FEAT_STATIC_CAT: "static_categorical_features",
                        FieldName.FEAT_STATIC_REAL: "static_real_features",
                        FieldName.FEAT_TIME: "time_features",
                        FieldName.TARGET: "values",
                        FieldName.OBSERVED_VALUES: "observed_mask",
                    }
                ),
            ]
        )


    """## Define `InstanceSplitter`

    For training/validation/testing we next create an `InstanceSplitter` which is used to sample windows from the dataset (as, remember, we can't pass the entire history of values to the Transformer due to time- and memory constraints).

    The instance splitter samples random `context_length` sized and subsequent `prediction_length` sized windows from the data, and appends a `past_` or `future_` key to any temporal keys in `time_series_fields` for the respective windows. The instance splitter can be configured into three different modes:
    1. `mode="train"`: Here we sample the context and prediction length windows randomly from the dataset given to it (the training dataset)
    2. `mode="validation"`: Here we sample the very last context length window and prediction window from the dataset given to it (for the back-testing or validation likelihood calculations)
    3. `mode="test"`: Here we sample the very last context length window only (for the prediction use case)
    """

    from gluonts.transform.sampler import InstanceSampler
    from typing import Optional


    def create_instance_splitter(
            config: PretrainedConfig,
            mode: str,
            train_sampler: Optional[InstanceSampler] = None,
            validation_sampler: Optional[InstanceSampler] = None,
    ) -> Transformation:
        assert mode in ["train", "validation", "test"]

        instance_sampler = {
            "train": train_sampler
                     or ExpectedNumInstanceSampler(
                num_instances=1.0, min_future=config.prediction_length
            ),
            "validation": validation_sampler
                          or ValidationSplitSampler(min_future=config.prediction_length),
            "test": TestSplitSampler(),
        }[mode]

        return InstanceSplitter(
            target_field="values",
            is_pad_field=FieldName.IS_PAD,
            start_field=FieldName.START,
            forecast_start_field=FieldName.FORECAST_START,
            instance_sampler=instance_sampler,
            past_length=config.context_length + max(config.lags_sequence),
            future_length=config.prediction_length,
            time_series_fields=["time_features", "observed_mask"],
        )


    """## Create DataLoaders

    Next, it's time to create the DataLoaders, which allow us to have batches of (input, output pairs) - or in other words (`past_values`, `future_values`).
    """

    from typing import Iterable

    import torch
    from gluonts.itertools import Cyclic, Cached
    from gluonts.dataset.loader import as_stacked_batches


    def create_train_dataloader(
            config: PretrainedConfig,
            freq,
            data,
            batch_size: int,
            num_batches_per_epoch: int,
            shuffle_buffer_length: Optional[int] = None,
            cache_data: bool = True,
            **kwargs,
    ) -> Iterable:
        PREDICTION_INPUT_NAMES = [
            "past_time_features",
            "past_values",
            "past_observed_mask",
            "future_time_features",
        ]
        if config.num_static_categorical_features > 0:
            PREDICTION_INPUT_NAMES.append("static_categorical_features")

        if config.num_static_real_features > 0:
            PREDICTION_INPUT_NAMES.append("static_real_features")

        TRAINING_INPUT_NAMES = PREDICTION_INPUT_NAMES + [
            "future_values",
            "future_observed_mask",
        ]

        transformation = create_transformation(freq, config)
        transformed_data = transformation.apply(data, is_train=True)
        if cache_data:
            transformed_data = Cached(transformed_data)

        # we initialize a Training instance
        instance_splitter = create_instance_splitter(config, "train")

        # the instance splitter will sample a window of
        # context length + lags + prediction length (from the 366 possible transformed time series)
        # randomly from within the target time series and return an iterator.
        stream = Cyclic(transformed_data).stream()
        training_instances = instance_splitter.apply(stream)

        return as_stacked_batches(
            training_instances,
            batch_size=batch_size,
            shuffle_buffer_length=shuffle_buffer_length,
            field_names=TRAINING_INPUT_NAMES,
            output_type=torch.tensor,
            num_batches_per_epoch=num_batches_per_epoch,
        )


    def create_backtest_dataloader(
            config: PretrainedConfig,
            freq,
            data,
            batch_size: int,
            **kwargs,
    ):
        PREDICTION_INPUT_NAMES = [
            "past_time_features",
            "past_values",
            "past_observed_mask",
            "future_time_features",
        ]
        if config.num_static_categorical_features > 0:
            PREDICTION_INPUT_NAMES.append("static_categorical_features")

        if config.num_static_real_features > 0:
            PREDICTION_INPUT_NAMES.append("static_real_features")

        transformation = create_transformation(freq, config)
        transformed_data = transformation.apply(data)

        # We create a Validation Instance splitter which will sample the very last
        # context window seen during training only for the encoder.
        instance_sampler = create_instance_splitter(config, "validation")

        # we apply the transformations in train mode
        testing_instances = instance_sampler.apply(transformed_data, is_train=True)

        return as_stacked_batches(
            testing_instances,
            batch_size=batch_size,
            output_type=torch.tensor,
            field_names=PREDICTION_INPUT_NAMES,
        )


    """We have a test dataloader helper for completion, even though we will not use it here. This is useful in a production setting where we want to start forecasting from the end of a given time series. Thus, the test dataloader will sample the very last context window from the dataset provided and pass it to the model."""


    def create_test_dataloader(
            config: PretrainedConfig,
            freq,
            data,
            batch_size: int,
            **kwargs,
    ):
        PREDICTION_INPUT_NAMES = [
            "past_time_features",
            "past_values",
            "past_observed_mask",
            "future_time_features",
        ]
        if config.num_static_categorical_features > 0:
            PREDICTION_INPUT_NAMES.append("static_categorical_features")

        if config.num_static_real_features > 0:
            PREDICTION_INPUT_NAMES.append("static_real_features")

        transformation = create_transformation(freq, config)
        transformed_data = transformation.apply(data, is_train=False)

        # We create a test Instance splitter to sample the very last
        # context window from the dataset provided.
        instance_sampler = create_instance_splitter(config, "test")

        # We apply the transformations in test mode
        testing_instances = instance_sampler.apply(transformed_data, is_train=False)

        return as_stacked_batches(
            testing_instances,
            batch_size=batch_size,
            output_type=torch.tensor,
            field_names=PREDICTION_INPUT_NAMES,
        )


    train_dataloader = create_train_dataloader(
        config=config,
        freq=freq,
        data=train_dataset,
        batch_size=256,
        num_batches_per_epoch=100,
    )

    test_dataloader = create_backtest_dataloader(
        config=config,
        freq=freq,
        data=test_dataset,
        batch_size=64,
    )

    """Let's check the first batch:"""

    batch = next(iter(train_dataloader))
    for k, v in batch.items():
        print(k, v.shape, v.type())

    """As can be seen, we don't feed `input_ids` and `attention_mask` to the encoder (as would be the case for NLP models), but rather `past_values`, along with `past_observed_mask`, `past_time_features`, and `static_categorical_features`.

    The decoder inputs consist of `future_values`, `future_observed_mask` and `future_time_features`. The `future_values` can be seen as the equivalent of `decoder_input_ids` in NLP.

    We refer to the [docs](https://huggingface.co/docs/transformers/model_doc/time_series_transformer#transformers.TimeSeriesTransformerForPrediction.forward.past_values) for a detailed explanation for each of them.

    ## Forward pass

    Let's perform a single forward pass with the batch we just created:
    """

    # perform forward pass
    outputs = model(
        past_values=batch["past_values"],
        past_time_features=batch["past_time_features"],
        past_observed_mask=batch["past_observed_mask"],
        static_categorical_features=batch["static_categorical_features"]
        if config.num_static_categorical_features > 0
        else None,
        static_real_features=batch["static_real_features"]
        if config.num_static_real_features > 0
        else None,
        future_values=batch["future_values"],
        future_time_features=batch["future_time_features"],
        future_observed_mask=batch["future_observed_mask"],
        output_hidden_states=True,
    )

    print("Loss:", outputs.loss.item())

    """Note that the model is returning a loss. This is possible as the decoder automatically shifts the `future_values` one position to the right in order to have the labels. This allows computing a loss between the predicted values and the labels.

    Also note that the decoder uses a causal mask to not look into the future as the values it needs to predict are in the `future_values` tensor.

    ## Train the Model

    It's time to train the model! We'll use a standard PyTorch training loop.

    We will use the 🤗 [Accelerate](https://huggingface.co/docs/accelerate/index) library here, which automatically places the model, optimizer and dataloader on the appropriate `device`.
    """

    from accelerate import Accelerator
    from torch.optim import AdamW

    accelerator = Accelerator()
    device = accelerator.device

    model.to(device)
    optimizer = AdamW(model.parameters(), lr=6e-4, betas=(0.9, 0.95), weight_decay=1e-1)

    model, optimizer, train_dataloader = accelerator.prepare(
        model,
        optimizer,
        train_dataloader,
    )

    model.train()
    for epoch in range(3):
        for idx, batch in enumerate(train_dataloader):
            optimizer.zero_grad()
            outputs = model(
                static_categorical_features=batch["static_categorical_features"].to(device)
                if config.num_static_categorical_features > 0
                else None,
                static_real_features=batch["static_real_features"].to(device)
                if config.num_static_real_features > 0
                else None,
                past_time_features=batch["past_time_features"].to(device),
                past_values=batch["past_values"].to(device),
                future_time_features=batch["future_time_features"].to(device),
                future_values=batch["future_values"].to(device),
                past_observed_mask=batch["past_observed_mask"].to(device),
                future_observed_mask=batch["future_observed_mask"].to(device),
            )
            loss = outputs.loss

            # Backpropagation
            accelerator.backward(loss)
            optimizer.step()

            if idx % 100 == 0:
                print(loss.item())

    """## Inference

    At inference time, it's recommended to use the `generate()` method for autoregressive generation, similar to NLP models.

    Forecasting involves getting data from the test instance sampler, which will sample the very last `context_length` sized window of values from each time series in the dataset, and pass it to the model. Note that we pass `future_time_features`, which are known ahead of time, to the decoder.

    The model will autoregressively sample a certain number of values from the predicted distribution and pass them back to the decoder to return the prediction outputs:
    """

    model.eval()

    forecasts = []

    for batch in test_dataloader:
        outputs = model.generate(
            static_categorical_features=batch["static_categorical_features"].to(device)
            if config.num_static_categorical_features > 0
            else None,
            static_real_features=batch["static_real_features"].to(device)
            if config.num_static_real_features > 0
            else None,
            past_time_features=batch["past_time_features"].to(device),
            past_values=batch["past_values"].to(device),
            future_time_features=batch["future_time_features"].to(device),
            past_observed_mask=batch["past_observed_mask"].to(device),
        )
        forecasts.append(outputs.sequences.cpu().numpy())

    """The model outputs a tensor of shape (`batch_size`, `number of samples`, `prediction length`).

    In this case, we get `100` possible values for the next `24` months (for each example in the batch which is of size `64`):
    """

    forecasts[0].shape

    """We'll stack them vertically, to get forecasts for all time-series in the test dataset:"""

    forecasts = np.vstack(forecasts)
    print(forecasts.shape)

    """We can evaluate the resulting forecast with respect to the ground truth out of sample values present in the test set. For that, we'll use the 🤗 [Evaluate](https://huggingface.co/docs/evaluate/index) library, which includes the [MASE](https://huggingface.co/spaces/evaluate-metric/mase) and [sMAPE](https://huggingface.co/spaces/evaluate-metric/smape) metrics.

    We calculate both metrics for each time series in the dataset:
    """

    from evaluate import load
    from gluonts.time_feature import get_seasonality

    mase_metric = load("evaluate-metric/mase")
    smape_metric = load("evaluate-metric/smape")

    forecast_median = np.median(forecasts, 1)

    mase_metrics = []
    smape_metrics = []
    for item_id, ts in enumerate(test_dataset):
        training_data = ts["target"][:-prediction_length]
        ground_truth = ts["target"][-prediction_length:]
        mase = mase_metric.compute(
            predictions=forecast_median[item_id],
            references=np.array(ground_truth),
            training=np.array(training_data),
            periodicity=get_seasonality(freq),
        )
        mase_metrics.append(mase["mase"])

        # smape = smape_metric.compute(
        #     predictions=forecast_median[item_id],
        #     references=np.array(ground_truth),
        # )
        # smape_metrics.append(smape["smape"])

    print(f"MASE: {np.mean(mase_metrics)}")

    # print(f"sMAPE: {np.mean(smape_metrics)}")

    """We can also plot the individual metrics of each time series in the dataset and observe that a handful of time series contribute a lot to the final test metric:"""

    # plt.scatter(mase_metrics, smape_metrics, alpha=0.3)
    # plt.xlabel("MASE")
    # plt.ylabel("sMAPE")
    # plt.show()

    """To plot the prediction for any time series with respect the ground truth test data we define the following helper:"""

    import matplotlib.dates as mdates


    def plot(ts_index):
        fig, ax = plt.subplots()

        index = pd.period_range(
            start=test_dataset[ts_index][FieldName.START],
            periods=len(test_dataset[ts_index][FieldName.TARGET]),
            freq=freq,
        ).to_timestamp()

        # Major ticks every half year, minor ticks every month,
        ax.xaxis.set_major_locator(mdates.MonthLocator(bymonth=(1, 7)))
        ax.xaxis.set_minor_locator(mdates.MonthLocator())

        ax.plot(
            index[-2 * prediction_length:],
            test_dataset[ts_index]["target"][-2 * prediction_length:],
            label="actual",
        )

        plt.plot(
            index[-prediction_length:],
            np.median(forecasts[ts_index], axis=0),
            label="median",
        )

        plt.fill_between(
            index[-prediction_length:],
            forecasts[ts_index].mean(0) - forecasts[ts_index].std(axis=0),
            forecasts[ts_index].mean(0) + forecasts[ts_index].std(axis=0),
            alpha=0.3,
            interpolate=True,
            label="+/- 1-std",
        )
        plt.legend()
        plt.show()


    """For example:"""

    plot(334)

    raise Exception




    # TODO
    #  - START HERE
    #  - ADFA-IDS LD dictionary approach


