import matplotlib
from sklearn.covariance import EllipticEnvelope
from sklearn.ensemble import IsolationForest
from sklearn.metrics import roc_auc_score
from sklearn.neighbors import LocalOutlierFactor
from sklearn.pipeline import make_pipeline
from sklearn.svm import OneClassSVM, SVC
from sklearn.utils import compute_class_weight
from xgboost import XGBClassifier

matplotlib.use("Qt5Agg")
import matplotlib.pyplot as plt
plt.ion()

import os

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import roc_auc_score, confusion_matrix, roc_curve, classification_report, log_loss
from sklearn.tree import DecisionTreeClassifier

from tensorflow.keras.utils import to_categorical


from ml_pipelines.processing import form_one_hot_encoder
from ml_pipelines.timeseries_processing import ModelSettings, RegressionData
import numpy as np
import pandas as pd
import seaborn as sns

from sklearn.preprocessing import label_binarize
from sklearn.preprocessing import LabelBinarizer

import tensorflow as tf
from tensorflow.keras.datasets import imdb
from tensorflow.keras.models import Sequential, load_model
from tensorflow.keras.layers import Dense
from tensorflow.keras.layers import LSTM, Reshape, Input
from tensorflow.keras.layers import Embedding
from tensorflow.keras.callbacks import EarlyStopping
from tensorflow.keras.preprocessing import sequence


def roc_auc_plot(y_test: np.array, y_scores: np.array, sample_weight=None) -> None:
    auc = roc_auc_score(y_test, y_scores, sample_weight=sample_weight)

    fpr, tpr, thresholds = roc_curve(y_test, y_scores)

    plt.figure()
    plt.plot(fpr, tpr, label=f"ROC curve (area = {auc:.3f})")
    plt.plot([0, 1], [0, 1], linestyle="--", label="Random chance")
    plt.xlabel("False Positive Rate")
    plt.ylabel("True Positive Rate")
    plt.title("Receiver Operating Characteristic (ROC) Curve")
    plt.legend(loc="lower right")
    plt.grid(True)
    plt.show(block=True)

    return


def score_plot(y_pred: np.array, malware_test: np.array):
    len_benign = len(y_pred) - len(malware_test)
    benign_x = [i for i in range(len_benign)]
    benign_y = y_pred[benign_x]

    len_malware = len(malware_test)
    malware_x = [i for i in range(len_benign, len_benign + len_malware)]
    malware_y = y_pred[malware_x]

    fig, ax = plt.subplots(1, 1, figsize=(10, 4), sharey=True)
    ax.plot(benign_x, benign_y, color="blue")
    ax.plot(malware_x, malware_y, color="red")
    plt.tight_layout()
    plt.show(block=True)

    return


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
        score_plot(deltas, mapped_malware_wdws)

        # len_benign = len(y_test) - len(mapped_malware_wdws)
        # benign_x = [i for i in range(len_benign)]
        # benign_y = deltas[benign_x]
        #
        # len_malware = len(mapped_malware_wdws)
        # malware_x = [i for i in range(len_benign, len_benign + len_malware)]
        # malware_y = deltas[malware_x]
        #
        # fig, ax = plt.subplots(1, 1, figsize=(10, 4), sharey=True)
        # # ax.plot(range(0, len(len_benign)), deltas[:len_benign], color="blue")
        # ax.plot(benign_x, benign_y, color="blue")
        # ax.plot(malware_x, malware_y, color="red")
        # plt.tight_layout()
        # plt.show(block=True)

    y_discrete = np.zeros((len(y_test)))
    y_discrete[len(y_discrete) - len(malware_futures):] = 1
    classes = np.unique(y_discrete)
    class_weights = compute_class_weight('balanced', classes=classes, y=y_discrete)
    sample_weights = class_weights[y_discrete.astype(int)]

    y_test = y_discrete
    y_scores = deltas
    auc = roc_auc_score(y_test, y_scores, sample_weight=sample_weights)
    print(f"ROC AUC Score: {auc:.3f}")

    if model_settings.plot:
        roc_auc_plot(y_test, y_scores, sample_weights)

    return


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

    def predict_proba(self, X_test: np.array) -> np.array:
        return self.model.predict(X_test)


def binary_supervised_error(model_settings: ModelSettings, benign: np.array, malware: np.array) -> None:
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
        roc_auc_plot(y_test, y_scores, sample_weights)

    return


def unsupervised_error(model_settings: ModelSettings, benign: np.array, malware: np.array):
    VALID_MODELS = {
        "isolation_forest",
        "minimum_covariance_determinant",
        "local_outlier_factor",
        "svc"
    }

    if model_settings.model_type not in VALID_MODELS:
        raise ValueError(f"mode must be one of {sorted(VALID_MODELS)!r}, got {model_settings.model_type !r}")

    if model_settings.preproc_approach != "windowed" and model_settings.model_type == "lstm":
        raise ValueError(f"preproc mode must be one of windowed when using lstm")

    X_train, X_test = train_test_split(
        benign, test_size=0.3, random_state=42
    )

    y_test = np.zeros((len(X_test) + len(malware)))
    y_test[:len(X_test)] = 1
    X_test = np.concatenate((X_test, malware))

    scaler = StandardScaler().fit(X_train)
    X_train = scaler.transform(X_train)
    X_test = scaler.transform(X_test)

    if model_settings.model_type == "isolation_forest":
        model = IsolationForest(contamination=0.01)

    elif model_settings.model_type == "minimum_covariance_determinant":
        model = EllipticEnvelope(contamination=0.01)

    elif model_settings.model_type == "local_outlier_factor":
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

    if model_settings.plot:
        score_plot(y_pred, malware)
        roc_auc_plot(y_test, y_pred, sample_weights)

    return


def multiclass_error(model_settings: ModelSettings, X: np.array, y: np.array):
    y = y.astype(int)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.3, random_state=42, stratify=y
    )

    classes = np.unique(y_train)
    class_weights = compute_class_weight('balanced', classes=classes, y=y_train)
    sample_weights = class_weights[y_train.astype(int)]

    lb = LabelBinarizer()
    lb.fit(y_train)
    y_test_ohe = lb.transform(y_test)

    dtree_model = DecisionTreeClassifier(max_depth=5).fit(X_train, y_train, sample_weight=sample_weights)
    y_pred_ohe = dtree_model.predict_proba(X_test)

    classes = np.unique(y_test)
    class_weights = compute_class_weight('balanced', classes=classes, y=y_test)
    sample_weights = class_weights[y_test.astype(int)]

    loss_ohe = log_loss(y_test_ohe, y_pred_ohe, sample_weight=sample_weights)
    print(f"Log Loss Score: {loss_ohe:.3f}")
    y_pred = lb.inverse_transform(y_pred_ohe)

    print(classification_report(y_test, y_pred, sample_weight=sample_weights))

    if model_settings.plot:
        cm = confusion_matrix(y_test, y_pred, sample_weight=sample_weights, normalize='true')
        cm_df = pd.DataFrame(cm)

        # 4) Plot with seaborn
        plt.figure(figsize=(8, 6))
        sns.heatmap(
            cm_df,
            annot=True,  # write the counts (or rates) in each cell
            fmt='.2f',  # integer format; use '.2f' if you normalized
            cmap='Blues',  # color map
            cbar_kws={'label': 'Normalized Count'}
        )
        plt.ylabel('Actual')
        plt.xlabel('Predicted')
        plt.title('Confusion Matrix')
        plt.tight_layout()
        plt.show(block=True)

    return



