from pathlib import Path
import joblib
import numpy as np
import os
import matplotlib
import matplotlib.pyplot as plt
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler, LabelBinarizer
from sklearn.metrics import roc_auc_score, confusion_matrix, roc_curve, classification_report, log_loss
from sklearn.tree import DecisionTreeClassifier
from sklearn.covariance import EllipticEnvelope
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor
from sklearn.pipeline import make_pipeline
from sklearn.svm import OneClassSVM, SVC
from sklearn.utils import compute_class_weight
from xgboost import XGBClassifier
import pandas as pd
import seaborn as sns

# Optional TensorFlow imports
try:
    import tensorflow as tf
    from tensorflow.keras.models import Sequential, load_model
    from tensorflow.keras.layers import Dense, LSTM, Reshape, Input, Embedding
    from tensorflow.keras.callbacks import EarlyStopping
    TF_AVAILABLE = True
except ImportError:
    TF_AVAILABLE = False

from detector_framework.data_processing.processing import (
    ModelSettings, RegressionData, get_windows_and_futures, preproc_transform, form_one_hot_encoder
)

# Configure Matplotlib
if os.environ.get('DISPLAY', '') == '':
    matplotlib.use('Agg')
else:
    try:
        matplotlib.use('Qt5Agg')
    except ImportError:
        matplotlib.use('Agg')
plt.ion()


def get_keyword_filenames(keyword, file_dir: Path):
    """
    Retrieve a list of filenames in a provided directory matching keyword.
    """
    keywords = {keyword} if isinstance(keyword, str) else set(keyword)
    return [p.name for p in file_dir.iterdir() if p.is_file() and any(kw in p.name for kw in keywords)]


def validate_settings(model_settings: ModelSettings, valid_models: set, valid_modes: set):
    if model_settings.model_type not in valid_models:
        raise ValueError(f"model_type must be one of {sorted(valid_models)!r}, got {model_settings.model_type!r}")

    if model_settings.preproc_approach not in valid_modes:
        raise ValueError(f"preproc_approach must be one of {sorted(valid_modes)!r}, got {model_settings.preproc_approach!r}")

    if model_settings.model_type not in str(model_settings.model_path):
        raise AssertionError(f"model_type {model_settings.model_type!r} not in model_path {model_settings.model_path!r}")


def calculate_sample_weights(y):
    classes = np.unique(y)
    class_weights = compute_class_weight('balanced', classes=classes, y=y)
    return class_weights[y.astype(int)]


def roc_auc_plot(y_test: np.ndarray, y_scores: np.ndarray, sample_weight=None) -> None:
    auc = roc_auc_score(y_test, y_scores, sample_weight=sample_weight)
    fpr, tpr, _ = roc_curve(y_test, y_scores)

    plt.figure()
    plt.plot(fpr, tpr, label=f"ROC curve (area = {auc:.3f})")
    plt.plot([0, 1], [0, 1], linestyle="--", label="Random chance")
    plt.xlabel("False Positive Rate")
    plt.ylabel("True Positive Rate")
    plt.title("Receiver Operating Characteristic (ROC) Curve")
    plt.legend(loc="lower right")
    plt.grid(True)
    plt.show(block=True)


def score_plot(y_pred: np.ndarray, malware_test: np.ndarray):
    len_benign = len(y_pred) - len(malware_test)
    benign_x = np.arange(len_benign)
    benign_y = y_pred[benign_x]

    len_malware = len(malware_test)
    malware_x = np.arange(len_benign, len_benign + len_malware)
    malware_y = y_pred[malware_x]

    _, ax = plt.subplots(1, 1, figsize=(10, 4), sharey=True)
    ax.plot(benign_x, benign_y, color="blue")
    ax.plot(malware_x, malware_y, color="red")
    plt.tight_layout()
    plt.show(block=True)


if TF_AVAILABLE:
    class LSTMWrapper:
        def __init__(self, X_train: np.ndarray):
            embedding_vector_length = 32
            self.model = Sequential()
            self.model.add(Embedding(int(np.max(X_train)) + 100, embedding_vector_length))
            self.model.add(LSTM(100))
            self.model.add(Dense(1, activation='sigmoid'))
            self.model.compile(loss='binary_crossentropy', optimizer='adam', metrics=['accuracy'])

        def fit(self, X: np.ndarray, y: np.ndarray) -> None:
            X_train, X_test, y_train, y_test = train_test_split(
                X, y, test_size=0.3, random_state=42, stratify=y
            )
            self.model.fit(X_train, y_train, validation_data=(X_test, y_test), epochs=5, batch_size=64)

        def predict(self, X_test: np.ndarray) -> np.ndarray:
            probas = self.model.predict(X_test)
            return (probas > 0.5).astype(int).reshape(-1)

        def predict_proba(self, X_test: np.ndarray) -> np.ndarray:
            return self.model.predict(X_test)
else:
    class LSTMWrapper:
        def __init__(self, *args, **kwargs):
            raise ImportError("TensorFlow is not available for LSTMWrapper")


def regression_error(model_settings: ModelSettings, regression_data: RegressionData):
    if not TF_AVAILABLE:
        raise ImportError("TensorFlow is required for regression_error (LSTM)")

    benign_wdws = regression_data.benign_windows
    benign_futures = regression_data.benign_futures
    malware_wdws = regression_data.malware_windows
    malware_futures = regression_data.malware_futures

    unique_vals = np.unique(benign_wdws.reshape(-1))
    lookup = np.full(unique_vals.max() + 1, -1, dtype=int)
    lookup[unique_vals] = np.arange(len(unique_vals))

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

    def encode_and_reshape(data):
        a, b = data.shape
        encoded = enc.transform(data.reshape(-1, 1)).toarray()
        return encoded.reshape(a, b, -1)

    X_train = encode_and_reshape(X_train)
    X_test = encode_and_reshape(X_test)
    y_train = encode_and_reshape(y_train)
    y_test = encode_and_reshape(y_test)

    scaler = StandardScaler().fit(X_train.reshape(-1, 1))

    def scale_and_reshape(data):
        original_shape = data.shape
        scaled = scaler.transform(data.reshape(-1, 1))
        return scaled.reshape(original_shape)

    X_train = scale_and_reshape(X_train)
    X_test = scale_and_reshape(X_test)
    y_train = scale_and_reshape(y_train)
    y_test = scale_and_reshape(y_test)

    if not model_settings.new_model and os.path.exists(model_settings.model_path):
        print(f"Loading model from {model_settings.model_path}")
        model = load_model(model_settings.model_path)
    else:
        tf.random.set_seed(42)

        split = int(0.8 * len(X_train))
        X_train_final, X_val = X_train[:split], X_train[split:]
        y_train_final, y_val = y_train[:split], y_train[split:]

        early_stop = EarlyStopping(
            monitor='val_loss',
            patience=5,
            min_delta=1e-4,
            restore_best_weights=True
        )

        model = Sequential([
            Input(shape=(model_settings.window_length, len(enc.categories_[0]))),
            Dense(64, activation='relu'),
            LSTM(64),
            Dense(len(enc.categories_[0]), activation='linear'),
            Reshape((1, len(enc.categories_[0])))
        ])

        model.compile(loss='mean_squared_error', optimizer='adam')
        model.fit(
            X_train_final, y_train_final,
            validation_data=(X_val, y_val),
            epochs=300, batch_size=64, verbose=2,
            callbacks=[early_stop]
        )
        model.save(model_settings.model_path)

    y_pred = model.predict(X_test)
    deltas = np.sum(np.abs(y_pred - y_test), axis=2)

    if model_settings.plot:
        score_plot(deltas, mapped_malware_wdws)

    y_discrete = np.zeros(len(y_test))
    y_discrete[-len(malware_futures):] = 1
    sample_weights = calculate_sample_weights(y_discrete)

    auc = roc_auc_score(y_discrete, deltas, sample_weight=sample_weights)
    print(f"ROC AUC Score: {auc:.3f}")

    if model_settings.plot:
        roc_auc_plot(y_discrete, deltas, sample_weights)


def binary_supervised_error(model_settings: ModelSettings, benign: np.ndarray, malware: np.ndarray) -> None:
    model_type = model_settings.model_type

    X = np.concatenate((benign, malware))
    y = np.zeros(len(benign) + len(malware))
    y[len(benign):] = 1

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.3, random_state=42, stratify=y
    )

    if model_type == "xgb":
        pipeline = XGBClassifier(
            objective='binary:logistic',
            n_estimators=100,
            max_depth=4,
            learning_rate=0.1,
            subsample=0.8,
            colsample_bytree=0.8,
            eval_metric='logloss',
            random_state=42
        )
    elif model_type == "svc":
        pipeline = make_pipeline(
            StandardScaler(),
            SVC(kernel='rbf', probability=True, class_weight="balanced")
        )
    elif model_type == "lstm":
        if not TF_AVAILABLE:
            raise ImportError("TensorFlow is required for LSTM models")
        tf.random.set_seed(42)
        pipeline = LSTMWrapper(X_train)
    else:
        raise ValueError(f"Unknown model_type: {model_type}")

    pipeline.fit(X_train, y_train)

    y_pred = pipeline.predict(X_test)
    print("Confusion matrix:\n", confusion_matrix(y_test, y_pred))
    print("\nClassification report:\n", classification_report(y_test, y_pred))

    y_scores = pipeline.predict_proba(X_test)
    if y_scores.ndim > 1 and y_scores.shape[1] > 1:
        y_scores = y_scores[:, 1]

    sample_weights = calculate_sample_weights(y_test)
    auc = roc_auc_score(y_test, y_scores, sample_weight=sample_weights)
    print(f"ROC AUC Score: {auc:.3f}")

    if model_settings.plot:
        roc_auc_plot(y_test, y_scores, sample_weights)


def unsupervised_error(model_settings: ModelSettings, benign: np.ndarray, malware: np.ndarray):
    model_type = model_settings.model_type

    X_train, X_test_benign = train_test_split(benign, test_size=0.3, random_state=42)

    X_test = np.concatenate((X_test_benign, malware))
    y_test = np.zeros(len(X_test))
    y_test[:len(X_test_benign)] = 1

    scaler = StandardScaler().fit(X_train)
    X_train = scaler.transform(X_train)
    X_test = scaler.transform(X_test)

    models = {
        "isolation_forest": IsolationForest(contamination=0.01),
        "minimum_covariance_determinant": EllipticEnvelope(contamination=0.01),
        "local_outlier_factor": LocalOutlierFactor(contamination=0.01, novelty=True),
        "svc": OneClassSVM(kernel='rbf', gamma='scale', nu=0.05)
    }

    if model_type not in models:
        raise ValueError(f"Unknown model_type: {model_type}")

    model = models[model_type]
    model.fit(X_train)
    y_pred = model.score_samples(X_test)

    sample_weights = calculate_sample_weights(y_test)
    auc = roc_auc_score(y_test, y_pred, sample_weight=sample_weights)
    print(f"ROC AUC Score: {auc:.3f}")

    if model_settings.plot:
        score_plot(y_pred, malware)
        roc_auc_plot(y_test, y_pred, sample_weights)


def multiclass_error(model_settings: ModelSettings, X: np.ndarray, y: np.ndarray):
    y = y.astype(int)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.3, random_state=42, stratify=y
    )

    sample_weights_train = calculate_sample_weights(y_train)

    lb = LabelBinarizer()
    lb.fit(y_train)
    y_test_ohe = lb.transform(y_test)

    dtree_model = DecisionTreeClassifier(max_depth=7).fit(X_train, y_train, sample_weight=sample_weights_train)
    y_pred_probas = dtree_model.predict_proba(X_test)

    sample_weights_test = calculate_sample_weights(y_test)

    loss_ohe = log_loss(y_test_ohe, y_pred_probas, sample_weight=sample_weights_test)
    print(f"Log Loss Score: {loss_ohe:.5f}")

    y_pred = lb.inverse_transform(y_pred_probas)
    print(classification_report(y_test, y_pred, sample_weight=sample_weights_test))

    if model_settings.plot:
        cm = confusion_matrix(y_test, y_pred, sample_weight=sample_weights_test, normalize='true')
        plt.figure(figsize=(8, 6))
        sns.heatmap(pd.DataFrame(cm), annot=True, fmt='.2f', cmap='Blues',
                    cbar_kws={'label': 'Normalized Count'})
        plt.ylabel('Actual')
        plt.xlabel('Predicted')
        plt.title('Confusion Matrix')
        plt.tight_layout()
        plt.show(block=True)

    model_path = Path(model_settings.model_path)
    model_path.parent.mkdir(parents=True, exist_ok=True)
    settings_path = Path(model_settings.settings_path)
    settings_path.parent.mkdir(parents=True, exist_ok=True)

    joblib.dump(dtree_model, model_settings.model_path, compress=("zlib", 3))
    joblib.dump(model_settings, model_settings.settings_path, compress=("zlib", 3))

    return loss_ohe


def regression_analysis(model_settings, benign_path, benign_list, malware_path, malware_list):
    validate_settings(model_settings, {"lstm"}, {"windowed"})
    benign_wdws, benign_futures = get_windows_and_futures(model_settings, benign_path, benign_list)
    malware_wdws, malware_futures = get_windows_and_futures(model_settings, malware_path, malware_list)

    malware_wdws = malware_wdws[:5000]
    malware_futures = malware_futures[:5000]

    regression_data = RegressionData(benign_wdws, benign_futures, malware_wdws, malware_futures)
    regression_error(model_settings, regression_data)


def binary_supervised_analysis(model_settings, benign_path, benign_list, malware_path, malware_list):
    validate_settings(model_settings, {"svc", "xgb", "lstm"},
                      {"zero-padded_trace", "syscall_frequency", "windowed_features", "windowed"})
    benign_transformed = preproc_transform(model_settings, benign_path, benign_list)
    malware_transformed = preproc_transform(model_settings, malware_path, malware_list)

    if model_settings.preproc_approach == "windowed":
        benign_transformed = benign_transformed[0]
        malware_transformed = malware_transformed[0]

    malware_transformed = malware_transformed[:5000]

    binary_supervised_error(model_settings, benign_transformed, malware_transformed)


def unsupervised_analysis(model_settings, benign_path, benign_list, malware_path, malware_list):
    validate_settings(model_settings, {"isolation_forest", "minimum_covariance_determinant", "local_outlier_factor", "svc"},
                      {"zero-padded_trace", "syscall_frequency", "windowed_features", "windowed"})
    benign_transformed = preproc_transform(model_settings, benign_path, benign_list)
    malware_transformed = preproc_transform(model_settings, malware_path, malware_list)

    if model_settings.preproc_approach == "windowed":
        benign_transformed = benign_transformed[0]
        malware_transformed = malware_transformed[0]

    malware_transformed = malware_transformed[:5000]

    unsupervised_error(model_settings, benign_transformed, malware_transformed)


def multiclass_analysis(model_settings, benign_path, benign_dict: dict, malware_path, malware_dict: dict):
    transformed_data = []
    labels = []

    for key, val in {**benign_dict, **malware_dict}.items():
        path = benign_path if key in benign_dict else malware_path
        tmp_list = get_keyword_filenames(val, path)
        transformed = preproc_transform(model_settings, path, tmp_list)
        transformed_data.append(transformed)
        labels.append(np.full(len(transformed), key))

    X = np.concatenate(transformed_data)
    y = np.concatenate(labels)

    return multiclass_error(model_settings, X, y)


def get_prescored_predictions(stage_keys: list, stage_windows: list, prescored_dir: Path) -> (np.ndarray, np.ndarray):
    trace_classes = []
    trace_values = []

    for ttp, window_seq_len in zip(stage_keys, stage_windows):
        prescored_path = prescored_dir / f"{ttp}_prescored.joblib"
        label_class, label_val = joblib.load(prescored_path)

        idx = np.random.randint(0, len(label_class) - window_seq_len)

        trace_classes.append(label_class[idx:idx + window_seq_len])
        trace_values.append(label_val[idx:idx + window_seq_len])

    return np.concatenate(trace_classes), np.concatenate(trace_values)


def get_live_predictions(stage_keys: list, stage_windows: list, classifier, model_settings: ModelSettings,
                         malware_path: Path) -> (np.ndarray, np.ndarray):
    trace_classes = []
    trace_values = []

    for ttp, window_seq_len in zip(stage_keys, stage_windows):
        malware_list = get_keyword_filenames(ttp, malware_path)
        transformed = preproc_transform(model_settings, malware_path, malware_list)

        idx = np.random.randint(0, len(transformed) - window_seq_len)
        transformed = transformed[idx:idx + window_seq_len]

        y_pred_ohe = classifier.predict_proba(transformed)
        label_class = np.argmax(y_pred_ohe, axis=1)
        label_val = y_pred_ohe[np.arange(len(label_class)), label_class]

        trace_classes.append(label_class)
        trace_values.append(label_val)

    return np.concatenate(trace_classes), np.concatenate(trace_values)
