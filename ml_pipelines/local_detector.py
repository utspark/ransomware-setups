from pathlib import Path

import joblib
import numpy as np

from ml_pipelines import config
from ml_pipelines.timeseries_processing import ModelSettings, preproc_transform


def get_prescored_predictions(stage_keys: list, stage_windows: list, prescored_dir: Path) -> (np.ndarray, np.array):
    rng = np.random.default_rng()
    trace_classes = []
    trace_values = []

    for ttp, window_seq_len in zip(stage_keys, stage_windows):
        prescored_filename = ttp + "_prescored.joblib"
        prescored_path = prescored_dir / prescored_filename
        label_class, label_val = joblib.load(prescored_path)

        idx = rng.integers(0, len(label_class) - window_seq_len)

        tmp_class = label_class[idx:idx + window_seq_len]
        tmp_val = label_val[idx:idx + window_seq_len]

        trace_classes.append(tmp_class)
        trace_values.append(tmp_val)

    trace_classes = np.concatenate(trace_classes)
    trace_values = np.concatenate(trace_values)

    return trace_classes, trace_values


def get_live_predictions(stage_keys: list, stage_windows: list, classifier, model_settings: ModelSettings,
                         malware_path: Path) -> (np.ndarray, np.array):
    trace_classes = []
    trace_values = []

    for ttp, window_seq_len in zip(stage_keys, stage_windows):
        rng = np.random.default_rng()
        malware_list = config.TTP_DICT[ttp]
        transformed = preproc_transform(model_settings, malware_path, malware_list)

        idx = rng.integers(0, len(transformed) - window_seq_len)
        transformed = transformed[idx:idx + window_seq_len]

        y_pred_ohe = classifier.predict_proba(transformed)
        label_class = np.argmax(y_pred_ohe, axis=1)
        label_val = y_pred_ohe[np.arange(y_pred_ohe.shape[0]), label_class]

        trace_classes.append(label_class)
        trace_values.append(label_val)

    trace_classes = np.concatenate(trace_classes)
    trace_values = np.concatenate(trace_values)

    return trace_classes, trace_values