from pathlib import Path

import joblib
import numpy as np

from ml_pipelines import local_detector, global_detector, config
from ml_pipelines.timeseries_processing import preproc_transform

if __name__ == "__main__":
    PRESCORE = False
    USE_PRESCORE = False

    cwd = Path.cwd()

    settings_path = "../data/saved_models/multiclass_supervised_windowed_features_decision_tree_settings.joblib"
    model_settings = joblib.load(settings_path)
    model_settings.model_path = "../data/saved_models/multiclass_supervised_windowed_features_decision_tree.joblib"
    classifier = joblib.load(model_settings.model_path)

    prescored_dir = cwd / "../data/prescored_windows"

    malware_path = cwd / "../data/syscall_ints"

    ttp_dict = config.TTP_DICT
    generation_attack_stages = config.GENERATION_ATTACK_STAGES


    if PRESCORE:
        for ttp in ttp_dict:
            prescored_filename = ttp + "_prescored.joblib"
            prescored_path = prescored_dir / prescored_filename

            malware_list = ttp_dict[ttp]
            transformed = preproc_transform(model_settings, malware_path, malware_list)

            y_pred_ohe = classifier.predict_proba(transformed)
            label_class = np.argmax(y_pred_ohe, axis=1)
            label_val = y_pred_ohe[np.arange(y_pred_ohe.shape[0]), label_class]

            prescored_predictions = (label_class, label_val)
            joblib.dump(prescored_predictions, prescored_path, compress=("zlib", 3))

    # *** global_detector
    gd = global_detector.LifecycleDetector()

    for i in range(5):
        # *** generate a sequence
        stage_keys, stage_windows = global_detector.form_lifecycle_sequence(generation_attack_stages, benign=False)

        if USE_PRESCORE:
            trace_classes, trace_values = local_detector.get_prescored_predictions(
                stage_keys, stage_windows, prescored_dir)

        else:
            trace_classes, trace_values = local_detector.get_live_predictions(
                stage_keys, stage_windows, classifier, model_settings, malware_path)

        proba = gd.score_sequence(trace_classes, trace_values)
        print(f"{proba: 6.5f}")



