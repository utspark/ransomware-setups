from pathlib import Path

import joblib
import numpy as np

import global_detector
from detector_framework import config, local_detector


if __name__ == "__main__":
    PRESCORE = False
    USE_PRESCORE = False

    settings_path = "data/models/local_detector_analysis/multiclass_supervised_windowed_features_decision_tree_settings.joblib"
    model_settings = joblib.load(settings_path)
    model_settings.model_path = "data/models/local_detector_analysis/multiclass_supervised_windowed_features_decision_tree.joblib"
    classifier = joblib.load(model_settings.model_path)

    cwd = Path.cwd()
    prescored_dir = cwd / "../data/prescored_windows"
    malware_path = cwd / "data/current_data/syscall_bucket"

    generation_attack_stages = config.GENERATION_ATTACK_STAGES

    # if PRESCORE:
    #     for ttp in ttp_dict:
    #         prescored_filename = ttp + "_prescored.joblib"
    #         prescored_path = prescored_dir / prescored_filename
    #
    #         malware_list = ttp_dict[ttp]
    #         transformed = preproc_transform(model_settings, malware_path, malware_list)
    #
    #         y_pred_ohe = classifier.predict_proba(transformed)
    #         label_class = np.argmax(y_pred_ohe, axis=1)
    #         label_val = y_pred_ohe[np.arange(y_pred_ohe.shape[0]), label_class]
    #
    #         prescored_predictions = (label_class, label_val)
    #         joblib.dump(prescored_predictions, prescored_path, compress=("zlib", 3))

    # *** global_detector
    model_paths = {
        "syscall_clf_path": cwd / "data/models/local_detector_analysis/multiclass_supervised_windowed_features_decision_tree.joblib",
        "network_clf_path": None,
        "hpc_clf_path": None,
    }

    la_components = {
        "density": True,
        "propagation": True,
        "memory":False,
    }

    gd = global_detector.LifecycleDetector(
        **model_paths,
        lifecycle_awareness=True,
        stage_filter=False,
        **la_components,
    )

    for i in range(5):
        # *** generate a sequence
        stage_keys, stage_windows = global_detector.form_lifecycle_sequence(generation_attack_stages, benign=False)

        if USE_PRESCORE:
            trace_classes, trace_values = local_detector.get_prescored_predictions(
                stage_keys, stage_windows, prescored_dir)

        else:
            trace_classes, trace_values = local_detector.get_live_predictions(
                stage_keys, stage_windows, classifier, model_settings, malware_path
            )

        translation = config.SYSCALL_BENIGN_MALWARE_CLASS_TRANSLATION
        vectorized_translate = np.vectorize(translation.get)
        clf_predictions = vectorized_translate(trace_classes)
        predictions = clf_predictions[trace_values > 0.90]


        proba = gd.score_stage_sequence(predictions, clf_predictions)
        print(f"{proba: 6.5f}")


