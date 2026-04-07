from pathlib import Path

import joblib

from detector_framework import config, local_detector, global_detector


def get_default_config():
    USE_PRESCORE = False

    cwd = Path.cwd()
    settings_path = cwd / "data/models/local_detector_analysis/multiclass_supervised_windowed_features_decision_tree_settings.joblib"
    model_path = cwd / "data/models/local_detector_analysis/multiclass_supervised_windowed_features_decision_tree.joblib"

    model_settings = joblib.load(settings_path)
    model_settings.model_path = model_path
    classifier = joblib.load(model_settings.model_path)

    prescored_dir = cwd / "../data/prescored_windows"
    malware_path = cwd / "data/current_data/syscall_bucket"

    generation_attack_stages = config.GENERATION_ATTACK_STAGES

    model_paths = {
        "syscall_clf_path": model_path,
        "network_clf_path": None,
        "hpc_clf_path": None,
    }

    la_components = {
        "density": True,
        "propagation": True,
        "memory": False,
    }

    return (
        USE_PRESCORE,
        model_settings,
        classifier,
        prescored_dir,
        malware_path,
        generation_attack_stages,
        model_paths,
        la_components,
    )


def run_global_detector(
    USE_PRESCORE,
    model_settings,
    classifier,
    prescored_dir,
    malware_path,
    generation_attack_stages,
    model_paths,
    la_components,
    num_sequences=5,
):
    gd = global_detector.LifecycleDetector(
        **model_paths,
        lifecycle_awareness=True,
        stage_filter=False,
        **la_components,
    )

    results = []
    for i in range(num_sequences):
        stage_keys, stage_windows = global_detector.LifecycleDetector.form_lifecycle_sequence(
            generation_attack_stages, benign=False
        )

        if USE_PRESCORE:
            trace_classes, trace_values = local_detector.get_prescored_predictions(
                stage_keys, stage_windows, prescored_dir
            )

        else:
            trace_classes, trace_values = local_detector.get_live_predictions(
                stage_keys, stage_windows, classifier, model_settings, malware_path
            )

        translation = config.SYSCALL_BENIGN_MALWARE_CLASS_TRANSLATION
        proba = gd.score_single_layer(trace_classes, trace_values, translation)
        print(f"{proba: 6.5f}")
        results.append(proba)

    return results


if __name__ == "__main__":
    config.set_seed()
    (
        USE_PRESCORE,
        model_settings,
        classifier,
        prescored_dir,
        malware_path,
        generation_attack_stages,
        model_paths,
        la_components,
    ) = get_default_config()

    run_global_detector(
        USE_PRESCORE,
        model_settings,
        classifier,
        prescored_dir,
        malware_path,
        generation_attack_stages,
        model_paths,
        la_components,
    )


