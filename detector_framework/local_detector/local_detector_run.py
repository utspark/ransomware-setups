from pathlib import Path

from detector_framework import config
from detector_framework.data_processing.timeseries_processing import ModelSettings, get_system_call_map
from detector_framework.local_detector.local_detector import (
    regression_analysis, binary_supervised_analysis, unsupervised_analysis, multiclass_analysis
)

config.set_seed()


def run_local_detector(model_settings: ModelSettings, benign_path: Path, benign_dict: dict,
                       malware_path: Path, malware_dict: dict):
    benign_list = list(benign_dict.values())
    malware_list = list(malware_dict.values())

    formulation = model_settings.problem_formulation

    if formulation == "regression":
        return regression_analysis(model_settings, benign_path, benign_list, malware_path, malware_list)

    if formulation == "binary_supervised":
        if model_settings.preproc_approach == "syscall_frequency":
            model_settings.system_calls = get_system_call_map(model_settings, benign_path, benign_list)

        return binary_supervised_analysis(model_settings, benign_path, benign_list, malware_path, malware_list)

    if formulation == "unsupervised":
        return unsupervised_analysis(model_settings, benign_path, benign_list, malware_path, malware_list)

    if formulation == "multiclass_supervised":
        return multiclass_analysis(model_settings, benign_path, benign_dict, malware_path, malware_dict)

    raise ValueError(f"Unknown problem formulation: {formulation}")


def get_default_config():
    cwd = Path.cwd()
    data_path = cwd / "data"

    problem_formulation = "multiclass_supervised"
    preproc_approach = "windowed_features"
    window_len = 40
    future_len = 1
    max_trace_length = 50_000 # 250_000
    model_type = "decision_tree"

    model_filename = ("models/local_detector_analysis/" +
                      problem_formulation + "_" + preproc_approach + "_" + model_type + ".joblib")
    settings_filename = ("models/local_detector_analysis/" +
                         problem_formulation + "_" + preproc_approach + "_" + model_type + "_settings.joblib")
    model_path = data_path / model_filename
    settings_path = data_path / settings_filename

    model_settings = ModelSettings(
        settings_path=settings_path,
        problem_formulation=problem_formulation,
        preproc_approach=preproc_approach,
        window_length=window_len,
        future_length=future_len,
        max_trace_length=max_trace_length,
        model_type=model_type,
        model_path=model_path,
        new_model=True,
        plot=True,
    )

    benign_path = data_path / "current_data/syscall_bucket"
    malware_path = data_path / "current_data/syscall_bucket"

    malware_dict = config.SYSCALL_MALWARE_DICT
    benign_malware_dict = config.SYSCALL_BENIGN_MALWARE_DICT

    benign_dict = {k: benign_malware_dict[k] for k in benign_malware_dict if k not in malware_dict}

    malware_dict = {i: val for i, val in enumerate(malware_dict.values())}
    offset = len(malware_dict)
    benign_dict = {i + offset: val for i, val in enumerate(benign_dict.values())}

    return model_settings, benign_path, benign_dict, malware_path, malware_dict


if __name__ == "__main__":
    model_settings, benign_path, benign_dict, malware_path, malware_dict = get_default_config()
    run_local_detector(model_settings, benign_path, benign_dict, malware_path, malware_dict)

