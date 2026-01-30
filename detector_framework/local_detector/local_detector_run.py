from pathlib import Path

import matplotlib

from detector_framework import config

matplotlib.use("Qt5Agg")
import matplotlib.pyplot as plt
plt.ion()

import numpy as np

from detector_framework.data_processing.timeseries_processing import RegressionData, ModelSettings, get_windows_and_futures, \
    preproc_transform, get_system_call_map
from detector_framework.local_detector.metrics import regression_error, binary_supervised_error, unsupervised_error, \
    multiclass_error


def regression_settings_check(model_settings: ModelSettings):
    VALID_MODELS = {"lstm"}
    VALID_MODES = {"windowed"}

    if model_settings.model_type not in VALID_MODELS:
        raise ValueError(f"mode must be one of {sorted(VALID_MODELS)!r}, got {model_settings.model_type!r}")

    if model_settings.preproc_approach not in VALID_MODES:
        raise ValueError(f"mode must be one of {sorted(VALID_MODES)!r}, got {model_settings.preproc_approach!r}")

    assert model_settings.model_type in str(model_settings.model_path)

    return


def regression_analysis(model_settings, benign_path, benign_list, malware_path, malware_list):
    benign_wdws, benign_futures = get_windows_and_futures(model_settings, benign_path, benign_list)
    malware_wdws, malware_futures = get_windows_and_futures(model_settings, malware_path, malware_list)

    malware_wdws = malware_wdws[:5000]
    malware_futures = malware_futures[:5000]

    regression_data = RegressionData(benign_wdws, benign_futures, malware_wdws, malware_futures)
    regression_error(model_settings, regression_data)


def binary_supervised_settings_check(model_settings: ModelSettings):
    VALID_MODELS = {"svc", "xgb", "lstm"}
    VALID_MODES = {"zero-padded_trace", "syscall_frequency", "windowed_features", "windowed"}

    if model_settings.model_type not in VALID_MODELS:
        raise ValueError(f"mode must be one of {sorted(VALID_MODELS)!r}, got {model_settings.model_type!r}")

    if model_settings.preproc_approach not in VALID_MODES:
        raise ValueError(f"mode must be one of {sorted(VALID_MODES)!r}, got {model_settings.preproc_approach!r}")

    assert model_settings.model_type in str(model_settings.model_path)

    return


def binary_supervised_analysis(model_settings, benign_path, benign_list, malware_path, malware_list):
    benign_transformed = preproc_transform(model_settings, benign_path, benign_list)
    malware_transformed = preproc_transform(model_settings, malware_path, malware_list)

    if "windowed" == model_settings.preproc_approach:
        benign_transformed = benign_transformed[0]
        malware_transformed = malware_transformed[0]

    malware_transformed = malware_transformed[:5000]

    binary_supervised_error(model_settings, benign_transformed, malware_transformed)

    return


def unsupervised_settings_check(model_settings: ModelSettings):
    VALID_MODELS = {"isolation_forest", "minimum_covariance_determinant", "local_outlier_factor", "svc"}
    VALID_MODES = {"zero-padded_trace", "syscall_frequency", "windowed_features", "windowed"}

    if model_settings.model_type not in VALID_MODELS:
        raise ValueError(f"mode must be one of {sorted(VALID_MODELS)!r}, got {model_settings.model_type!r}")

    if model_settings.preproc_approach not in VALID_MODES:
        raise ValueError(f"mode must be one of {sorted(VALID_MODES)!r}, got {model_settings.preproc_approach!r}")

    assert model_settings.model_type in str(model_settings.model_path)

    return


def unsupervised_analysis(model_settings, benign_path, benign_list, malware_path, malware_list):
    benign_transformed = preproc_transform(model_settings, benign_path, benign_list)
    malware_transformed = preproc_transform(model_settings, malware_path, malware_list)

    if "windowed" == model_settings.preproc_approach:
        benign_transformed = benign_transformed[0]
        malware_transformed = malware_transformed[0]

    malware_transformed = malware_transformed[:5000]

    unsupervised_error(model_settings, benign_transformed, malware_transformed)

    return


def get_keyword_filenames(keyword, file_dir: Path):
    """
    Retrieve a list of filenames in a provided directory matching keyword.
    """
    keywords = set(keyword if isinstance(keyword, list) else [keyword])
    return [p.name for p in file_dir.iterdir() if p.is_file() and any(kw in p.name for kw in keywords)]


def multiclass_analysis(model_settings, benign_path, benign_dict: dict, malware_path, malware_dict: dict):
    transformed_data = []
    labels = []

    for key, val in benign_dict.items():
        tmp_list = get_keyword_filenames(val, benign_path)
        transformed = preproc_transform(model_settings, benign_path, tmp_list)
        tmp_labels = np.zeros((len(transformed))) + key

        transformed_data.append(transformed)
        labels.append(tmp_labels)

    for key, val in malware_dict.items():
        tmp_list = get_keyword_filenames(val, malware_path)
        transformed = preproc_transform(model_settings, malware_path, tmp_list)
        tmp_labels = np.zeros((len(transformed))) + key

        transformed_data.append(transformed)
        labels.append(tmp_labels)

    X = np.concatenate(transformed_data)
    y = np.concatenate(labels)

    multiclass_error(model_settings, X, y)

    return


if __name__ == "__main__":
    cwd = Path.cwd()

    # +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    # *** Approach and Model Settings +++++++++++++++++++++++++++++++++++++++++++++
    # +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

    # ***
    # "binary_supervised"
    # "full_trace", "syscall_frequency", "windowed_features", "windowed"
    # "svc", "xgb", "lstm"

    # ***
    # "regression"
    # "windowed"
    # "lstm"

    # ***
    # "unsupervised"
    # "full_trace", "syscall_frequency", "windowed_features", "windowed"
    # "isolation_forest", "minimum_covariance_determinant", "local_outlier_factor", "svc"

    # TODO hardcode options here
    problem_formulation = "multiclass_supervised"
    preproc_approach = "windowed_features"
    window_len = 40  # 10
    future_len = 1  # 3
    max_trace_length = 500_000
    system_calls = None
    # model_path = cwd / "basic_lstm.h5"

    data_path = cwd / "data"
    model_type = "decision_tree"
    # model_filename = problem_formulation + "_" + preproc_approach + "_" + "lstm.h5"
    model_filename = ("models/local_detector_analysis/" +
                      problem_formulation + "_" + preproc_approach + "_" + model_type + ".joblib")
    settings_filename = ("models/local_detector_analysis/" +
                         problem_formulation + "_" + preproc_approach + "_" + model_type + "_settings.joblib")
    model_path = data_path / model_filename
    settings_path = data_path / settings_filename

    new_model = True
    plot = True

    model_settings = ModelSettings(
        settings_path=settings_path,
        problem_formulation=problem_formulation,
        preproc_approach=preproc_approach,
        window_length=window_len,
        future_length=future_len,
        max_trace_length=max_trace_length,
        # system_calls
        model_type=model_type,
        model_path=model_path,
        new_model=new_model,
        plot=plot,
    )

    # +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    # *** File Selection ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    # +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

    benign_path = data_path / "current_data/syscall_bucket"
    # benign_dict = {
    #     "idle_20_trace_system_timed_ints.txt": 0,
    #     # "gzip_system_timed_ints.txt": 1,
    # }
    # benign_list = list(benign_dict.keys())

    malware_path = data_path / "current_data/syscall_bucket"
    # malware_dict = {
    #     "AES_O_exfil_aws1_system_timed_ints.txt": 0,
    #     "AES_O_exfil_aws2_system_timed_ints.txt": 0,
    #     "AES_O_exfil_sftp1_system_timed_ints.txt": 0,
    #     "AES_O_exfil_sftp2_system_timed_ints.txt": 0,
    #     "gzip_system_timed_ints.txt": 1,
    # }

    malware_dict = config.SYSCALL_MALWARE_DICT
    malware_list = list(malware_dict.values())

    benign_malware_dict = config.SYSCALL_BENIGN_MALWARE_DICT

    A = benign_malware_dict
    B = malware_dict
    benign_dict = {k: A[k] for k in A if k not in B}
    benign_list = list(benign_dict.values())


    malware_dict = {i: val for i, val in enumerate(malware_dict.values())}
    offset = len(malware_dict)
    benign_dict = {i + offset: val for i, val in enumerate(benign_dict.values())}

    # +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    # *** Pipeline Execution ++++++++++++++++++++++++++++++++++++++++++++++++++++++
    #
    # *** Should not have to modify any code below
    #
    # +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

    if model_settings.problem_formulation == "regression":
        regression_analysis(
            model_settings, benign_path, benign_list, malware_path, malware_list,
        )

    elif model_settings.problem_formulation == "binary_supervised":
        binary_supervised_settings_check(model_settings)

        if "syscall_frequency" == model_settings.preproc_approach:
            model_settings.syscalls = get_system_call_map(model_settings, benign_path, benign_list)

        binary_supervised_analysis(
            model_settings, benign_path, benign_list, malware_path, malware_list,
        )

    elif model_settings.problem_formulation == "unsupervised":
        unsupervised_analysis(
            model_settings, benign_path, benign_list, malware_path, malware_list,
        )

    else:  # "multiclass_supervised"
        multiclass_analysis(
            model_settings, benign_path, benign_dict, malware_path, malware_dict
        )


