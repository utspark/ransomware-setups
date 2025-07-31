from pathlib import Path

import matplotlib

from ml_pipelines.timeseries_processing import RegressionData, ModelSettings, get_windows_and_futures, \
    preproc_transform, get_system_call_map
from ml_pipelines.pipeline_analysis import regression_error, supervised_error, unsupervised_error

matplotlib.use("Qt5Agg")
import matplotlib.pyplot as plt
plt.ion()


def regression_settings_check(model_settings: ModelSettings):
    VALID_MODELS = {"lstm"}
    VALID_MODES = {"windowed"}

    if model_settings.model_type not in VALID_MODELS:
        raise ValueError(f"mode must be one of {sorted(VALID_MODELS)!r}, got {model_settings.model_type!r}")

    if model_settings.preproc_approach not in VALID_MODES:
        raise ValueError(f"mode must be one of {sorted(VALID_MODES)!r}, got {model_settings.preproc_approach!r}")

    assert model_settings.model_type in model_settings.model_path

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

    assert model_settings.model_type in model_settings.model_path

    return


def binary_supervised_analysis(model_settings, benign_path, benign_list, malware_path, malware_list):
    benign_transformed = preproc_transform(model_settings, benign_path, benign_list)
    malware_transformed = preproc_transform(model_settings, malware_path, malware_list)

    malware_transformed = malware_transformed[:5000]

    if "windowed" == model_settings.preproc_approach:
        benign_transformed = benign_transformed[0]
        malware_transformed = malware_transformed[0]

    supervised_error(model_settings, benign_transformed, malware_transformed)

    return


def unsupervised_settings_check(model_settings: ModelSettings):
    VALID_MODELS = {"isolation_forest", "minimum_covariance_determinant", "local_outlier_factor", "svc"}
    VALID_MODES = {"zero-padded_trace", "syscall_frequency", "windowed_features", "windowed"}

    if model_settings.model_type not in VALID_MODELS:
        raise ValueError(f"mode must be one of {sorted(VALID_MODELS)!r}, got {model_settings.model_type!r}")

    if model_settings.preproc_approach not in VALID_MODES:
        raise ValueError(f"mode must be one of {sorted(VALID_MODES)!r}, got {model_settings.preproc_approach!r}")

    assert model_settings.model_type in model_settings.model_path

    return


def unsupervised_analysis(model_settings, benign_path, benign_list, malware_path, malware_list):
    benign_transformed = preproc_transform(model_settings, benign_path, benign_list)
    malware_transformed = preproc_transform(model_settings, malware_path, malware_list)

    malware_transformed = malware_transformed[:5000]

    unsupervised_error(model_settings, benign_transformed, malware_transformed)

    return




if __name__ == "__main__":
    cwd = Path.cwd()

    # +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    # *** Approach and Model Settings +++++++++++++++++++++++++++++++++++++++++++++
    # +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

    # TODO hardcode options here
    problem_formulation = "unsupervised"  # ["binary_supervised",  "regression"]
    preproc_approach = "syscall_frequency"  # ["full_trace", "windowed_features", "windowed"]
    window_len = 20  # 10
    future_len = 1  # 3
    max_trace_length = 500000
    system_calls = None
    # model_path = cwd / "basic_lstm.h5"
    model_path = cwd / "supervised_xgb.json"
    model_type = "xgb"
    new_model = True
    plot = True

    model_settings = ModelSettings(
        problem_formulation=problem_formulation,
        preproc_approach=preproc_approach,
        window_length=window_len,
        future_length=future_len,
        max_trace_length=max_trace_length,
        # system_calls
        model_path=model_path,
        model_type=model_type,
        new_model=new_model,
        plot=plot,
    )

    # +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    # *** File Selection ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    # +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

    benign_path = cwd / "ftrace/benign"
    benign_list = [
        "idle_20_trace_system_timed_ints.txt",
        # gzip_system_timed_ints.txt",
    ]

    malware_path = cwd / "ftrace/malware"
    malware_list = [
        "AES_O_exfil_aws1_system_timed_ints.txt",
        # "AES_O_exfil_aws2_system_timed_ints.txt",
        # "AES_O_exfil_sftp1_system_timed_ints.txt",
        # "AES_O_exfil_sftp2_system_timed_ints.txt",
    ]

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

    # TODO start here multiclass supervised



