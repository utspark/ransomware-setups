import io
from pathlib import Path

import numpy as np

import matplotlib

from ml_pipelines.processing import RegressionData, ModelSettings, regression_error, \
    get_windows_and_futures, preproc_transform, supervised_error, get_syscall_map, get_system_call_map

matplotlib.use("Qt5Agg")
import matplotlib.pyplot as plt
plt.ion()





if __name__ == "__main__":
    cwd = Path.cwd()

    # +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    # *** Approach and Model Settings +++++++++++++++++++++++++++++++++++++++++++++
    # +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

    problem_formulation = "supervised"  # "regression"
    preproc_approach = "zero-padded_trace"  # "windowed_features", "windowed"
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
        problem_formulation, preproc_approach, window_len, future_len, max_trace_length, model_path, model_type,
        new_model, plot
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
        benign_wdws, benign_futures = get_windows_and_futures(model_settings, benign_path, benign_list)
        malware_wdws, malware_futures = get_windows_and_futures(model_settings, malware_path, malware_list)

        malware_wdws = malware_wdws[:5000]
        malware_futures = malware_futures[:5000]

        regression_data = RegressionData(benign_wdws, benign_futures, malware_wdws, malware_futures)
        regression_error(model_settings, regression_data)

    elif model_settings.problem_formulation == "supervised":
        VALID_MODELS = {"svc", "xgb", "lstm"}
        VALID_MODES = {"zero-padded_trace", "syscall_frequency", "windowed_features", "windowed"}

        if model_settings.model_type not in VALID_MODELS:
            raise ValueError(f"mode must be one of {sorted(VALID_MODELS)!r}, got {model_settings.model_type!r}")

        if model_settings.preproc_approach not in VALID_MODES:
            raise ValueError(f"mode must be one of {sorted(VALID_MODES)!r}, got {model_settings.preproc_approach!r}")

        if "syscall_frequency" == model_settings.preproc_approach:
            model_settings.syscalls = get_system_call_map(model_settings, benign_path, benign_list)

        benign_transformed = preproc_transform(model_settings, benign_path, benign_list)
        malware_transformed = preproc_transform(model_settings, malware_path, malware_list)

        malware_transformed = malware_transformed[:5000]

        if "windowed" == model_settings.preproc_approach:
            benign_transformed = benign_transformed[0]
            malware_transformed = malware_transformed[0]

        supervised_error(model_settings, benign_transformed, malware_transformed)




































