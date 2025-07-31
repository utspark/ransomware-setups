from pathlib import Path

import matplotlib
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
from sklearn.multiclass import OneVsRestClassifier, OneVsOneClassifier
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.svm import SVC
from sklearn.utils import compute_class_weight




matplotlib.use("Qt5Agg")
import matplotlib.pyplot as plt
plt.ion()

import numpy as np

from ml_pipelines.timeseries_processing import RegressionData, ModelSettings, get_windows_and_futures, \
    preproc_transform, get_system_call_map
from ml_pipelines.pipeline_analysis import regression_error, binary_supervised_error, unsupervised_error, \
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


def multiclass_analysis(model_settings, benign_path, benign_list, malware_path, malware_list):
    transformed_data = []
    labels = []

    for key in benign_dict:
            tmp_list = [key]
            transformed = preproc_transform(model_settings, benign_path, tmp_list)
            tmp_labels = np.zeros((len(transformed))) + benign_dict[key]

            transformed_data.append(transformed)
            labels.append(tmp_labels)

    for key in malware_dict:
        tmp_list = [key]
        transformed = preproc_transform(model_settings, malware_path, tmp_list)
        tmp_labels = np.zeros((len(transformed))) + malware_dict[key]

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
    window_len = 20  # 10
    future_len = 1  # 3
    max_trace_length = 500000
    system_calls = None
    # model_path = cwd / "basic_lstm.h5"
    model_type = "svc"
    # model_filename = problem_formulation + "_" + preproc_approach + "_" + "lstm.h5"
    model_filename = problem_formulation + "_" + preproc_approach + "_" + "svc.json"
    model_path = cwd / model_filename
    new_model = True
    plot = True

    model_settings = ModelSettings(
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

    benign_path = cwd / "ftrace/benign"
    # benign_list = [
    #     "idle_20_trace_system_timed_ints.txt",
    #     # gzip_system_timed_ints.txt",
    # ]
    benign_dict = {
        "idle_20_trace_system_timed_ints.txt": 0,
        # gzip_system_timed_ints.txt",
    }


    malware_path = cwd / "ftrace/malware"
    # malware_list = [
    #     "AES_O_exfil_aws1_system_timed_ints.txt",
    #     # "AES_O_exfil_aws2_system_timed_ints.txt",
    #     # "AES_O_exfil_sftp1_system_timed_ints.txt",
    #     # "AES_O_exfil_sftp2_system_timed_ints.txt",
    # ]
    malware_dict = {
        "AES_O_exfil_aws1_system_timed_ints.txt": 1,
        # "AES_O_exfil_aws2_system_timed_ints.txt",
        "AES_O_exfil_sftp1_system_timed_ints.txt": 2,
        # "AES_O_exfil_sftp2_system_timed_ints.txt",
    }

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




    raise Exception

    base_svc = SVC(kernel='rbf', C=1.0, gamma='scale', probability=False)

    pipeline = make_pipeline(
        StandardScaler(),
        base_svc
    )

    # 4a) Train the default multiclass SVC (OvO)
    pipeline.fit(X_train, y_train)
    y_pred = pipeline.predict(X_test)

    print("=== Default SVC (one‐vs‐one) ===")
    print(classification_report(y_test, y_pred))
    print("Confusion matrix:\n", confusion_matrix(y_test, y_pred))

    # 4b) Explicit One‐vs‐Rest wrapper
    ovr = make_pipeline(
        StandardScaler(),
        OneVsRestClassifier(base_svc)
    )
    ovr.fit(X_train, y_train)
    y_pred_ovr = ovr.predict(X_test)

    print("\n=== One‐vs‐Rest SVC ===")
    print(classification_report(y_test, y_pred_ovr))

    # 4c) Explicit One‐vs‐One wrapper (same as default)
    ovo = make_pipeline(
        StandardScaler(),
        OneVsOneClassifier(base_svc)
    )
    ovo.fit(X_train, y_train)
    y_pred_ovo = ovo.predict(X_test)

    print("\n=== One‐vs‐One SVC ===")
    print(classification_report(y_test, y_pred_ovo))

    # 5) (Optional) Hyperparameter tuning with GridSearchCV
    # param_grid = {
    #     'svc__C': [0.1, 1, 10],
    #     'svc__gamma': ['scale', 0.1, 1]
    # }
    # grid = GridSearchCV(pipeline, param_grid, cv=5, scoring='accuracy')
    # grid.fit(X_train, y_train)
    # print("\nBest params:", grid.best_params_)
    # print("Best CV accuracy:", grid.best_score_)
    # print("Test set accuracy:", grid.score(X_test, y_test))



























