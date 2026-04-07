import random
import os
from copy import deepcopy
from pathlib import Path

import numpy as np
import pytest
import detector_framework
from detector_framework import global_detector
# from detector_framework import config
from detector_framework.local_detector.local_detector import files_and_labels_to_X_y, train_and_save_model, outer_train_loop
from detector_framework.cross_layer.cross_layer_train_run import form_feature_frame_joblib, build_cross_layer_X
from detector_framework.cross_layer import network_signals, syscall_signals, hpc_signals


def test_cross_layer_train_run():
    detector_framework.config.set_seed()

    SYSCALL = True
    NETWORK = True
    HPC = True

    tts = detector_framework.config.TRAIN_TEST_SPLIT
    window_size_time = detector_framework.config.WINDOW_SIZE_TIME
    window_stride_time = detector_framework.config.WINDOW_STRIDE_TIME

    cwd = Path.cwd()

    iteration_dict = {
        "syscall": {
            "signal_selection": SYSCALL,
            "data_dir": cwd / "data/current_data/syscall_bucket",
            "malware_dictionary": detector_framework.config.SYSCALL_BENIGN_MALWARE_DICT,
            "feature_extraction_module": syscall_signals,
            "save_path": cwd / "data/models/syscall_clf.joblib"
        },
        "network": {
            "signal_selection": NETWORK,
            "data_dir": cwd / "data/current_data/network_bucket",
            "malware_dictionary": detector_framework.config.NETWORK_BENIGN_MALWARE_DICT,
            "feature_extraction_module": network_signals,
            "save_path": cwd / "data/models/network_clf.joblib"
        },
        "hpc": {
            "signal_selection": HPC,
            "data_dir": cwd / "data/current_data/hpc_bucket",
            "malware_dictionary": detector_framework.config.HPC_BENIGN_MALWARE_DICT,
            "feature_extraction_module": hpc_signals,
            "save_path": cwd / "data/models/hpc_clf.joblib"
        }
    }

    train_scores = outer_train_loop(iteration_dict, window_size_time, window_stride_time, tts, train=True)

    expected_train_scores = [0.992058, 0.958916, 1.0]

    for i in range(len(train_scores)):
        assert train_scores[i] == pytest.approx(expected_train_scores[i], abs=1e-6)

    feature_frames_path = cwd / "data/joblib/feature_frames.joblib"
    test_workloads = ["compress_gzip_1t", "symm_AES_256b", "transfer_aws_8t", "browser_mix", "spec_gcc", "filebench_varmail", "recon_mount", "filebench_fileserver"]

    if os.environ.get("RUN_ALL_TESTS") == "true":
        behaviors = deepcopy(detector_framework.config.BEHAVIOR_FILES)
    else:
        behaviors = {
            k: v for k, v in detector_framework.config.BEHAVIOR_FILES.items()
            if k in test_workloads
        }
    signal_modules = {
        "syscall": syscall_signals,
        "network": network_signals,
        "hpc": hpc_signals,
    }

    feature_frames = form_feature_frame_joblib(
        cwd, feature_frames_path, window_size_time, window_stride_time, tts, behaviors, signal_modules
    )

    assert feature_frames["network"]["compress_gzip_1t"].iloc[600, 9] == pytest.approx(0.952380, abs=1e-6)
    assert feature_frames["network"]["symm_AES_256b"].iloc[250, 3] == pytest.approx(62.0, abs=1e-6)
    assert feature_frames["network"]["transfer_aws_8t"].iloc[400, 7] == pytest.approx(0.000382, abs=1e-6)

    assert feature_frames["syscall"]["browser_mix"].iloc[0, 0] == pytest.approx(1709.0, abs=1e-6)
    assert feature_frames["syscall"]["browser_mix"].iloc[1200, 4] == pytest.approx(71.660877, abs=1e-6)
    assert feature_frames["syscall"]["spec_gcc"].iloc[1500, 2] == pytest.approx(23.687804, abs=1e-6)

    assert feature_frames["hpc"]["filebench_varmail"].iloc[100, 8] == pytest.approx(115065.571428, abs=1e-6)
    assert feature_frames["hpc"]["recon_mount"].iloc[300, 14] == pytest.approx(11791146.142857, abs=1e-6)
    assert feature_frames["hpc"]["filebench_fileserver"].iloc[50, 12]== pytest.approx(79630.833333, abs=1e-6)

    num_workloads = 10
    start = 1.5
    stop = 10
    step = 0.2
    time_choices = np.arange(start, stop + step / 2, step, dtype=float).tolist()

    cross_layer_X_list = []

    for _ in range(5):
        techniques = [random.choice(test_workloads) for _ in range(num_workloads)]
        stage_lens = [(technique, random.choice(time_choices)) for technique in techniques]

        attack_X = build_cross_layer_X(feature_frames, stage_lens, window_size_time, window_stride_time)
        cross_layer_X = attack_X
        cross_layer_X_list.append(cross_layer_X)

    model_paths = {
        "syscall_clf_path": cwd / "data/models/syscall_clf.joblib",
        "network_clf_path": cwd / "data/models/network_clf.joblib",
        "hpc_clf_path": cwd / "data/models/hpc_clf.joblib",
    }
    la_components = {
        "density": True,
        "propagation": True,
    }

    gd = global_detector.LifecycleDetector(
        **model_paths,
        lifecycle_awareness=True,
        stage_filter=False,
        **la_components
    )

    scores = [gd.score_cross_layer(cross_layer_X) for cross_layer_X in cross_layer_X_list]

    assert scores[0] == pytest.approx(0.643978, abs=1e-6)
    assert scores[1] == pytest.approx(0.654492, abs=1e-6)
    assert scores[2] == pytest.approx(0.780377, abs=1e-6)
    assert scores[3] == pytest.approx(0.752738, abs=1e-6)
    assert scores[4] == pytest.approx(0.593482, abs=1e-6)

