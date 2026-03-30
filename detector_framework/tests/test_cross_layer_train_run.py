from pathlib import Path

import pytest
import detector_framework
# from detector_framework import config
from cross_layer.cross_layer_train_run import files_and_labels_to_X_y, train_and_save_model, outer_train_loop
from cross_layer import network_signals, syscall_signals, hpc_signals


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

    expected_train_scores = [0.992058, 0.958916, 0.995160]

    for i in range(len(train_scores)):
        assert train_scores[i] == pytest.approx(expected_train_scores[i], abs=1e-6)
