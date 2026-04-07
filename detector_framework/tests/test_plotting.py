from pathlib import Path
import numpy as np
import random
import joblib
import detector_framework

import pytest

from detector_framework.cross_layer.plotting import trace_len_plot, model_curves_plot, evade_density_plot, signal_sample_plot, \
    flow_variations, benign_app_scores, score_over_time
from detector_framework import config


def test_plotting_run():
    config.set_seed()

    cwd = Path.cwd()

    window_size_time = config.WINDOW_SIZE_TIME
    window_stride_time = config.WINDOW_STRIDE_TIME

    start = 1.5  # 0.5
    stop = 10
    step = 0.2
    time_choice_list = np.arange(start, stop + step / 2, step, dtype=float).tolist()

    model_paths = {
        "syscall_clf_path": cwd / "data/models/syscall_clf.joblib",
        "network_clf_path": cwd / "data/models/network_clf.joblib",
        "hpc_clf_path": cwd / "data/models/hpc_clf.joblib",
    }

    feature_frames_path = cwd / "data/joblib/feature_frames.joblib"
    feature_frames = joblib.load(feature_frames_path)
    attack_stages = detector_framework.config.GENERATION_ATTACK_STAGES

    attack_stages_dict = attack_stages
    feature_frames_dict = feature_frames
    time_choices = time_choice_list

    plot_inputs = {
        "model_paths": model_paths,
        "attack_stages_dict": attack_stages,
        "feature_frames_dict": feature_frames,
        "window_size_time": window_size_time,
        "window_stride_time": window_stride_time,
        "time_choices": time_choices
    }

    benign_scores, malware_scores = trace_len_plot(
        attack_stages, feature_frames, window_size_time, window_stride_time, time_choice_list, cwd, plot=False
    )
    assert benign_scores[0] == pytest.approx(0.598425, abs=1e-6)
    assert benign_scores[1] == pytest.approx(0.423750, abs=1e-6)
    assert benign_scores[2] == pytest.approx(0.0, abs=1e-6)
    assert malware_scores[0] == pytest.approx(0.823838, abs=1e-6)
    assert malware_scores[1] == pytest.approx(0.765352, abs=1e-6)
    assert malware_scores[2] == pytest.approx(0.782104, abs=1e-6)

    auc_values = model_curves_plot(**plot_inputs, plot=False)
    assert auc_values[0][2] == pytest.approx(0.85735, abs=1e-5)
    assert auc_values[1][2] == pytest.approx(0.9617, abs=1e-4)
    assert auc_values[2][2] == pytest.approx(0.99205, abs=1e-4)
    assert auc_values[3][2] == pytest.approx(0.9988, abs=1e-5)
    assert auc_values[4][2] == pytest.approx(1.0, abs=1e-5)

    auc_values = evade_density_plot(**plot_inputs, plot=False)
    assert auc_values[0][2] == pytest.approx(0.74565, abs=1e-4)
    assert auc_values[1][2] == pytest.approx(0.8042, abs=1e-4)
    assert auc_values[2][2] == pytest.approx(0.9896, abs=1e-4)
    assert auc_values[3][2] == pytest.approx(0.9872, abs=1e-4)
    assert auc_values[4][2] == pytest.approx(0.69295, abs=1e-5)

    auc_values = signal_sample_plot(**plot_inputs, cwd=cwd, plot=False)
    assert auc_values[7][2] == pytest.approx(0.842355, abs=1e-6)
    assert auc_values[8][2] == pytest.approx(0.884955, abs=1e-6)
    assert auc_values[9][2] == pytest.approx(0.8434, abs=1e-6)
    assert auc_values[10][2] == pytest.approx(0.8848, abs=1e-6)
    assert auc_values[11][2] == pytest.approx(0.816733, abs=1e-6)
    assert auc_values[12][2] == pytest.approx(0.822555, abs=1e-6)
    assert auc_values[13][2] == pytest.approx(0.839622, abs=1e-6)

    auc_values = flow_variations(
        attack_stages, feature_frames, window_size_time, window_stride_time, time_choice_list, cwd=cwd,  plot=False
    )
    assert auc_values[0][2] == pytest.approx(0.998622, abs=1e-6)
    assert auc_values[1][2] == pytest.approx(0.976133, abs=1e-6)
    assert auc_values[2][2] == pytest.approx(0.941333, abs=1e-6)
    assert auc_values[3][2] == pytest.approx(0.765022, abs=1e-6)
    assert auc_values[4][2] == pytest.approx(0.921822, abs=1e-6)
    assert auc_values[5][2] == pytest.approx(0.599066, abs=1e-6)

    # bars = benign_app_scores(
    #     attack_stages, feature_frames, window_size_time, window_stride_time, time_choice_list, cwd=cwd, plot=False
    # )
    # assert bars[0][0] == pytest.approx(0.9470, abs=1e-4)
    # assert bars[0][1] == pytest.approx(0.9712, abs=1e-4)
    # assert bars[5][0] == pytest.approx(0.9682, abs=1e-4)
    # assert bars[5][1] == pytest.approx(0.9803, abs=1e-4)
    # assert bars[14][0] == pytest.approx(0.9398, abs=1e-4)
    # assert bars[14][1] == pytest.approx(0.9716, abs=1e-4)

    threshold_results = score_over_time(
        attack_stages, feature_frames, window_size_time, window_stride_time, time_choice_list, cwd=cwd, plot=False
    )
    assert threshold_results["accuracy"] == [0.56, 0.7, 0.85, 0.93, 0.81]
    assert threshold_results["f1"][0] == pytest.approx(0.694444, abs=1e-6)
    assert threshold_results["f1"][1] == pytest.approx(0.769230, abs=1e-6)
    assert threshold_results["f1"][2] == pytest.approx(0.869565, abs=1e-6)
    assert threshold_results["f1"][3] == pytest.approx(0.934579, abs=1e-6)
    assert threshold_results["f1"][4] == pytest.approx(0.771084, abs=1e-6)

