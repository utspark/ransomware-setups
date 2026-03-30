from pathlib import Path
import numpy as np
import random
import joblib
import detector_framework

import pytest

from cross_layer.plotting import trace_len_plot, model_curves_plot, evade_density_plot, signal_sample_plot, \
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

    feature_frames_path = cwd / "data/feature_frames.joblib"
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
    assert malware_scores[0] == pytest.approx(0.796488, abs=1e-6)
    assert malware_scores[1] == pytest.approx(0.765352, abs=1e-6)
    assert malware_scores[2] == pytest.approx(0.781828, abs=1e-6)

    auc_values = model_curves_plot(**plot_inputs, plot=False)
    assert auc_values[0][2] == pytest.approx(0.83475, abs=1e-5)
    assert auc_values[1][2] == pytest.approx(0.9419, abs=1e-4)
    assert auc_values[2][2] == pytest.approx(0.9898, abs=1e-4)
    assert auc_values[3][2] == pytest.approx(0.99820, abs=1e-5)
    assert auc_values[4][2] == pytest.approx(1.0, abs=1e-5)

    auc_values = evade_density_plot(**plot_inputs, plot=False)
    assert auc_values[0][2] == pytest.approx(0.7483, abs=1e-4)
    assert auc_values[1][2] == pytest.approx(0.7866, abs=1e-4)
    assert auc_values[2][2] == pytest.approx(0.9945, abs=1e-4)
    assert auc_values[3][2] == pytest.approx(0.9915, abs=1e-4)
    assert auc_values[4][2] == pytest.approx(0.6844, abs=1e-4)

    auc_values = signal_sample_plot(**plot_inputs, cwd=cwd, plot=False)
    assert auc_values[7][2] == pytest.approx(0.841777, abs=1e-6)
    assert auc_values[8][2] == pytest.approx(0.873777, abs=1e-6)
    assert auc_values[9][2] == pytest.approx(0.841866, abs=1e-6)
    assert auc_values[10][2] == pytest.approx(0.885777, abs=1e-6)
    assert auc_values[11][2] == pytest.approx(0.817622, abs=1e-6)
    assert auc_values[12][2] == pytest.approx(0.816577, abs=1e-6)
    assert auc_values[13][2] == pytest.approx(0.792555, abs=1e-6)

    auc_values = flow_variations(
        attack_stages, feature_frames, window_size_time, window_stride_time, time_choice_list, cwd=cwd,  plot=False
    )
    assert auc_values[0][2] == pytest.approx(0.998533, abs=1e-6)
    assert auc_values[1][2] == pytest.approx(0.984488, abs=1e-6)
    assert auc_values[2][2] == pytest.approx(0.951377, abs=1e-6)
    assert auc_values[3][2] == pytest.approx(0.769777, abs=1e-6)
    assert auc_values[4][2] == pytest.approx(0.917822, abs=1e-6)
    assert auc_values[5][2] == pytest.approx(0.628400, abs=1e-6)

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
    assert threshold_results["accuracy"] == [0.59, 0.71, 0.84, 0.97, 0.8]
    assert threshold_results["f1"][0] == pytest.approx(0.709219, abs=1e-6)
    assert threshold_results["f1"][1] == pytest.approx(0.775193, abs=1e-6)
    assert threshold_results["f1"][2] == pytest.approx(0.862068, abs=1e-6)
    assert threshold_results["f1"][3] == pytest.approx(0.970873, abs=1e-6)
    assert threshold_results["f1"][4] == pytest.approx(0.75, abs=1e-6)

