from pathlib import Path

import pytest

from cross_layer.heatmap import load_classifiers, load_feature_frames, accuracy_outer_loop


def test_heatmap_run():

    # Load classifiers and feature frames
    classifiers = load_classifiers()
    feature_frames = load_feature_frames()

    # Calculate accuracies for each classifier
    all_accuracies = accuracy_outer_loop(classifiers, feature_frames)

    assert all_accuracies["network"][0] == pytest.approx(0.978662, abs=1e-6)
    assert all_accuracies["network"][1] == pytest.approx(0.8375, abs=1e-6)
    assert all_accuracies["network"][2] == pytest.approx(0.973552, abs=1e-6)

    assert all_accuracies["syscall"][0] == pytest.approx(0.975288, abs=1e-6)
    assert all_accuracies["syscall"][1] == pytest.approx(0.758949, abs=1e-6)
    assert all_accuracies["syscall"][2] == pytest.approx(0.920351, abs=1e-6)

    assert all_accuracies["hpc"][0] == pytest.approx(0.942857, abs=1e-6)
    assert all_accuracies["hpc"][1] == pytest.approx(0.904825, abs=1e-6)
    assert all_accuracies["hpc"][2] == pytest.approx(1.0, abs=1e-6)