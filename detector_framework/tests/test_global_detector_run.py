import pytest
import numpy as np
from pathlib import Path
from unittest.mock import MagicMock, patch
import joblib
import os

from detector_framework.global_detector.global_detector_run import (
    run_global_detector,
    get_default_config,
)

from detector_framework import config


def test_global_detector_run():
    config.set_seed()

    (
        USE_PRESCORE,
        model_settings,
        classifier,
        prescored_dir,
        malware_path,
        generation_attack_stages,
        model_paths,
        la_components,
    ) = get_default_config()

    results = run_global_detector(
        USE_PRESCORE,
        model_settings,
        classifier,
        prescored_dir,
        malware_path,
        generation_attack_stages,
        model_paths,
        la_components,
        num_sequences=5,
    )

    expected_results = [0.22948, 0.54503, 0.24466, 0.24946, 0.70014]

    for i in range(len(results)):
        assert results[i] == pytest.approx(expected_results[i], abs=1e-5)
