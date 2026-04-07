import joblib
import pytest
from pathlib import Path
from unittest.mock import patch

# Import the main functions from the adfa replicate scripts
from detector_framework.adfa_replicate import adfa, adfa_new_data, adfa_plotting

RESULTS_DIR = Path("detector_framework/adfa_replicate/results")
FIGURES_DIR = Path("data/figures")
PLOT_FILE_NAME = "adfa_replicate.pdf"

def test_adfa_replicate_run():
    """
    Runs all source files in the adfa_replicate directory and checks the final outputs.
    """
    # 1. Run adfa.main() - This generates adfa_data_curve.joblib
    print("\nRunning adfa.main()...")
    with patch("builtins.print"):  # Mock print to keep test output clean
        adfa.main(plot=False)
    
    adfa_data_path = RESULTS_DIR / "adfa_data_curve.joblib"
    assert adfa_data_path.exists(), "adfa_data_curve.joblib was not created"
    
    # Check AUC for adfa_data
    _, _, auc = joblib.load(adfa_data_path)
    assert auc == pytest.approx(0.850655, abs=1e-5)
    
    # 2. Run adfa_new_data.main() - This generates individual_behavior_curve.joblib, 
    # exclude_encryption_curve.joblib, partial_encryption_curve.joblib, 
    # and full_encryption_curve.joblib
    print("Running adfa_new_data.main()...")
    with patch("builtins.print"), patch("tqdm.tqdm", side_effect=lambda x, **kwargs: x):
        adfa_new_data.main(plot=False)
        
    expected_curves = [
        ("individual_behavior_curve.joblib", 0.872916),
        ("exclude_encryption_curve.joblib", 0.9988),
        ("partial_encryption_curve.joblib", 0.9864),
        ("full_encryption_curve.joblib", 0.4584)
    ]
    
    for filename, expected_auc in expected_curves:
        path = RESULTS_DIR / filename
        assert path.exists(), f"{filename} was not created"
        _, _, auc = joblib.load(path)
        assert auc == pytest.approx(expected_auc, abs=1e-3)

    # 3. Run adfa_plotting.main() - This handles loading and "plotting" (skipped via plot=False)
    print("Running adfa_plotting.main()...")
    with patch("builtins.print"):
        adfa_plotting.main(plot=False)
