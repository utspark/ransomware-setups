import pytest
import sys
import os
from pathlib import Path

def run_all():
    """
    Run all tests in the current directory using pytest.
    """
    print("Starting test execution...")
    # Ensure project root is in PYTHONPATH and change to it
    project_root = Path(__file__).resolve().parent.parent.parent
    os.chdir(project_root)
    if str(project_root) not in sys.path:
        sys.path.insert(0, str(project_root))
    
    # Get the directory of the current script
    test_dir = str(Path(__file__).resolve().parent)
    
    # Arguments for pytest:
    # -v: verbose
    # Specify test files in exact order
    test_files = [
        os.path.join(test_dir, "test_local_detector_run.py"),
        os.path.join(test_dir, "test_global_detector_run.py"),
        os.path.join(test_dir, "test_cross_layer_train_run.py"),
        os.path.join(test_dir, "test_plotting.py"),
        os.path.join(test_dir, "test_heatmap.py"),
    ]
    # Add other tests in the directory not already listed
    all_tests = [str(f.resolve()) for f in Path(test_dir).glob("test_*.py")]
    for test in all_tests:
        if test not in test_files:
            test_files.append(test)

    args = ["-v"] + test_files
    
    # Run pytest and exit with its return code
    os.environ["RUN_ALL_TESTS"] = "true"
    return_code = pytest.main(args)
    sys.exit(return_code)

if __name__ == "__main__":
    run_all()
