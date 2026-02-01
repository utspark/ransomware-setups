import pytest
import sys
import os
from pathlib import Path

def run_all():
    """
    Run all tests in the current directory using pytest.
    """
    print("Starting test execution...")
    # Ensure project root is in PYTHONPATH
    project_root = str(Path(__file__).parent.parent.parent)
    if project_root not in sys.path:
        sys.path.insert(0, project_root)
    
    # Get the directory of the current script
    test_dir = str(Path(__file__).parent)
    
    # Arguments for pytest:
    # -v: verbose
    # test_dir: the directory to search for tests
    args = ["-v", test_dir]
    
    # Run pytest and exit with its return code
    return_code = pytest.main(args)
    sys.exit(return_code)

if __name__ == "__main__":
    run_all()
