import joblib
import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
from pathlib import Path
from sklearn.preprocessing import StandardScaler

from detector_framework import config
from detector_framework.local_detector import local_detector
from detector_framework.cross_layer import hpc_signals


def grab_details():
    """
    Helper function to retrieve details about the HPC model.
    """
    script_dir = Path(__file__).resolve().parent
    # Assuming project root is 2 levels up from detector_framework/local_detector
    project_root = script_dir.parent.parent
    model_path = project_root / "data/models/hpc_clf.joblib"

    if not model_path.exists():
        print(f"Model file not found at {model_path}")
        return

    print(f"Loading model from {model_path}...")
    clf = joblib.load(model_path)

    print("\nModel Parameters:")
    params = clf.get_params()
    for param, value in params.items():
        print(f"  {param}: {value}")

    feature_names = [
        "instructions",
        "LLC_load_misses",
        "avx_insts_all",
        "block_rq_issue",
        "br_inst_retired",
        "cache_references",
        "mem-loads",
        "mem-stores",
        "port_0",
        "port_1",
        "port_2",
        "port_3",
        "port_4",
        "port_5",
        "port_6",
        "port_7",
    ]

    if hasattr(clf, 'feature_importances_'):
        print("\nFeature Importances (sorted):")
        importances = clf.feature_importances_
        # Pair feature names with their importance values
        feature_importance_pairs = list(zip(feature_names, importances))
        # Sort by importance in descending order
        feature_importance_pairs.sort(key=lambda x: x[1], reverse=True)

        for name, importance in feature_importance_pairs:
            print(f"  {name}: {importance:.4f}")


def get_hpc_correlation():
    """
    Load HPC data, extract features, normalize, and compute cross-correlation matrix.
    """
    script_dir = Path(__file__).resolve().parent
    project_root = script_dir.parent.parent
    hpc_dir = project_root / "data/current_data/hpc_bucket"
    
    if not hpc_dir.exists():
        print(f"HPC data directory not found at {hpc_dir}")
        return

    print("\nLoading HPC data and extracting features for correlation analysis...")
    
    # Get all files in the hpc_bucket (they don't have .csv extension)
    data_paths = [p for p in hpc_dir.iterdir() if p.is_file()]
    if not data_paths:
        print(f"No files found in {hpc_dir}")
        return

    # Use the same parameters as in cross_layer_train_run.py
    malware_dict = config.HPC_BENIGN_MALWARE_DICT
    window_size_time = config.WINDOW_SIZE_TIME
    window_stride_time = config.WINDOW_STRIDE_TIME
    tts = config.TRAIN_TEST_SPLIT

    # Use files_and_labels_to_X_y to get the feature matrix
    # We only need X, so we'll set strict=False to skip files not in the map
    X_train, y_train, X_test, y_test = local_detector.files_and_labels_to_X_y(
        data_paths,
        hpc_signals,
        malware_dict,
        window_size_time,
        window_stride_time,
        train_test_split=tts,
        strict=False
    )

    X = pd.DataFrame(pd.concat([pd.DataFrame(X_train), pd.DataFrame(X_test)]))
    
    feature_names = [
        "instructions",
        "LLC_load_misses",
        "avx_insts_all",
        "block_rq_issue",
        "br_inst_retired",
        "cache_references",
        "mem-loads",
        "mem-stores",
        "port_0",
        "port_1",
        "port_2",
        "port_3",
        "port_4",
        "port_5",
        "port_6",
        "port_7",
    ]
    X.columns = feature_names

    print(f"Extracted {X.shape[0]} samples with {X.shape[1]} features.")

    # Normalize the data
    print("Normalizing data using StandardScaler...")
    scaler = StandardScaler()
    X_normalized = pd.DataFrame(scaler.fit_transform(X), columns=feature_names)

    # Compute correlation matrix
    print("Computing 16x16 cross-correlation matrix...")
    # Fill NaN with 0 for correlation calculation if some features are constant
    corr_matrix = X_normalized.fillna(0).corr()

    # Print correlation matrix
    pd.set_option('display.max_columns', None)
    pd.set_option('display.width', 1000)
    print("\nCross-Correlation Matrix:")
    print(corr_matrix)

    # Identify redundant features (correlation > 0.9 or < -0.9)
    print("\nPotential Redundant Features (Correlation > 0.9):")
    redundant = []
    for i in range(len(corr_matrix.columns)):
        for j in range(i):
            if abs(corr_matrix.iloc[i, j]) > 0.9:
                col_i = corr_matrix.columns[i]
                col_j = corr_matrix.columns[j]
                redundant.append((col_i, col_j, corr_matrix.iloc[i, j]))
                print(f"  {col_i} <-> {col_j}: {corr_matrix.iloc[i, j]:.4f}")
    
    if not redundant:
        print("  None found with correlation > 0.9")

    return corr_matrix


def main():
    grab_details()
    get_hpc_correlation()


if __name__ == "__main__":
    main()