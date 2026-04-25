

import joblib
from pathlib import Path

def main():
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

if __name__ == "__main__":
    main()