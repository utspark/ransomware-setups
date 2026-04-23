import time
import numpy as np
import pandas as pd
import joblib
from pathlib import Path
from detector_framework import config
from detector_framework.cross_layer import syscall_signals, network_signals, hpc_signals
from detector_framework.global_detector.global_detector import LifecycleDetector

def benchmark_overhead():
    cwd = Path.cwd()
    
    # Paths to models
    syscall_clf_path = cwd / "data/models/syscall_clf.joblib"
    network_clf_path = cwd / "data/models/network_clf.joblib"
    hpc_clf_path = cwd / "data/models/hpc_clf.joblib"
    
    # Sample data paths
    sample_base = "browser_compute_1"
    syscall_path = cwd / f"data/current_data/syscall_bucket/{sample_base}_ints.txt"
    network_path = cwd / f"data/current_data/network_bucket/{sample_base}"
    hpc_path = cwd / f"data/current_data/hpc_bucket/{sample_base}"

    print(f"--- Benchmark for {sample_base} ---")
    start_init = time.time()
    detector = LifecycleDetector(
        syscall_clf_path=str(syscall_clf_path),
        network_clf_path=str(network_clf_path),
        hpc_clf_path=str(hpc_clf_path)
    )
    end_init = time.time()
    print(f"Detector initialization took: {end_init - start_init:.4f}s")

    # Parameters from config
    window_size_time = config.WINDOW_SIZE_TIME
    window_stride_time = config.WINDOW_STRIDE_TIME
    
    print(f"Using window_size: {window_size_time}s, window_stride: {window_stride_time}s")

    print("\n--- Data Loading ---")
    
    t_load_start = time.time()
    df_syscall = syscall_signals.get_file_df(syscall_path)
    t_syscall_load = time.time() - t_load_start
    
    t_load_start = time.time()
    df_network = network_signals.get_file_df(network_path)
    t_network_load = time.time() - t_load_start
    
    t_load_start = time.time()
    df_hpc = hpc_signals.get_file_df(hpc_path)
    t_hpc_load = time.time() - t_load_start
    
    print(f"Syscall loading: {t_syscall_load:.4f}s")
    print(f"Network loading: {t_network_load:.4f}s")
    print(f"HPC loading:     {t_hpc_load:.4f}s")

    print("\n--- Feature Extraction ---")
    
    t_fe_start = time.time()
    X_syscall = syscall_signals.file_df_feature_extraction(df_syscall, window_size_time, window_stride_time)
    t_syscall_fe = time.time() - t_fe_start
    
    t_fe_start = time.time()
    X_network = network_signals.file_df_feature_extraction_parallel(df_network, window_size_time, window_stride_time)
    t_network_fe = time.time() - t_fe_start
    
    t_fe_start = time.time()
    X_hpc = hpc_signals.file_df_feature_extraction_parallel(df_hpc, window_size_time, window_stride_time)
    t_hpc_fe = time.time() - t_fe_start
    
    print(f"Syscall FE: {t_syscall_fe:.4f}s for {len(X_syscall)} windows")
    print(f"Network FE: {t_network_fe:.4f}s for {len(X_network)} windows")
    print(f"HPC FE:     {t_hpc_fe:.4f}s for {len(X_hpc)} windows")

    # Alignment for cross-layer prediction (simulating what build_cross_layer_X does roughly)
    # LifecycleDetector.cross_layer_class_preds expects a tuple of (syscall_X, network_X, hpc_X)
    # They should have the same number of rows for global detector's collation.
    
    min_len = min(len(X_syscall), len(X_network), len(X_hpc))
    print(f"\nAligning to {min_len} windows for global detection")
    
    X_syscall_aligned = X_syscall.iloc[:min_len].to_numpy()
    X_network_aligned = X_network.iloc[:min_len].to_numpy()
    X_hpc_aligned = X_hpc.iloc[:min_len].to_numpy()
    
    cross_layer_X = (X_syscall_aligned, X_network_aligned, X_hpc_aligned)

    print("\n--- Model Inference ---")
    
    t_inf_start = time.time()
    classes, probas = detector.cross_layer_class_preds(cross_layer_X)
    t_local_inf = time.time() - t_inf_start
    print(f"Local detector inference (all 3 layers): {t_local_inf:.4f}s")

    print("\n--- Global Analysis ---")
    
    t_global_start = time.time()
    # Lifecycle scoring components
    # 1. Collate
    collated_preds = detector._collate_preds(classes, probas)
    
    # 2. Filter
    filtered_preds, counts = detector.filter(collated_preds)
    
    # 3. Score sequence (includes HMM/LIS depending on settings)
    score = detector.score_stage_sequence(filtered_preds, collated_preds)
    t_global_inf = time.time() - t_global_start
    
    print(f"Global analysis took: {t_global_inf:.4f}s")
    print(f"Final Detection Score: {score}")

    total_time = (t_syscall_load + t_network_load + t_hpc_load + 
                  t_syscall_fe + t_network_fe + t_hpc_fe + 
                  t_local_inf + t_global_inf)
    
    print("\n--- Summary ---")
    print(f"Total processing time for trace {sample_base}: {total_time:.4f}s")
    print(f"Overhead per window (avg): {total_time / min_len * 1000:.4f}ms")

if __name__ == "__main__":
    benchmark_overhead()
