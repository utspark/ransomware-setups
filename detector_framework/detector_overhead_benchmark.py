import time
import matplotlib.pyplot as plt
import numpy as np
from pathlib import Path
from detector_framework import config
from detector_framework.cross_layer import syscall_signals, network_signals, hpc_signals
from detector_framework.global_detector.global_detector import LifecycleDetector

def benchmark_overhead(window_stride_time=None, global_update_frequency=1, num_runs=5):
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

    print(f"\n--- Benchmark for {sample_base} (Stride: {window_stride_time}s, Global Update Freq: {global_update_frequency}, Runs: {num_runs}) ---")
    
    all_runs_times = []
    total_times = []
    min_len = 0

    for r in range(num_runs):
        start_init = time.time()
        detector = LifecycleDetector(
            syscall_clf_path=str(syscall_clf_path),
            network_clf_path=str(network_clf_path),
            hpc_clf_path=str(hpc_clf_path)
        )
        end_init = time.time()
        if r == 0:
            print(f"Detector initialization took: {end_init - start_init:.4f}s")

        # Parameters
        window_size_time = config.WINDOW_SIZE_TIME
        if window_stride_time is None:
            window_stride_time = config.WINDOW_STRIDE_TIME
        
        if r == 0:
            print(f"Using window_size: {window_size_time}s, window_stride: {window_stride_time}s")

        # Data Loading
        t_load_start = time.time()
        df_syscall = syscall_signals.get_file_df(syscall_path)
        t_syscall_load = time.time() - t_load_start
        
        t_load_start = time.time()
        df_network = network_signals.get_file_df(network_path)
        t_network_load = time.time() - t_load_start
        
        t_load_start = time.time()
        df_hpc = hpc_signals.get_file_df(hpc_path)
        t_hpc_load = time.time() - t_load_start
        
        total_load_time = t_syscall_load + t_network_load + t_hpc_load

        # Feature Extraction
        t_fe_start = time.time()
        X_syscall = syscall_signals.file_df_feature_extraction(df_syscall, window_size_time, window_stride_time)
        t_syscall_fe = time.time() - t_fe_start
        
        t_fe_start = time.time()
        X_network = network_signals.file_df_feature_extraction_parallel(df_network, window_size_time, window_stride_time,
                                                                        n_workers=1)
        t_network_fe = time.time() - t_fe_start
        
        t_fe_start = time.time()
        X_hpc = hpc_signals.file_df_feature_extraction_parallel(df_hpc, window_size_time, window_stride_time, n_workers=1)
        t_hpc_fe = time.time() - t_fe_start
        
        total_fe_time = t_syscall_fe + t_network_fe + t_hpc_fe

        min_len = min(len(X_syscall), len(X_network), len(X_hpc))
        
        X_syscall_aligned = X_syscall.iloc[:min_len].to_numpy()
        X_network_aligned = X_network.iloc[:min_len].to_numpy()
        X_hpc_aligned = X_hpc.iloc[:min_len].to_numpy()
        
        cross_layer_X = (X_syscall_aligned, X_network_aligned, X_hpc_aligned)

        # Model Inference
        t_inf_start = time.time()
        classes, probas = detector.cross_layer_class_preds(cross_layer_X)
        t_local_inf = time.time() - t_inf_start

        # Global Analysis
        t_global_start = time.time()
        for i in range(min_len):
            if (i + 1) % global_update_frequency == 0 or (i + 1) == min_len:
                tmp_classes = classes[0:i+1]
                tmp_probas = probas[0:i+1]
                collated_preds = detector._collate_preds(tmp_classes, tmp_probas)
                filtered_preds, counts = detector.filter(collated_preds)
                score = detector.score_stage_sequence(filtered_preds, collated_preds)
        t_global_inf = time.time() - t_global_start
        
        total_time = total_load_time + total_fe_time + t_local_inf + t_global_inf
        
        all_runs_times.append([total_load_time, total_fe_time, t_local_inf, t_global_inf])
        total_times.append(total_time)

    avg_times = np.mean(all_runs_times, axis=0)
    avg_total_time = np.mean(total_times)
    
    print(f"Average Total time: {avg_total_time:.4f}s")
    print(f"Average Overhead per window: {avg_total_time / min_len * 1000:.4f}ms")

    return {
        'stride': window_stride_time,
        'update_freq': global_update_frequency,
        'min_len': min_len,
        'times': avg_times.tolist(),
        'total_time': avg_total_time
    }

def run_multiple_benchmarks(num_runs=5):
    strides = [0.1, 0.2, 0.5] # Example strides
    update_freqs = [1, 5, 10] # Example update frequencies
    
    results = []
    
    # Let's do a few combinations
    # 1. Vary stride with fixed freq=1
    for s in strides:
        results.append(benchmark_overhead(window_stride_time=s, global_update_frequency=1, num_runs=num_runs))
        
    # 2. Vary freq with fixed stride (default or 0.1)
    for f in update_freqs:
        if f == 1: continue # already did it
        results.append(benchmark_overhead(window_stride_time=0.1, global_update_frequency=f, num_runs=num_runs))

    # Plotting comparison
    plt.rcParams['font.size'] = 14
    labels = ['Data Loading', 'Feature Extraction', 'Local Inference', 'Global Analysis']
    
    # Print results table
    print("\n" + "="*85)
    print(f"{'Configuration':<15} | {'Metric':<10} | {'Loading':<10} | {'Feature':<10} | {'Local Inf':<10} | {'Global Inf':<10} | {'Total':<10}")
    print("-" * 85)
    for r in results:
        cfg = f"S:{r['stride']} F:{r['update_freq']}"
        # Wall-clock (s)
        times = r['times']
        total = r['total_time']
        print(f"{cfg:<15} | {'Total (s)':<10} | {times[0]:<10.4f} | {times[1]:<10.4f} | {times[2]:<10.4f} | {times[3]:<10.4f} | {total:<10.4f}")
        # Per-window (ms)
        win_times = [t / r['min_len'] * 1000 for t in times]
        win_total = total / r['min_len'] * 1000
        print(f"{'':<15} | {'Win (ms)':<10} | {win_times[0]:<10.4f} | {win_times[1]:<10.4f} | {win_times[2]:<10.4f} | {win_times[3]:<10.4f} | {win_total:<10.4f}")
        print("-" * 85)
    print("="*85)

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(18, 7))
    
    config_labels = [f"S:{r['stride']}s\nF:{r['update_freq']}" for r in results]
    
    # 1. Per-window comparison
    bottom1 = np.zeros(len(results))
    colors = plt.cm.tab10(np.linspace(0, 1, len(labels)))
    for i, label in enumerate(labels):
        vals = [r['times'][i] / r['min_len'] * 1000 for r in results]
        ax1.bar(config_labels, vals, bottom=bottom1, label=label, color=colors[i])
        bottom1 += vals

    ax1.set_ylabel('Avg Time per Window (ms)')
    ax1.set_title('Per-Window Overhead')
    ax1.legend()
    
    # 2. Wall-clock comparison
    bottom2 = np.zeros(len(results))
    for i, label in enumerate(labels):
        vals = [r['times'][i] for r in results]
        ax2.bar(config_labels, vals, bottom=bottom2, label=label, color=colors[i])
        bottom2 += vals

    ax2.set_ylabel('Total Wall-Clock Time (s)')
    ax2.set_title('Total Wall-Clock Overhead')
    ax2.legend()

    # Add explanation for S and F
    textstr = f"S: Window Stride\nF: Global Update Frequency\nAveraged over {num_runs} runs"
    props = dict(boxstyle='round', facecolor='wheat', alpha=0.5)
    fig.text(0.01, 0.02, textstr, fontsize=12, verticalalignment='bottom', bbox=props)
    
    plt.tight_layout(rect=[0, 0.05, 1, 1])
    cwd = Path.cwd()
    output_path = cwd / "data/figures/overhead_comparison.pdf"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    plt.savefig(output_path)
    print(f"\nComparison plot saved to {output_path}")
    plt.show()

if __name__ == "__main__":
    run_multiple_benchmarks()
