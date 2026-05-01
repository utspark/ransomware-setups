#!/usr/bin/env python3
"""
Parse metrics.log files from multiple workloads and create unified visualization.
Dynamically finds all <prefix>_<workload>_2 directories in each category and analyzes their metrics.
"""

import re
from collections import defaultdict
from pathlib import Path
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
import argparse

# Define categories and their base paths relative to benignware directory
CATEGORIES = {
    'fbench': 'fbench/output_streaming',
    'browser': 'browser/output_streaming',
    'compression': 'compression/output_streaming',
    'cpu2017': 'perf/cpu2017/output_streaming',
}

def parse_metrics_log(filepath):
    """
    Parse metrics.log file and extract time, events, and sizes.
    Returns a dictionary mapping time -> list of (events, sizes) tuples.
    """
    time_map = defaultdict(lambda: {"events": [], "sizes": []})
    
    pattern = r'\[Metrics\].*?:\s*([\d.]+)\s*ms\.\s*Counted\s*(\d+)\s*lines,\s*Size:\s*(\d+)\s*bytes'
    
    try:
        with open(filepath, 'r') as f:
            for line in f:
                match = re.search(pattern, line)
                if match:
                    time_ms = float(match.group(1))
                    events = int(match.group(2))
                    size = int(match.group(3))
                    
                    time_map[time_ms]["events"].append(events)
                    time_map[time_ms]["sizes"].append(size)
    except FileNotFoundError:
        return None
    
    return time_map if time_map else None

def analyze_workload(time_map, workload_name):
    """
    Analyze a single workload's time map and return a DataFrame with workload label.
    """
    if time_map is None:
        return None
    
    rows = []
    for time_ms, data in time_map.items():
        for events, size in zip(data["events"], data["sizes"]):
            rows.append({
                "workload": workload_name,
                "time_ms": time_ms,
                "events": events,
                "size_bytes": size
            })
    return pd.DataFrame(rows)

def find_all_workloads(benignware_dir='.', prefix='SYSTEM'):
    """
    Dynamically find all <prefix>_<workload>_2 directories and their metrics.log files.
    Returns a list of (full_workload_name, filepath) tuples.
    """
    workload_files = []
    
    for category, relative_path in CATEGORIES.items():
        category_path = Path(benignware_dir) / relative_path
        
        if not category_path.exists():
            continue
        
        # Find all {prefix}_*_2 directories
        for system_dir in category_path.glob(f'{prefix}_*_2'):
            if system_dir.is_dir():
                metrics_file = system_dir / 'metrics.log'
                if metrics_file.exists():
                    # Extract workload name from directory (e.g., SYSTEM_fileserver_2 -> fileserver)
                    workload_name = system_dir.name.replace(f'{prefix}_', '').replace('_2', '')
                    full_name = f"{category}/{workload_name}"
                    workload_files.append((full_name, str(metrics_file)))
    
    return sorted(workload_files)

def load_all_workloads(benignware_dir='.', prefix='SYSTEM'):
    """
    Load metrics from all available workloads found dynamically.
    Returns a combined DataFrame with all data.
    """
    all_data = []
    workload_stats = {}
    
    workload_files = find_all_workloads(benignware_dir, prefix)
    
    if not workload_files:
        raise ValueError(f"No {prefix}_*_2 directories with metrics.log found!")
    
    for full_name, filepath in workload_files:
        print(f"Loading {full_name:30} from {filepath}...", end=" ")
        
        time_map = parse_metrics_log(filepath)
        if time_map is None:
            print("✗ NOT FOUND")
            continue
        
        df = analyze_workload(time_map, full_name)
        if df is not None and len(df) > 0:
            all_data.append(df)
            
            # Calculate stats for this workload
            stats = {
                "records": len(df),
                "unique_times": len(time_map),
                "time_min": df['time_ms'].min(),
                "time_max": df['time_ms'].max(),
                "time_median": df['time_ms'].median(),
                "time_p99": df['time_ms'].quantile(0.99),
                "events_min": df['events'].min(),
                "events_max": df['events'].max(),
                "events_median": df['events'].median(),
                "events_p99": df['events'].quantile(0.99),
                "size_min": df['size_bytes'].min(),
                "size_max": df['size_bytes'].max(),
                "size_median": df['size_bytes'].median(),
            }
            workload_stats[full_name] = stats
            print(f"✓ ({len(df)} records, {len(time_map)} epochs)")
        else:
            print("✗ EMPTY")
    
    if not all_data:
        raise ValueError(f"No {prefix} workload data found!")
    
    combined_df = pd.concat(all_data, ignore_index=True)
    return combined_df, workload_stats

def print_workload_summary(workload_stats):
    """Print summary statistics for each workload."""
    print("\n" + "="*130)
    print("WORKLOAD SUMMARY STATISTICS")
    print("="*130)
    print(f"{'Workload':<35} {'Records':<12} {'Epochs':<10} "
          f"{'Time (ms)':<20} {'Events (lines)':<20} {'Size (KB)':<20}")
    print("-" * 130)
    
    for workload, stats in sorted(workload_stats.items()):
        time_range = f"{stats['time_min']:.0f}-{stats['time_max']:.0f}"
        events_range = f"{stats['events_min']:,}-{stats['events_max']:,}"
        size_range_kb = f"{stats['size_min']/1024:.0f}-{stats['size_max']/1024:.0f}"
        
        print(f"{workload:<35} {stats['records']:<12} {stats['unique_times']:<10} "
              f"{time_range:<20} {events_range:<20} {size_range_kb:<20}")
    
    print("="*130 + "\n")

def create_unified_visualization(df, workload_stats, prefix):
    """
    Create a comprehensive visualization comparing all workloads.
    Uses separate rows for each workload showing time and events distributions with median and p99.
    """
    workloads = sorted(df['workload'].unique())
    n_workloads = len(workloads)
    colors = sns.color_palette("husl", n_workloads)
    workload_colors = {w: colors[i] for i, w in enumerate(workloads)}
    
    # Create figure with subplots: 2 columns (time, events) x n_workloads rows
    fig, axes = plt.subplots(n_workloads, 2, figsize=(14, 4*n_workloads))
    
    # Handle single workload case
    if n_workloads == 1:
        axes = axes.reshape(1, -1)
    
    fig.suptitle(f'{prefix} Workload Metrics Analysis: Distributions with Median and P99', 
                 fontsize=16, fontweight='bold', y=0.995)
    
    for idx, workload in enumerate(workloads):
        data = df[df['workload'] == workload]
        color = workload_colors[workload]
        stats = workload_stats[workload]
        
        # Time distribution (column 0)
        axes[idx, 0].hist(data['time_ms'], bins=40, color=color, alpha=0.7, edgecolor='black')
        axes[idx, 0].axvline(stats['time_median'], color='red', linestyle='--', linewidth=2, 
                             label=f'Median: {stats["time_median"]:.1f}ms')
        axes[idx, 0].axvline(stats['time_p99'], color='orange', linestyle=':', linewidth=2,
                             label=f'P99: {stats["time_p99"]:.1f}ms')
        axes[idx, 0].set_ylabel(workload, fontsize=11, fontweight='bold')
        if idx == 0:
            axes[idx, 0].set_title('Processing Time (ms)', fontsize=12, fontweight='bold')
        axes[idx, 0].legend(fontsize=9, loc='upper right')
        axes[idx, 0].grid(alpha=0.3)
        if idx < n_workloads - 1:
            axes[idx, 0].set_xticklabels([])
        else:
            axes[idx, 0].set_xlabel('Time (ms)', fontsize=10)
        
        # Events distribution (column 1)
        axes[idx, 1].hist(data['events'], bins=40, color=color, alpha=0.7, edgecolor='black')
        axes[idx, 1].axvline(stats['events_median'], color='red', linestyle='--', linewidth=2,
                             label=f'Median: {stats["events_median"]:.0f}')
        axes[idx, 1].axvline(stats['events_p99'], color='orange', linestyle=':', linewidth=2,
                             label=f'P99: {stats["events_p99"]:.0f}')
        if idx == 0:
            axes[idx, 1].set_title('Event Count (lines)', fontsize=12, fontweight='bold')
        axes[idx, 1].legend(fontsize=9, loc='upper right')
        axes[idx, 1].grid(alpha=0.3)
        if idx < n_workloads - 1:
            axes[idx, 1].set_xticklabels([])
        else:
            axes[idx, 1].set_xlabel('Events', fontsize=10)
    
    plt.tight_layout()
    plt.savefig(f'unified_metrics_distributions_{prefix}.png', dpi=300, bbox_inches='tight')
    print(f"✓ Saved distribution visualization to: unified_metrics_distributions_{prefix}.png")
    
    # Create a separate comparison summary plot
    create_comparison_plot(df, workload_stats, workload_colors, prefix)
    
    # Create combined processing time plot
    create_combined_processing_time_plot(df, workload_stats, workload_colors, prefix)

def create_combined_processing_time_plot(df, workload_stats, workload_colors, prefix):
    """Create a combined plot showing processing time comparison and max p99 distribution."""
    workloads = sorted(df['workload'].unique())
    
    # Find workload with max p99 time
    max_p99_workload = max(workloads, key=lambda w: workload_stats[w]['time_p99'])
    max_p99_data = df[df['workload'] == max_p99_workload]
    max_p99_color = workload_colors[max_p99_workload]
    
    from matplotlib import gridspec
    fig = plt.figure(figsize=(18, 6))
    gs = gridspec.GridSpec(1, 2, width_ratios=[2, 1])
    ax1 = plt.subplot(gs[0])
    ax2 = plt.subplot(gs[1])
    
    # Left subplot: Grouped horizontal bars for median and p99
    y_pos = np.arange(len(workloads))
    bar_width = 0.35
    
    times_med = [workload_stats[w]['time_median'] for w in workloads]
    times_p99 = [workload_stats[w]['time_p99'] for w in workloads]
    
    # Median bars
    bars_med = ax1.barh(y_pos - bar_width/2, times_med, bar_width, 
                        color=[workload_colors[w] for w in workloads], alpha=0.7, edgecolor='black', 
                        label='Median')
    
    # P99 bars
    bars_p99 = ax1.barh(y_pos + bar_width/2, times_p99, bar_width, 
                        color=[workload_colors[w] for w in workloads], alpha=0.5, edgecolor='black', 
                        hatch='//', label='P99')
    
    ax1.set_yticks(y_pos)
    ax1.set_yticklabels(workloads)
    ax1.set_xlabel('Processing Time (ms)', fontsize=11)
    ax1.set_title(f'{prefix} Median and P99 Processing Times by Workload', fontsize=12, fontweight='bold')
    ax1.legend()
    ax1.grid(alpha=0.3, axis='x')
    
    # Add value labels with larger font and space
    max_time = max(max(times_med), max(times_p99))
    for i, (med, p99) in enumerate(zip(times_med, times_p99)):
        ax1.text(med + max_time * 0.02, i - bar_width/2, f'{med:.1f}', va='center', ha='left', fontsize=10)
        ax1.text(p99 + max_time * 0.02, i + bar_width/2, f'{p99:.1f}', va='center', ha='left', fontsize=10)
    
    # Right subplot: Distribution of max p99 workload
    ax2.hist(max_p99_data['time_ms'], bins=40, color=max_p99_color, alpha=0.7, edgecolor='black')
    ax2.axvline(workload_stats[max_p99_workload]['time_median'], color='red', linestyle='--', linewidth=2, 
                label=f'Median: {workload_stats[max_p99_workload]["time_median"]:.1f}ms')
    ax2.axvline(workload_stats[max_p99_workload]['time_p99'], color='orange', linestyle=':', linewidth=2,
                label=f'P99: {workload_stats[max_p99_workload]["time_p99"]:.1f}ms')
    ax2.set_xlabel('Processing Time (ms)', fontsize=11)
    ax2.set_ylabel('Frequency', fontsize=11)
    ax2.set_title(f'Processing Time Distribution\n({max_p99_workload})', fontsize=12, fontweight='bold')
    ax2.legend(fontsize=9, loc='upper right')
    ax2.grid(alpha=0.3)
    
    plt.tight_layout()
    plt.savefig(f'processing_time_combined_{prefix}.png', dpi=300, bbox_inches='tight')
    plt.savefig(f'processing_time_combined_{prefix}.pdf', dpi=300, bbox_inches='tight')
    print(f"✓ Saved combined processing time plot to: processing_time_combined_{prefix}.png and processing_time_combined_{prefix}.pdf")
    
    # Save separate plots
    # Left plot
    fig_left = plt.figure(figsize=(12, 6))
    ax_left = fig_left.add_subplot(111)
    bars_med = ax_left.barh(y_pos - bar_width/2, times_med, bar_width, 
                            color=[workload_colors[w] for w in workloads], alpha=0.7, edgecolor='black', 
                            label='Median')
    bars_p99 = ax_left.barh(y_pos + bar_width/2, times_p99, bar_width, 
                            color=[workload_colors[w] for w in workloads], alpha=0.5, edgecolor='black', 
                            hatch='//', label='P99')
    ax_left.set_yticks(y_pos)
    ax_left.set_yticklabels(workloads)
    ax_left.set_xlabel('Processing Time (ms)', fontsize=11)
    ax_left.set_title(f'{prefix} Median and P99 Processing Times by Workload', fontsize=12, fontweight='bold')
    ax_left.legend()
    ax_left.grid(alpha=0.3, axis='x')
    for i, (med, p99) in enumerate(zip(times_med, times_p99)):
        ax_left.text(med + max_time * 0.02, i - bar_width/2, f'{med:.1f}', va='center', ha='left', fontsize=10)
        ax_left.text(p99 + max_time * 0.02, i + bar_width/2, f'{p99:.1f}', va='center', ha='left', fontsize=10)
    plt.tight_layout()
    plt.savefig(f'processing_time_comparison_{prefix}.png', dpi=300, bbox_inches='tight')
    plt.savefig(f'processing_time_comparison_{prefix}.pdf', dpi=300, bbox_inches='tight')
    print(f"✓ Saved comparison plot to: processing_time_comparison_{prefix}.png and processing_time_comparison_{prefix}.pdf")
    
    # Right plot
    fig_right = plt.figure(figsize=(6, 6))
    ax_right = fig_right.add_subplot(111)
    ax_right.hist(max_p99_data['time_ms'], bins=40, color=max_p99_color, alpha=0.7, edgecolor='black')
    ax_right.axvline(workload_stats[max_p99_workload]['time_median'], color='red', linestyle='--', linewidth=2, 
                     label=f'Median: {workload_stats[max_p99_workload]["time_median"]:.1f}ms')
    ax_right.axvline(workload_stats[max_p99_workload]['time_p99'], color='orange', linestyle=':', linewidth=2,
                     label=f'P99: {workload_stats[max_p99_workload]["time_p99"]:.1f}ms')
    ax_right.set_xlabel('Processing Time (ms)', fontsize=11)
    ax_right.set_ylabel('Frequency', fontsize=11)
    ax_right.set_title(f'Processing Time Distribution\n({max_p99_workload})', fontsize=12, fontweight='bold')
    ax_right.legend(fontsize=9, loc='upper right')
    ax_right.grid(alpha=0.3)
    plt.tight_layout()
    plt.savefig(f'processing_time_distribution_{prefix}.png', dpi=300, bbox_inches='tight')
    plt.savefig(f'processing_time_distribution_{prefix}.pdf', dpi=300, bbox_inches='tight')
    print(f"✓ Saved distribution plot to: processing_time_distribution_{prefix}.png and processing_time_distribution_{prefix}.pdf")

def create_comparison_plot(df, workload_stats, workload_colors, prefix):
    """Create a summary comparison plot with median and p99 bar charts for all workloads."""
    workloads = sorted(df['workload'].unique())
    
    fig, axes = plt.subplots(2, 2, figsize=(14, 10))
    fig.suptitle(f'{prefix} Workload Comparison: Median and P99 Values', fontsize=14, fontweight='bold')
    
    # Extract medians and p99
    times_med = [workload_stats[w]['time_median'] for w in workloads]
    times_p99 = [workload_stats[w]['time_p99'] for w in workloads]
    events_med = [workload_stats[w]['events_median'] for w in workloads]
    events_p99 = [workload_stats[w]['events_p99'] for w in workloads]
    
    # Time medians (top left)
    bars = axes[0, 0].barh(workloads, times_med, color=[workload_colors[w] for w in workloads], 
                           alpha=0.7, edgecolor='black')
    axes[0, 0].set_xlabel('Time (ms)', fontsize=11)
    axes[0, 0].set_title('Median Processing Time', fontsize=12, fontweight='bold')
    axes[0, 0].grid(alpha=0.3, axis='x')
    for i, (bar, val) in enumerate(zip(bars, times_med)):
        axes[0, 0].text(val, i, f' {val:.1f}ms', va='center', fontsize=9)
    
    # Time p99 (top right)
    bars = axes[0, 1].barh(workloads, times_p99, color=[workload_colors[w] for w in workloads],
                           alpha=0.7, edgecolor='black')
    axes[0, 1].set_xlabel('Time (ms)', fontsize=11)
    axes[0, 1].set_title('P99 Processing Time', fontsize=12, fontweight='bold')
    axes[0, 1].grid(alpha=0.3, axis='x')
    for i, (bar, val) in enumerate(zip(bars, times_p99)):
        axes[0, 1].text(val, i, f' {val:.1f}ms', va='center', fontsize=9)
    
    # Events median (bottom left)
    bars = axes[1, 0].barh(workloads, events_med, color=[workload_colors[w] for w in workloads],
                           alpha=0.7, edgecolor='black')
    axes[1, 0].set_xlabel('Event Count', fontsize=11)
    axes[1, 0].set_title('Median Event Count', fontsize=12, fontweight='bold')
    axes[1, 0].grid(alpha=0.3, axis='x')
    for i, (bar, val) in enumerate(zip(bars, events_med)):
        axes[1, 0].text(val, i, f' {val:.0f}', va='center', fontsize=9)
    
    # Events p99 (bottom right)
    bars = axes[1, 1].barh(workloads, events_p99, color=[workload_colors[w] for w in workloads],
                           alpha=0.7, edgecolor='black')
    axes[1, 1].set_xlabel('Event Count', fontsize=11)
    axes[1, 1].set_title('P99 Event Count', fontsize=12, fontweight='bold')
    axes[1, 1].grid(alpha=0.3, axis='x')
    for i, (bar, val) in enumerate(zip(bars, events_p99)):
        axes[1, 1].text(val, i, f' {val:.0f}', va='center', fontsize=9)
    
    plt.tight_layout()
    plt.savefig(f'workload_comparison_summary_{prefix}.png', dpi=300, bbox_inches='tight')
    print(f"✓ Saved comparison summary to: workload_comparison_summary_{prefix}.png")

def create_comparison_table(df, workload_stats, prefix):
    """Create and save a detailed comparison table."""
    comparison_data = []
    
    for workload in sorted(workload_stats.keys()):
        stats = workload_stats[workload]
        comparison_data.append({
            'Workload': workload,
            'Records': stats['records'],
            'Time (ms) - Median': f"{stats['time_median']:.1f}",
            'Time (ms) - P99': f"{stats['time_p99']:.1f}",
            'Time (ms) - Min': f"{stats['time_min']:.1f}",
            'Time (ms) - Max': f"{stats['time_max']:.1f}",
            'Events - Median': f"{stats['events_median']:.0f}",
            'Events - P99': f"{stats['events_p99']:.0f}",
            'Events - Min': f"{stats['events_min']:,}",
            'Events - Max': f"{stats['events_max']:,}",
        })
    
    comparison_df = pd.DataFrame(comparison_data)
    comparison_df.to_csv(f'workload_comparison_{prefix}.csv', index=False)
    print(f"✓ Saved comparison table to: workload_comparison_{prefix}.csv")
    
    print("\nComparison Table:")
    print(comparison_df.to_string(index=False))

def main():
    parser = argparse.ArgumentParser(description="Parse metrics.log files from workloads and create visualizations.")
    parser.add_argument('prefix', choices=['SYSTEM', 'NETWORK', 'HWPERF'], help='The prefix for the workload directories (SYSTEM, NETWORK, or HWPERF)')
    args = parser.parse_args()
    prefix = args.prefix
    
    print(f"Loading {prefix} metrics from all workloads...")
    try:
        combined_df, workload_stats = load_all_workloads(prefix=prefix)
    except ValueError as e:
        print(f"Error: {e}")
        return
    
    print_workload_summary(workload_stats)
    
    # Save combined data
    combined_df.to_csv(f'all_workloads_metrics_{prefix}.csv', index=False)
    print(f"✓ Saved combined data ({len(combined_df)} records) to: all_workloads_metrics_{prefix}.csv")
    
    # Create visualizations
    print("\nGenerating unified visualization...")
    create_unified_visualization(combined_df, workload_stats, prefix)
    
    # Create comparison table
    print("\nGenerating comparison table...")
    create_comparison_table(combined_df, workload_stats, prefix)
    
    print("\n" + "="*130)
    print("Analysis complete!")
    print("="*130)

if __name__ == "__main__":
    main()
