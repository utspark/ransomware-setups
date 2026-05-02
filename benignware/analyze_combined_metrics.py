#!/usr/bin/env python3
"""
Parse metrics.log files from all prefixes (SYSTEM, NETWORK, HWPERF) and create combined visualizations.
Groups workloads and compares latencies across prefixes.
"""

import re
from collections import defaultdict
from pathlib import Path
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np

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
    Dynamically find all <prefix>_<workload> directories and their metrics.log files.
    Returns a list of (full_workload_name, filepath) tuples.
    """
    workload_files = []
    
    for category, relative_path in CATEGORIES.items():
        category_path = Path(benignware_dir) / relative_path
        
        if not category_path.exists():
            continue
        
        # Find all {prefix}_* directories
        for system_dir in category_path.glob(f'{prefix}_*'):
            if system_dir.is_dir():
                metrics_file = system_dir / 'metrics.log'
                if metrics_file.exists():
                    # Extract workload name from directory (e.g., SYSTEM_fileserver -> fileserver)
                    workload_name = system_dir.name.replace(f'{prefix}_', '')
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
        raise ValueError(f"No {prefix}_* directories with metrics.log found!")
    
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
                "size_p99": df['size_bytes'].quantile(0.99),
            }
            workload_stats[full_name] = stats
            print(f"✓ ({len(df)} records, {len(time_map)} epochs)")
        else:
            print("✗ EMPTY")
    
    if not all_data:
        raise ValueError(f"No {prefix} workload data found!")
    
    combined_df = pd.concat(all_data, ignore_index=True)
    return combined_df, workload_stats

def load_all_prefixes(benignware_dir='.'):
    """
    Load workload stats for all prefixes.
    Returns a dict of prefix -> workload_stats
    """
    prefixes = ['SYSTEM', 'NETWORK', 'HWPERF']
    all_stats = {}
    
    for prefix in prefixes:
        try:
            _, workload_stats = load_all_workloads(benignware_dir, prefix)
            all_stats[prefix] = workload_stats
            print(f"Loaded {len(workload_stats)} workloads for {prefix}")
        except ValueError as e:
            print(f"No data for {prefix}: {e}")
            all_stats[prefix] = {}
    
    return all_stats

def sort_categories(categories):
    """Sort categories with custom order: BROWSER, COMPRESSION, FILEBENCH, CPU2017."""
    category_order = ['browser', 'compression', 'fbench', 'cpu2017']
    result = []
    # Convert categories to a list and handle both upper/lower case
    categories_list = [c.lower() if isinstance(c, str) else c for c in categories]
    for cat in category_order:
        if cat in categories_list:
            result.append(cat)
    for cat in sorted(categories_list):
        if cat not in result:
            result.append(cat)
    return result

def create_combined_latency_plot(all_stats):
    """
    Create a combined vertical bar plot showing median and p99 processing latencies for all prefixes, grouped by workloads and categories.
    """
    from collections import defaultdict
    
    # Collect all unique workloads
    workloads = set()
    for prefix_stats in all_stats.values():
        workloads.update(prefix_stats.keys())
    workloads = sorted(workloads)
    
    if not workloads:
        print("No workloads found across any prefix!")
        return
    
    # Group workloads by category
    workloads_by_category = defaultdict(list)
    for w in workloads:
        category, workload = w.split('/', 1)
        workloads_by_category[category].append(workload)
    
    # Prepare data: for each workload, get med and p99 for each prefix
    data = {w: {} for w in workloads}
    for w in workloads:
        for prefix in ['SYSTEM', 'NETWORK', 'HWPERF']:
            if w in all_stats[prefix]:
                data[w][f'{prefix}_med'] = all_stats[prefix][w]['time_median']
                data[w][f'{prefix}_p99'] = all_stats[prefix][w]['time_p99']
            else:
                data[w][f'{prefix}_med'] = np.nan
                data[w][f'{prefix}_p99'] = np.nan
    
    # Create x positions with gaps between categories
    x_pos = []
    x_labels = []
    category_positions = {}
    current_x = 0
    
    for category in sort_categories(workloads_by_category.keys()):
        category_workloads = sorted(workloads_by_category[category])
        start_x = current_x
        for workload in category_workloads:
            x_pos.append(current_x)
            x_labels.append(workload)  # Just workload name
            current_x += 0.7
        end_x = current_x - 0.7
        category_positions[category] = (start_x, end_x)
        # No gap between categories
    
    # Create the plot
    fig, ax = plt.subplots(figsize=(15, 6.5))
    
    bar_width = 0.1  # Narrow bars for 6 per workload
    
    colors = {'SYSTEM': '#1f77b4', 'NETWORK': '#ff7f0e', 'HWPERF': '#2ca02c'}
    prefixes = ['SYSTEM', 'NETWORK', 'HWPERF']

    def geometric_mean(values):
        values = np.asarray(values, dtype=float)
        values = values[(~np.isnan(values)) & (values > 0)]
        if len(values) == 0:
            return np.nan
        return float(np.exp(np.mean(np.log(values))))

    geo_means = {}
    for prefix in prefixes:
        med_values = [data[f"{category}/{workload}"][f'{prefix}_med']
                      for category in sort_categories(workloads_by_category.keys())
                      for workload in sorted(workloads_by_category[category])]
        p99_values = [data[f"{category}/{workload}"][f'{prefix}_p99']
                      for category in sort_categories(workloads_by_category.keys())
                      for workload in sorted(workloads_by_category[category])]
        geo_means[f'{prefix}_med'] = geometric_mean(med_values)
        geo_means[f'{prefix}_p99'] = geometric_mean(p99_values)

    # Plot bars for each prefix and metric
    for i, prefix in enumerate(prefixes):
        med_values = [data[f"{category}/{workload}"][f'{prefix}_med'] 
                     for category in sort_categories(workloads_by_category.keys()) 
                     for workload in sorted(workloads_by_category[category])]
        p99_values = [data[f"{category}/{workload}"][f'{prefix}_p99'] 
                     for category in sort_categories(workloads_by_category.keys()) 
                     for workload in sorted(workloads_by_category[category])]
        
        # Median bars
        ax.bar([x - bar_width + i * 2 * bar_width for x in x_pos], 
               med_values, bar_width, 
               color=colors[prefix], alpha=0.8, 
               label=f"{prefix} Median (geomean={geo_means[f'{prefix}_med']:.1f} ms)", edgecolor='black')
        
        # P99 bars
        ax.bar([x + i * 2 * bar_width for x in x_pos], 
               p99_values, bar_width, 
               color=colors[prefix], alpha=0.5, hatch='//', 
               label=f"{prefix} P99 (geomean={geo_means[f'{prefix}_p99']:.1f} ms)", edgecolor='black')
    xtick_positions = [x + 1.5 * bar_width for x in x_pos]
    ax.set_xticks(xtick_positions)
    ax.set_xticklabels(x_labels, ha='center', fontsize=18)
    for idx, label in enumerate(ax.get_xticklabels()):
        label.set_y(-0.05 if idx % 2 else 0)
    
    ax.tick_params(axis='x', length=8, width=1.5, labelsize=18)
    # 2. Iterate through ticks and double the length for every other one
    # This matches your label logic (idx % 2)
    for idx, tick in enumerate(ax.xaxis.get_major_ticks()):
        if not idx % 2:
            # Ticks for labels at y=0 (default length)
            tick.tick1line.set_markersize(8) 
        else:
            # Ticks for labels at y=-0.05 (longer to reach the text)
            # Adjust '25' to match the visual gap created by -0.05
            tick.tick1line.set_markersize(25) 
    ax.set_ylabel('Processing Time (ms)', fontsize=18)
    ax.tick_params(axis='y', labelsize=18, rotation=90)
    ax.legend(loc='upper left', bbox_to_anchor=(0.03, 0.925), fontsize=18, borderaxespad=0.2, 
    borderpad=0.1,       # Extra padding inside the box
    labelspacing=0.2,    # More vertical space between entries
    handletextpad=0.5,   # Bring text closer to the lines
    framealpha=0.5 )
    ax.grid(alpha=0.3, axis='y')
    
    # Add a small top margin so category labels and value text don't overlap the plot edge
    y_min, y_max = ax.get_ylim()
    ax.set_ylim(0, y_max * 1.12)
    y_top = ax.get_ylim()[1]
    y_label_offset = max(y_max * 0.04, 4)
    
    # Add category labels inside the plot area, above workload groups
    for category, (start, end) in category_positions.items():
        mid_pos = (start + end) / 2 + 1.5 * bar_width
        ax.text(mid_pos, y_top * 0.93, category.upper().replace("FBENCH", "FILEBENCH"), 
                ha='center', va='bottom', fontsize=18, fontweight='bold', color='black')
    
    # Add demarcation lines between categories
    for category, (start, end) in category_positions.items():
        if start > 0:
            boundary_x = start - 0.35 + 1.5 * bar_width
            ax.axvline(boundary_x, color='gray', linestyle=':', alpha=0.8, linewidth=1)
    
    # Tighten x-axis limits around the plotted bars and add a small equal gap at both ends
    left_bar_edge = x_pos[0] - bar_width * 1.5
    right_bar_edge = x_pos[-1] + bar_width * 4.5
    extra_gap = bar_width * 1.0
    ax.set_xlim(left_bar_edge - extra_gap, right_bar_edge + extra_gap)
    
    # Add value labels with extra spacing above bars
    for idx, x in enumerate(x_pos):
        workload_name = x_labels[idx]
        # Find the full workload key by matching the workload name with category
        for category in sort_categories(workloads_by_category.keys()):
            if workload_name in workloads_by_category[category]:
                workload = f"{category}/{workload_name}"
                break
        
        for j, prefix in enumerate(['SYSTEM', 'NETWORK', 'HWPERF']):
            med_val = data[workload][f'{prefix}_med']
            p99_val = data[workload][f'{prefix}_p99']
            
            # Only add text for SYSTEM and NETWORK p99
            if prefix in ['SYSTEM', 'NETWORK'] and not np.isnan(p99_val):
                ax.text(x + j * 2 * bar_width, p99_val + y_label_offset, 
                       f'{p99_val:.1f}', ha='center', va='bottom', fontsize=18, rotation=90)
    
    plt.tight_layout()
    plt.savefig('combined_latencies_all_prefixes_vertical.png', dpi=300, bbox_inches='tight')
    plt.savefig('combined_latencies_all_prefixes_vertical.pdf', dpi=300, bbox_inches='tight')
    print("✓ Saved combined vertical latencies plot to: combined_latencies_all_prefixes_vertical.png and .pdf")

def create_combined_size_plot(all_stats):
    """
    Create a combined vertical bar plot showing median and p99 sizes for all prefixes, grouped by workloads and categories.
    """
    from collections import defaultdict
    
    # Collect all unique workloads
    workloads = set()
    for prefix_stats in all_stats.values():
        workloads.update(prefix_stats.keys())
    workloads = sorted(workloads)
    
    if not workloads:
        print("No workloads found across any prefix!")
        return
    
    # Group workloads by category
    workloads_by_category = defaultdict(list)
    for w in workloads:
        category, workload = w.split('/', 1)
        workloads_by_category[category].append(workload)
    
    # Prepare data: for each workload, get med and p99 sizes for each prefix
    data = {w: {} for w in workloads}
    for w in workloads:
        for prefix in ['SYSTEM', 'NETWORK', 'HWPERF']:
            if w in all_stats[prefix]:
                data[w][f'{prefix}_med'] = all_stats[prefix][w]['size_median']
                data[w][f'{prefix}_p99'] = all_stats[prefix][w]['size_p99']
            else:
                data[w][f'{prefix}_med'] = np.nan
                data[w][f'{prefix}_p99'] = np.nan
    
    # Create x positions with no gaps between categories
    x_pos = []
    x_labels = []
    category_positions = {}
    current_x = 0
    
    for category in sort_categories(workloads_by_category.keys()):
        category_workloads = sorted(workloads_by_category[category])
        start_x = current_x
        for workload in category_workloads:
            x_pos.append(current_x)
            x_labels.append(workload)  # Just workload name
            current_x += 0.7
        end_x = current_x - 0.7
        category_positions[category] = (start_x, end_x)
        # No gap between categories
    
    # Create the plot
    fig, ax = plt.subplots(figsize=(15, 6.5))
    
    bar_width = 0.12  # Narrow bars for 6 per workload
    
    colors = {'SYSTEM': '#1f77b4', 'NETWORK': '#ff7f0e', 'HWPERF': '#2ca02c'}
    prefixes = ['SYSTEM', 'NETWORK', 'HWPERF']

    def geometric_mean(values):
        values = np.asarray(values, dtype=float)
        values = values[(~np.isnan(values)) & (values > 0)]
        if len(values) == 0:
            return np.nan
        return float(np.exp(np.mean(np.log(values))))

    geo_means = {}
    for prefix in prefixes:
        med_values = [data[f"{category}/{workload}"][f'{prefix}_med']
                      for category in sort_categories(workloads_by_category.keys())
                      for workload in sorted(workloads_by_category[category])]
        p99_values = [data[f"{category}/{workload}"][f'{prefix}_p99']
                      for category in sort_categories(workloads_by_category.keys())
                      for workload in sorted(workloads_by_category[category])]
        geo_means[f'{prefix}_med'] = geometric_mean(med_values)
        geo_means[f'{prefix}_p99'] = geometric_mean(p99_values)

    # Plot bars for each prefix and metric
    for i, prefix in enumerate(prefixes):
        med_values = [data[f"{category}/{workload}"][f'{prefix}_med'] 
                     for category in sort_categories(workloads_by_category.keys()) 
                     for workload in sorted(workloads_by_category[category])]
        p99_values = [data[f"{category}/{workload}"][f'{prefix}_p99'] 
                     for category in sort_categories(workloads_by_category.keys()) 
                     for workload in sorted(workloads_by_category[category])]
        
        # Median bars
        ax.bar([x - bar_width + i * 2 * bar_width for x in x_pos], 
               med_values, bar_width, 
               color=colors[prefix], alpha=0.8, 
               label=f"{prefix} Median (g={geo_means[f'{prefix}_med']:.1f} bytes)", edgecolor='black')
        
        # P99 bars
        ax.bar([x + i * 2 * bar_width for x in x_pos], 
               p99_values, bar_width, 
               color=colors[prefix], alpha=0.5, hatch='//', 
               label=f"{prefix} P99 (geomean={geo_means[f'{prefix}_p99']:.1f} bytes)", edgecolor='black')
    xtick_positions = [x + 1.5 * bar_width for x in x_pos]
    ax.set_xticks(xtick_positions)
    ax.set_xticklabels(x_labels, ha='center', fontsize=18)
    for idx, label in enumerate(ax.get_xticklabels()):
        label.set_y(-0.05 if idx % 2 else 0)

    ax.tick_params(axis='x', length=8, width=1.5, labelsize=18)
    # 2. Iterate through ticks and double the length for every other one
    # This matches your label logic (idx % 2)
    for idx, tick in enumerate(ax.xaxis.get_major_ticks()):
        if not idx % 2:
            # Ticks for labels at y=0 (default length)
            tick.tick1line.set_markersize(8) 
        else:
            # Ticks for labels at y=-0.05 (longer to reach the text)
            # Adjust '25' to match the visual gap created by -0.05
            tick.tick1line.set_markersize(25) 
    ax.set_ylabel('Size (bytes)', fontsize=18)
    ax.tick_params(axis='y', labelsize=18, rotation=90)
    # ax.set_title('Data Sizes by Workload and Monitoring Type', fontsize=18, fontweight='bold')
    ax.legend(loc='upper left', bbox_to_anchor=(0.03, 0.925), fontsize=18, borderaxespad=0.2, 
    borderpad=0.1,       # Extra padding inside the box
    labelspacing=0.2,    # More vertical space between entries
    handletextpad=0.5,   # Bring text closer to the lines
    framealpha=0.5 )
    ax.grid(alpha=0.3, axis='y')
    
    # Add a small top margin so category labels and value text don't overlap the plot edge
    y_min, y_max = ax.get_ylim()
    ax.set_ylim(0, y_max * 1.12)
    y_top = ax.get_ylim()[1]
    y_label_offset = max(y_max * 0.04, max(y_max * 0.01, 1000))
    
    # Add category labels inside the plot area, above workload groups
    for category, (start, end) in category_positions.items():
        mid_pos = (start + end) / 2 + 1.5 * bar_width
        ax.text(mid_pos, y_top * 0.93, category.upper().replace("FBENCH", "FILEBENCH"), 
                ha='center', va='bottom', fontsize=18, fontweight='bold', color='black')
    
    # Add demarcation lines between categories
    for category, (start, end) in category_positions.items():
        if start > 0:
            boundary_x = start - 0.35 + 1.5 * bar_width
            ax.axvline(boundary_x, color='gray', linestyle=':', alpha=0.8, linewidth=1)
    
    # Tighten x-axis limits around the plotted bars and add a small equal gap at both ends
    left_bar_edge = x_pos[0] - bar_width * 1.5
    right_bar_edge = x_pos[-1] + bar_width * 4.5
    extra_gap = bar_width * 1.0
    ax.set_xlim(left_bar_edge - extra_gap, right_bar_edge + extra_gap)
    
    # Add value labels with extra spacing above bars
    for idx, x in enumerate(x_pos):
        workload_name = x_labels[idx]
        # Find the full workload key by matching the workload name with category
        for category in sort_categories(workloads_by_category.keys()):
            if workload_name in workloads_by_category[category]:
                workload = f"{category}/{workload_name}"
                break
        
        for j, prefix in enumerate(['SYSTEM', 'NETWORK', 'HWPERF']):
            med_val = data[workload][f'{prefix}_med']
            p99_val = data[workload][f'{prefix}_p99']
            
            # Only add text for SYSTEM and NETWORK p99
            if prefix in ['SYSTEM', 'NETWORK'] and not np.isnan(p99_val):
                ax.text(x + j * 2 * bar_width, p99_val + y_label_offset, 
                       f'{p99_val:.1f}', ha='center', va='bottom', fontsize=18, rotation=90)
            
            # if not np.isnan(med_val):
            #     ax.text(x - bar_width + j * 2 * bar_width, med_val + y_label_offset, 
            #            f'{med_val:.0f}', ha='center', va='bottom', fontsize=10, rotation=90)
            # if not np.isnan(p99_val):
            #     ax.text(x + j * 2 * bar_width, p99_val + y_label_offset, 
            #            f'{p99_val:.0f}', ha='center', va='bottom', fontsize=10, rotation=90)
    
    plt.tight_layout()
    plt.savefig('combined_sizes_all_prefixes_vertical.png', dpi=300, bbox_inches='tight')
    plt.savefig('combined_sizes_all_prefixes_vertical.pdf', dpi=300, bbox_inches='tight')
    print("✓ Saved combined vertical sizes plot to: combined_sizes_all_prefixes_vertical.png and .pdf")

def create_comparison_csv(all_stats):
    """
    Create a CSV with all latency data for comparison.
    """
    rows = []
    for prefix in ['SYSTEM', 'NETWORK', 'HWPERF']:
        for workload, stats in all_stats[prefix].items():
            rows.append({
                'Prefix': prefix,
                'Workload': workload,
                'Median Latency (ms)': stats['time_median'],
                'P99 Latency (ms)': stats['time_p99'],
                'Min Latency (ms)': stats['time_min'],
                'Max Latency (ms)': stats['time_max'],
                'Median Events': stats['events_median'],
                'P99 Events': stats['events_p99'],
                'Records': stats['records'],
            })
    
    df = pd.DataFrame(rows)
    df.to_csv('combined_workload_comparison.csv', index=False)
    print("✓ Saved comparison CSV to: combined_workload_comparison.csv")
    
    print("\nCombined Comparison Table:")
    print(df.to_string(index=False))

def main():
    print("Loading metrics from all prefixes...")
    all_stats = load_all_prefixes()
    
    print("\nGenerating combined latency visualization...")
    create_combined_latency_plot(all_stats)
    
    print("\nGenerating combined size visualization...")
    create_combined_size_plot(all_stats)
    
    print("\nGenerating comparison CSV...")
    create_comparison_csv(all_stats)
    
    print("\n" + "="*130)
    print("Combined analysis complete!")
    print("="*130)

if __name__ == "__main__":
    main()