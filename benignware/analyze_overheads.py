#!/usr/bin/env python3
"""
Parse all latency_overhead.log files under benignware and plot tracing overheads.
The script detects syscall, network, hardware, and none trace modes per workload,
computes average latency and overhead relative to the none baseline, and creates plots.
"""

import re
from pathlib import Path

import matplotlib.pyplot as plt
import pandas as pd
import seaborn as sns

BASE_DIR = Path(__file__).resolve().parent
OUTPUT_CSV = BASE_DIR / 'overhead_durations.csv'
OVERVIEW_CSV = BASE_DIR / 'workload_overheads.csv'
PLOT_DURATION_FILE = BASE_DIR / 'trace_duration_by_workload.png'
PLOT_OVERHEAD_FILE = BASE_DIR / 'trace_overhead_by_workload.png'
PLOT_MEDIAN_FILE = BASE_DIR / 'median_overhead_by_trace.png'

TRACE_LINE_RE = re.compile(
    r'^(Syscall Trace|Network Trace|Hardware Performance Trace|No Trace)\s+(.+)$',
    re.IGNORECASE,
)
DURATION_RE = re.compile(r'^Duration\s*[:=]?\s*([0-9]+(?:\.[0-9]+)?)\s*ms', re.IGNORECASE)
DURATION_INLINE_RE = re.compile(
    r'^Duration\s*[:=]?\s*([0-9]+(?:\.[0-9]+)?)\s*ms\s+([A-Za-z0-9 _-]+)\s+(.+)$',
    re.IGNORECASE,
)

TRACE_TYPE_MAP = {
    'syscall trace': 'syscall',
    'network trace': 'network',
    'hardware performance trace': 'hardware',
    'no trace': 'none',
    'system': 'syscall',
    'network': 'network',
    'hwperf': 'hardware',
    'none': 'none',
}


def find_latency_files():
    files = sorted(BASE_DIR.rglob('output_timed/latency_overhead.log'))
    return files


def parse_latency_file(path):
    records = []
    current = {'trace_type': None, 'workload': None}
    category = path.parent.parent.name

    with path.open('r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            trace_match = TRACE_LINE_RE.match(line)
            if trace_match:
                trace_label = trace_match.group(1).strip().lower()
                current['trace_type'] = TRACE_TYPE_MAP.get(trace_label, None)
                current['workload'] = trace_match.group(2).strip()
                continue

            duration_inline_match = DURATION_INLINE_RE.match(line)
            if duration_inline_match:
                duration_ms = float(duration_inline_match.group(1))
                trace_label = duration_inline_match.group(2).strip().lower()
                workload = duration_inline_match.group(3).strip()
                trace_type = TRACE_TYPE_MAP.get(trace_label, None)
                if trace_type and workload:
                    records.append({
                        'category': category,
                        'workload': workload,
                        'trace_type': trace_type,
                        'duration_ms': duration_ms,
                        'source_file': str(path),
                    })
                continue

            duration_match = DURATION_RE.match(line)
            if duration_match and current['trace_type'] and current['workload']:
                records.append({
                    'category': category,
                    'workload': current['workload'],
                    'trace_type': current['trace_type'],
                    'duration_ms': float(duration_match.group(1)),
                    'source_file': str(path),
                })

    return records


def load_all_records():
    files = find_latency_files()
    if not files:
        raise FileNotFoundError('No latency_overhead.log files found under benignware/*/output_timed/')

    all_records = []
    for path in files:
        print(f'Parsing: {path}')
        all_records.extend(parse_latency_file(path))

    if not all_records:
        raise ValueError('No duration records were parsed from latency_overhead.log files.')

    return pd.DataFrame(all_records)


def aggregate_records(df):
    grouped = (
        df.groupby(['category', 'workload', 'trace_type'])['duration_ms']
        .mean()
        .reset_index()
        .rename(columns={'duration_ms': 'avg_duration_ms'})
    )
    grouped['workload_label'] = grouped['category'] + '/' + grouped['workload']
    return grouped


def compute_overhead(grouped):
    baseline = grouped[grouped['trace_type'] == 'none'][['category', 'workload', 'avg_duration_ms']]
    baseline = baseline.rename(columns={'avg_duration_ms': 'baseline_none_ms'})
    merged = grouped.merge(baseline, on=['category', 'workload'], how='left')
    merged['overhead_ms'] = merged['avg_duration_ms'] - merged['baseline_none_ms']
    merged['overhead_pct'] = merged.apply(
        lambda row: (row['overhead_ms'] / row['baseline_none_ms'] * 100)
        if row['baseline_none_ms'] and row['trace_type'] != 'none'
        else 0,
        axis=1,
    )
    return merged


def plot_duration_summary(grouped):
    plt.figure(figsize=(18, 9))
    plot_df = grouped[grouped['trace_type'] != 'none'].copy()
    sns.barplot(
        data=plot_df,
        x='workload_label',
        y='avg_duration_ms',
        hue='trace_type',
        palette='Set2',
    )
    plt.title('Average Trace Duration by Category/Workload')
    plt.ylabel('Average Duration (ms)')
    plt.xlabel('Category / Workload')
    plt.xticks(rotation=45, ha='right')
    plt.legend(title='Trace Type')
    plt.tight_layout()
    plt.savefig(PLOT_DURATION_FILE, dpi=300)
    plt.close()
    print(f'Saved duration comparison plot: {PLOT_DURATION_FILE}')


def plot_overhead_summary(overhead):
    plt.figure(figsize=(18, 9))
    plot_df = overhead[overhead['trace_type'] != 'none'].copy()
    sns.barplot(
        data=plot_df,
        x='workload_label',
        y='overhead_ms',
        hue='trace_type',
        palette='Set1',
    )
    plt.title('Absolute Overhead over No Trace by Category/Workload')
    plt.ylabel('Overhead (ms)')
    plt.xlabel('Category / Workload')
    plt.xticks(rotation=45, ha='right')
    plt.legend(title='Trace Type')
    plt.tight_layout()
    plt.savefig(PLOT_OVERHEAD_FILE, dpi=300)
    plt.close()
    print(f'Saved overhead plot: {PLOT_OVERHEAD_FILE}')


def plot_median_overhead(overhead):
    medians = (
        overhead[overhead['trace_type'] != 'none']
        .groupby('trace_type')['overhead_ms']
        .median()
        .reset_index()
    )
    plt.figure(figsize=(8, 6))
    sns.barplot(
        data=medians,
        x='trace_type',
        y='overhead_ms',
        palette='pastel',
    )
    plt.title('Median Trace Overhead over No Trace by Trace Type')
    plt.ylabel('Median Overhead (ms)')
    plt.xlabel('Trace Type')
    for index, row in medians.iterrows():
        plt.text(index, row['overhead_ms'] + max(medians['overhead_ms']) * 0.01,
                 f"{row['overhead_ms']:.1f} ms", ha='center', va='bottom')
    plt.tight_layout()
    plt.savefig(PLOT_MEDIAN_FILE, dpi=300)
    plt.close()
    print(f'Saved median overhead plot: {PLOT_MEDIAN_FILE}')


def main():
    df = load_all_records()
    df.to_csv(OUTPUT_CSV, index=False)
    print(f'Saved raw duration records to: {OUTPUT_CSV}')

    grouped = aggregate_records(df)
    overhead = compute_overhead(grouped)
    overhead.to_csv(OVERVIEW_CSV, index=False)
    print(f'Saved aggregated overheads to: {OVERVIEW_CSV}')

    print('\nCreating plots...')
    plot_duration_summary(grouped)
    plot_overhead_summary(overhead)
    plot_median_overhead(overhead)

    print('\nAnalysis complete. Use the generated plots and CSV files for workload overhead inspection.')


if __name__ == '__main__':
    main()
