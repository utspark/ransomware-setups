from pathlib import Path
import numpy as np
import io

import pandas as pd

import feature_extraction


def get_file_df(filepath: Path) -> pd.DataFrame:
    with open(filepath, "r", newline="") as f:
        lines = f.readlines()
        arr1 = np.loadtxt(io.StringIO(lines[0]), dtype=int)
        arr2 = np.loadtxt(io.StringIO(lines[1]), dtype=float)

    arr1 = arr1.reshape(-1, 1)
    arr2 = arr2.reshape(-1, 1)
    df = pd.DataFrame(np.column_stack((arr2, arr1)), columns=["seconds", "syscall"])

    df["seconds"] = df["seconds"] - df["seconds"][0]

    return df


def file_df_feature_extraction(df: pd.DataFrame, window_size_time, window_stride_time, preserve_time=False) -> pd.DataFrame:
    left_idx, right_idx = feature_extraction.get_time_windows(df["seconds"], window_size_time, window_stride_time)

    feature_list = []

    for i, j in zip(left_idx, right_idx):
        window = df.iloc[i:j]
        values = window["syscall"]

        window_len = len(values)
        syscall_max = np.max(values)
        syscall_mean = np.mean(values)
        syscall_min = np.min(values)
        syscall_std = np.std(values)
        syscall_ptp = np.ptp(values)

        features = [
            window_len,
            syscall_max,
            syscall_mean,
            syscall_min,
            syscall_std,
            syscall_ptp,
        ]
        feature_list.append(features)

    col = [
        "window_len",
        "syscall_max",
        "syscall_mean",
        "syscall_min",
        "syscall_std",
        "syscall_ptp",
    ]

    X = pd.DataFrame(feature_list, columns=col)

    if preserve_time:
        X["time"] = df["seconds"].iloc[right_idx].reset_index(drop=True)
        X.insert(0, "time", X.pop("time"))

    X = X[X["window_len"] != 0]

    return X


