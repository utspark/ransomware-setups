from pathlib import Path

# Requires tshark installed (Wireshark) + pyshark:
#   - macOS: brew install wireshark
#   - Linux: apt/dnf install tshark
# pip install pyshark pandas

import pyshark
import pandas as pd
import csv
import re
import numpy as np


# 2) Fix lines that have too many/few fields
def fix_bad_line(fields: list[str]) -> list[str] | None:
    expected = 11
    sep = ","

    if len(fields) > expected:
        # keep first expected-1 fields; glue the remainder into the last field
        tail = sep.join(fields[expected - 1:])
        return fields[:expected - 1] + [tail]
    elif len(fields) < expected:
        # (optional) pad short rows
        return fields + [""] * (expected - len(fields))
    return fields


def get_time_windows(t: pd.Series, window_size_time: float, window_stride_time: float):
    def time_window_bounds_float(t, span):
        """
        For each time t[i], compute left index of the closed window [t[i]-span, t[i]].
        times: array-like of floats (ascending if assume_sorted=True)
        span: non-negative float (same units as times)
        Returns: (left_idx, right_idx) for the *sorted* order.
        """
        left = np.searchsorted(t, t - span, side="left")
        right = np.arange(t.size)  # inclusive end at each i

        return left, right

    time_windowed_left, time_windowed_right = time_window_bounds_float(t, window_size_time)

    time_strided_right = np.arange(window_size_time, t.iloc[-1], window_stride_time)
    time_indices = np.searchsorted(t, time_strided_right)

    left_indices = time_windowed_left[time_indices]
    right_indices = time_windowed_right[time_indices]

    return np.array(left_indices), np.array(right_indices)


def get_network_file_df(filepath: Path) -> pd.DataFrame:
    sep = ","

    df = pd.read_csv(
        filepath,
        sep=sep,
        engine="python",  # needed for callable on_bad_lines
        on_bad_lines=fix_bad_line  # normalize bad rows on the fly
    )

    df.reset_index(drop=True, inplace=True)

    pat = r'((?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d(?:\.\d+)?)'

    df['time'] = df['frame.time'].str.extract(pat)  # first match per row
    df['seconds'] = pd.to_timedelta(df['time']).dt.total_seconds()
    df["seconds"] = df["seconds"] - df["seconds"][0]

    df.drop(columns=["frame.time", "time"], inplace=True)
    col = "seconds"
    df = df[[col] + [c for c in df.columns if c != col]]

    df["merged_src"] = df["tcp.srcport"].fillna(df["udp.srcport"])
    df["merged_dst"] = df["tcp.dstport"].fillna(df["udp.dstport"])
    df = df.drop(columns=["tcp.srcport", "udp.srcport", "tcp.dstport", "udp.dstport", "ip.src", "ip.dst"])
    df = df.drop(columns=["_ws.col.Info"])

    return df


def network_df_feature_extraction(df: pd.DataFrame) -> pd.DataFrame:
    window_size_time = 0.1
    window_stride_time = 0.05

    left_idx, right_idx = get_time_windows(df["seconds"], window_size_time, window_stride_time)

    feature_list = []

    for i, j in zip(left_idx, right_idx):
        window = df.iloc[i:j]

        window_len = len(window)
        max_frame_len = np.max(window["frame.len"])
        mean_frame_len = np.mean(window["frame.len"])
        min_frame_len = np.min(window["frame.len"])
        std_frame_len = np.std(window["frame.len"])
        unique_src_ports = len(np.unique(window["merged_src"]))
        unique_dst_ports = len(np.unique(window["merged_dst"]))
        protocol_count_str = str(window["_ws.col.Protocol"])
        ssh_count = protocol_count_str.count("SSH")
        nfs_count = protocol_count_str.count("NFS")
        arp_count = protocol_count_str.count("ARP")
        tcp_count = protocol_count_str.count("TCP")

        protocol_count_sum = ssh_count + nfs_count + arp_count + tcp_count + 1

        ssh_count = ssh_count / protocol_count_sum
        nfs_count = nfs_count / protocol_count_sum
        arp_count = arp_count / protocol_count_sum
        tcp_count = tcp_count / protocol_count_sum

        features = [
            window_len,
            max_frame_len,
            mean_frame_len,
            min_frame_len,
            std_frame_len,
            unique_src_ports,
            unique_dst_ports,
            ssh_count,
            nfs_count,
            arp_count,
            tcp_count
        ]

        feature_list.append(features)

    col = [
        "window_len",
        "max_frame_len",
        "mean_frame_len",
        "min_frame_len",
        "std_frame_len",
        "unique_src_ports",
        "unique_dst_ports",
        "ssh_count",
        "nfs_count",
        "arp_count",
        "tcp_count"
    ]

    X = pd.DataFrame(feature_list, columns=col)
    X = X[X["window_len"] != 0]

    return X



if __name__ == "__main__":
    cwd = Path.cwd()
    data_dir = cwd / "../data/v4_results/out_recon"

    paths = [p for p in data_dir.iterdir() if p.is_file()]
    paths.sort()

    filename = paths[0]

    df = get_network_file_df(filename)
    X = network_df_feature_extraction(df)



    # TODO
    #  - convert syscalls and network to time-domain

