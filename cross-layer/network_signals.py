from pathlib import Path

import numpy as np
import pandas as pd

import feature_extraction


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





def get_file_df(filepath: Path) -> pd.DataFrame:
    sep = ","

    df = pd.read_csv(
        filepath,
        sep=sep,
        engine="python",  # needed for callable on_bad_lines
        on_bad_lines=fix_bad_line  # normalize bad rows on the fly
    )

    df.reset_index(drop=True, inplace=True)

    pat = r'((?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d(?:\.\d+)?)'

    df = df[df["tcp.srcport"] != "127.0.0.1"]  # TODO cleaner fix

    df['time'] = df['frame.time'].str.extract(pat)  # first match per row
    df['seconds'] = pd.to_timedelta(df['time']).dt.total_seconds()
    df["seconds"] = df["seconds"] - df["seconds"][0]

    df.drop(columns=["frame.time", "time"], inplace=True)
    col = "seconds"
    df = df[[col] + [c for c in df.columns if c != col]]

    df["merged_src"] = df["tcp.srcport"].fillna(df["udp.srcport"])
    df["merged_src"] = df["merged_src"].fillna(0)
    df["merged_src"] = df["merged_src"].astype(int)
    df["merged_dst"] = df["tcp.dstport"].fillna(df["udp.dstport"])
    df["merged_dst"] = df["merged_dst"].fillna(0)
    df["merged_dst"] = df["merged_dst"].astype(int)
    df = df.drop(columns=["tcp.srcport", "udp.srcport", "tcp.dstport", "udp.dstport", "ip.src", "ip.dst"])
    df = df.drop(columns=["_ws.col.Info"])


    return df


def file_df_feature_extraction(df: pd.DataFrame, window_size_time, window_stride_time) -> pd.DataFrame:
    left_idx, right_idx = feature_extraction.get_time_windows(df["seconds"], window_size_time, window_stride_time)

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

