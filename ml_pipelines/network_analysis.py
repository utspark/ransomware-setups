from pathlib import Path

# Requires tshark installed (Wireshark) + pyshark:
#   - macOS: brew install wireshark
#   - Linux: apt/dnf install tshark
# pip install pyshark pandas

import pyshark
import pandas as pd
import csv
import re


# 2) Fix lines that have too many/few fields
def fix_bad_line(fields: list[str]) -> list[str] | None:
    expected = 11

    if len(fields) > expected:
        # keep first expected-1 fields; glue the remainder into the last field
        tail = sep.join(fields[expected - 1:])
        return fields[:expected - 1] + [tail]
    elif len(fields) < expected:
        # (optional) pad short rows
        return fields + [""] * (expected - len(fields))
    return fields


def time_to_seconds(s: str) -> float:
    """
    Parse a time string into seconds (float).
    Supports:
      - "HH:MM:SS", "MM:SS", "SS" (seconds may be fractional)
      - "1h 2m 3.4s" (units optional, case-insensitive, spaces optional)
    """
    s = s.strip()

    # Pattern with explicit units, e.g. "1h 2m 3.4s", "2m", "45.5s"
    m = re.fullmatch(r'(?:(\d+)\s*h)?\s*(?:(\d+)\s*m)?\s*(?:(\d+(?:\.\d+)?)\s*s)?', s, re.I)
    if m and any(m.groups()):
        h = int(m.group(1) or 0)
        m_ = int(m.group(2) or 0)
        sec = float(m.group(3) or 0.0)
        return h * 3600 + m_ * 60 + sec

    # Colon formats: HH:MM:SS(.ms) | MM:SS(.ms) | SS(.ms)
    parts = s.split(':')
    if len(parts) == 3:
        h, m_, sec = parts
        return int(h) * 3600 + int(m_) * 60 + float(sec)
    elif len(parts) == 2:
        m_, sec = parts
        return int(m_) * 60 + float(sec)
    elif len(parts) == 1:
        return float(parts[0])  # already seconds (maybe fractional)

    raise ValueError(f"Unrecognized time string format: {s!r}")


if __name__ == "__main__":
    cwd = Path.cwd()
    data_dir = cwd / "../data/v4_results/out_recon"

    paths = [p for p in data_dir.iterdir() if p.is_file()]
    paths.sort()

    # if file_list is not None:
    #     file_set = set(file_list)
    #     filtered = [path for path in paths if path.name in file_set]
    #     paths = filtered



    # with open(file_path, "r", newline="") as f:
    #     lines = f.readlines()
    #     arr1 = np.loadtxt(io.StringIO(lines[0]), dtype=int)
    #     # arr2 = np.loadtxt(io.StringIO(lines[1]), dtype=float)
    #     trace_list.append(arr1)


    filename = paths[0]
    sep = ","

    bad_rows = []

    # with open(filename, newline="", encoding="utf-8") as f:
    #     header = next(csv.reader(f, delimiter=sep))
    # expected = len(header)

    df = pd.read_csv(
        filename,
        sep=sep,
        engine="python",  # needed for callable on_bad_lines
        on_bad_lines=fix_bad_line  # normalize bad rows on the fly
    )

    df.reset_index(drop=True, inplace=True)

    pat = r'((?:[01]\d|2[0-3]):[0-5]\d:[0-5]\d(?:\.\d+)?)'

    df['time'] = df['frame.time'].str.extract(pat)  # first match per row
    df['seconds'] = pd.to_timedelta(df['time']).dt.total_seconds()

    df.drop(columns=["frame.time", "time"], inplace=True)
    col = "seconds"
    df = df[[col] + [c for c in df.columns if c != col]]

    df["seconds"] = df["seconds"] - df["seconds"][0]

    # delta_next_minus_current = df["seconds"].shift(-1) - df["seconds"]

    import numpy as np


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


    times = np.array([0.0, 1.5, 5.0, 5.1, 9.99])  # floats (e.g., seconds)
    vals = np.array([2.0, 3.5, 1.0, 4.0, 5.0])
    span = 5.0  # look back 5 seconds at each timestamp

    span = 5.0
    left, right = time_window_bounds_float(times, span)

    # TODO
    #  - ignore info column, concatenate the extra commas
    #  - convert syscalls and network to time-domain

