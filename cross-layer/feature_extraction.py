import pandas as pd
import numpy as np


def get_time_windows(t: pd.Series, window_size_time: float, window_stride_time: float):
    t = t.copy().reset_index(drop=True)

    left_edges = np.arange(t.iloc[0], t.iloc[-1] - window_size_time, window_stride_time)
    right_edges = np.arange(t.iloc[0] + window_size_time, t.iloc[-1], window_stride_time)

    if len(left_edges) == 0:
        left_indices = np.array([0])
        right_indices = np.array([len(t)])

    else:
        left_indices = np.searchsorted(t, left_edges, side="left")
        right_indices = np.searchsorted(t, right_edges, side="left")

    return left_indices, right_indices

