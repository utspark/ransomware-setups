import pandas as pd
import numpy as np


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

