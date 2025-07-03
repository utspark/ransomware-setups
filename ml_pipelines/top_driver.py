import csv
import numpy as np
from sklearn.preprocessing import OneHotEncoder
from pathlib import Path

import os
os.environ["QT_QPA_PLATFORM"] = "wayland"

import matplotlib
matplotlib.use("Qt5Agg")
import matplotlib.pyplot as plt



if __name__ == "__main__":
    plt.ion()

    cwd = Path.cwd()
    child = cwd / "ADFA-IDS_DATASETS/ADFA-LD/Training_Data_Master"
    files = [p for p in child.iterdir() if p.is_file()]

    trace_list = []

    for file_name in files[0:20]:
        print(file_name.name)
        file_path = str(file_name)

        with open(file_path, "r", newline="") as f:
            arr = np.loadtxt(f, dtype=int)
            trace_list.append(arr)

    # trace_list = trace_list[50]
    max_len = max(a.shape[0] for a in trace_list)

    # TODO think of proper padding approach
    padded = [
        np.pad(a,
               pad_width=(0, max_len - a.shape[0]),
               mode='constant',
               constant_values=0)
        for a in trace_list
    ]

    padded_matrix = np.vstack(padded)

    # raise Exception

    max_syscall = np.max(padded_matrix)
    one_hot_array = np.array(range(max_syscall))
    one_hot_array = one_hot_array.reshape(-1, 1)
    enc = OneHotEncoder(handle_unknown='ignore')
    enc.fit(one_hot_array)

    padded_matrix = padded_matrix.reshape(-1, 1)
    X = enc.transform(padded_matrix).toarray()
    X = X.reshape(-1, max_len, max_syscall)

    # TODO
    #  - import file with numpy
    #  - one-hot encode each value [sequence of 255-wide vectors]
    #  - train-test on data

    padded_matrix = padded_matrix.reshape(-1, max_len)


    # Create the plot
    plt.plot(padded_matrix[0, :], marker='o', linestyle="None")
    plt.plot(padded_matrix[1, :], marker='o', linestyle="None")
    plt.plot(padded_matrix[2, :], marker='o', linestyle="None")
    plt.plot(padded_matrix[3, :], marker='o', linestyle="None")
    plt.plot(padded_matrix[4, :], marker='o', linestyle="None")
    plt.show()

