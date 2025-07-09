import numpy as np
from sklearn.preprocessing import OneHotEncoder


def form_array_from_files(child_path, file_subsample=-1) -> np.array:
    if file_subsample == -1:
        file_subsample = 40

    files = [p for p in child_path.iterdir() if p.is_file()]
    files.sort()

    trace_list = []
    # TODO use all files
    for file_name in files[0:file_subsample]:
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

    return padded_matrix


def form_one_hot_encoder(benign_array) -> OneHotEncoder:
    max_syscall = np.max(benign_array)
    one_hot_array = np.array(range(max_syscall))
    one_hot_array = one_hot_array.reshape(-1, 1)
    enc = OneHotEncoder(handle_unknown='ignore')
    enc.fit(one_hot_array)

    return enc


def increase_padding(pad_target, max_len) -> np.array:
    pad_len = max_len - pad_target.shape[1]
    pad_array = np.zeros((pad_target.shape[0], pad_len))
    padded = np.concatenate((pad_target, pad_array), axis=1)

    return padded



