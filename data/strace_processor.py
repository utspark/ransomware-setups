import io
from importlib.metadata import files
from pathlib import Path

import requests
import pandas as pd
import numpy as np
import csv
from typing import List

import matplotlib
matplotlib.use("Qt5Agg")
import matplotlib.pyplot as plt
plt.ion()



def read_tbl_into_strings(path: Path) -> List[str]:
    """
    Reads a .tbl file (or any text file) and returns a list of strings,
    one per row (line), without the trailing newline.
    """
    lines: List[str] = []
    with path.open('r', encoding='utf-8') as f:
        for line in f:
            # strip only the newline; preserve any other whitespace
            lines.append(line.rstrip('\n'))
    return lines


def form_syscall_dict() -> dict:
    file_path = Path("syscall_64.tbl")

    if not file_path.exists() or not file_path.is_file():
        raw_url = "https://raw.githubusercontent.com/torvalds/linux/refs/heads/master/arch/x86/entry/syscalls/syscall_64.tbl"
        dest = "./syscall_64.tbl"
        dest = Path(dest)

        resp = requests.get(raw_url)
        resp.raise_for_status()  # will raise HTTPError for bad status
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(resp.content)
        print(f"Downloaded {raw_url!r} → {dest}")

    tbl_path = Path('syscall_64.tbl')
    rows_as_strings = read_tbl_into_strings(tbl_path)

    filtered = [s for s in rows_as_strings
                if s.strip() and not s.lstrip().startswith('#')]
    filtered = [s for s in filtered if "x32" not in s]

    syscall_dict = {}

    for row in filtered:
        parts = row.split()
        if len(parts) >= 4:
            syscall_dict[parts[3]] = int(parts[0])

        elif len(parts) == 3:
            syscall_dict[parts[2]] = int(parts[0])

        else:
            raise ValueError(f"Invalid syscall {row}")

    return syscall_dict


def write_out_syscalls(syscall_dict: dict, syscall_lines: list, output_file_path: str) -> None:
    filtered = [s.replace("_enter_", "_") for s in syscall_lines if "_exit_" not in s]
    filtered = [s for s in filtered if "monitor_syscall" not in s]
    filtered = [s for s in filtered if "trace-cmd" not in s]

    syscall_ints = []
    syscall_time = []

    for row in filtered:
        parts = row.split()

        syscall_text = parts[3][:-1]
        syscall_ts = parts[2][:-1]

        try:
            syscall_ints.append(syscall_dict[syscall_text])
            syscall_time.append(float(syscall_ts))
        except KeyError:
            substr = "sys_"
            index, first = next(((i, s) for i, s in enumerate(parts) if substr in s), (None, None))

            if first:
                first = first[:-1]
                ts = parts[index - 1][:-1]
                # if first == '112882.623291':
                #     print("hi")

                syscall_ints.append(syscall_dict[first])
                syscall_time.append(float(ts))

            else:
                print(f"Invalid syscall {row}")
                continue
                # raise ValueError(f"Invalid syscall: {row}")

        with open(output_file_path, 'w', encoding='utf-8') as f:
            f.write(" ".join(map(str, syscall_ints)) + "\n")
            f.write(" ".join(map(str, syscall_time)))

    return


if __name__ == "__main__":
    TRANSLATE_SYSCALL_FILES = True

    if TRANSLATE_SYSCALL_FILES:
        syscall_dict = form_syscall_dict()

        # file_list = [
        #     "syscall_data/AES_O_noexfil_comb_system",
        #     "syscall_data/AES_WA_noexfil_comb_system",
        #     "syscall_data/AES_WB_noexfil_comb_system",
        #     # "syscall_data/perf_syscalls_ransom",
        #     # "syscall_data/strace_syscalls_ransom",
        # ]

        file_list = [
            "ftrace/idle_20_trace_system_timed",

            "ftrace/AES_O_exfil_aws1_system_timed",
            "ftrace/AES_O_exfil_aws2_system_timed",
            "ftrace/AES_O_exfil_sftp1_system_timed",
            "ftrace/AES_O_exfil_sftp2_system_timed",
            "ftrace/gzip_system_timed",
        ]

        for base_file in file_list:
            input_file_path = Path("./" + base_file)
            output_file_path = Path("./" + base_file + "_ints.txt")

            directory = Path("/path/to/your/dir")
            filename = "my_file.txt"
            file_path = directory / filename

            if output_file_path.is_file():
                continue

            syscall_lines = read_tbl_into_strings(input_file_path)

            target = "cpus=32"
            idx = next((i for i, s in enumerate(syscall_lines) if s == target), None) + 1
            syscall_lines = syscall_lines[idx:]
            write_out_syscalls(syscall_dict, syscall_lines, output_file_path)


    cwd = Path.cwd()
    file_list = [
        "ftrace/idle_20_trace_system_timed_ints.txt",

        "ftrace/AES_O_exfil_aws1_system_timed_ints.txt",
        "ftrace/AES_O_exfil_aws2_system_timed_ints.txt",
        "ftrace/AES_O_exfil_sftp1_system_timed_ints.txt",
        "ftrace/AES_O_exfil_sftp2_system_timed_ints.txt",
        "ftrace/gzip_system_timed_ints.txt",
    ]


    trace_list = []
    time_list = []

    for file in file_list:
        file_path = cwd / file

        with open(file, "r", newline="") as f:
            lines = f.readlines()
            arr1 = np.loadtxt(io.StringIO(lines[0]), dtype=int)
            arr2 = np.loadtxt(io.StringIO(lines[1]), dtype=float)
            trace_list.append(arr1)
            time_list.append(arr2)

    # TODO comment exception just to pause the script
    raise Exception

    fig, ax = plt.subplots(3, 1, figsize=(10, 4), sharey=True)
    ax[0].plot(time_list[0], trace_list[0], color="blue", marker='.', linestyle="None", markersize=2.5, markeredgecolor='none')
    ax[1].plot(time_list[1], trace_list[1], color="red", marker='.', linestyle="None", markersize=2.5, markeredgecolor='none')
    ax[2].plot(time_list[5], trace_list[5], color="green", marker='.', linestyle="None", markersize=2.5, markeredgecolor='none')
    plt.tight_layout()
    plt.show()

    fig, ax = plt.subplots(1, 1, figsize=(10, 4), sharey=True)
    ax.plot(trace_list[1], color="blue", marker='o', linestyle="None")
    ax.plot(trace_list[3], color="green", marker='o', linestyle="None")
    plt.tight_layout()
    plt.show()

    fig, ax = plt.subplots(3, 1, figsize=(10, 4), sharey=True)
    ax.plot(trace_list[0][0:2000], color="blue", marker='o', linestyle="None")
    ax.plot(trace_list[1][0:2000], color="red", marker='o', linestyle="None")
    ax.plot(trace_list[5][0:2000], color="green", marker='o', linestyle="None")
    plt.tight_layout()
    plt.show()



    fig, ax = plt.subplots(3, 1, figsize=(10, 4), sharey=True)
    ax[0].plot(trace_list[0], color="blue", marker='o', linestyle="None")
    ax[1].plot(trace_list[1], color="red", marker='o', linestyle="None")
    ax[2].plot(trace_list[3], color="green", marker='o', linestyle="None")
    plt.tight_layout()
    plt.show()

    fig, ax = plt.subplots(3, 1, figsize=(10, 4), sharey=True)
    ax[0].plot(trace_list[0][4000:6000], color="blue", marker='o', linestyle="None")
    ax[1].plot(trace_list[1][4000:6000], color="red", marker='o', linestyle="None")
    ax[2].plot(trace_list[2][4000:6000], color="green", marker='o', linestyle="None")
    plt.tight_layout()
    plt.show()

    # your 1-D integer array
    arr_1 = trace_list[0]
    arr_2 = trace_list[1]

    # 1) Build a common set of unique values across both arrays
    unique_vals = np.unique(np.concatenate([arr_1, arr_2]))

    # 2) Construct bin edges so each integer gets its own bin
    bin_edges = np.concatenate([unique_vals - 0.5, [unique_vals[-1] + 0.5]])

    # 3) Create a 1×2 grid of subplots
    fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(12, 5))

    # 4) Plot the first histogram
    ax1.hist(arr_1, bins=bin_edges, edgecolor='black')
    ax1.set_xticks(unique_vals)
    ax1.set_xlabel('Value')
    ax1.set_ylabel('Frequency')
    ax1.set_title('Histogram of arr1')

    # 5) Plot the second histogram
    ax2.hist(arr_2, bins=bin_edges, edgecolor='black')
    ax2.set_xticks(unique_vals)
    ax2.set_xlabel('Value')
    ax2.set_ylabel('Frequency')
    ax2.set_title('Histogram of arr2')

    # 6) Layout and show
    plt.tight_layout()
    plt.show()

    x = np.concatenate([arr_1, arr_2])
    unique_vals = np.unique(x.reshape(-1))
    new_labels = np.arange(len(unique_vals))
    max_val = unique_vals.max()
    lookup = np.full(max_val + 1, -1, dtype=int)
    lookup[unique_vals] = new_labels

    mapped_arr_1 = lookup[arr_1]
    mapped_arr_2 = lookup[arr_2]

    arr_1 = mapped_arr_1
    arr_2 = mapped_arr_2

    arr1 = mapped_arr_1
    arr2 = mapped_arr_2


    # 1) Get the sorted unique values across both arrays
    unique_vals = np.unique(np.concatenate([arr1, arr2]))

    # 2) Compute counts for each array at each unique value
    counts1 = [(arr1 == v).sum() for v in unique_vals]
    counts2 = [(arr2 == v).sum() for v in unique_vals]

    # 3) Set up bar positions for grouped bars
    x = np.arange(len(unique_vals))
    width = 0.35  # width of each bar

    # 4) Plot
    fig, ax = plt.subplots(figsize=(10, 5))
    ax.bar(x - width / 2, counts1, width=width, label='arr1', edgecolor='black')
    ax.bar(x + width / 2, counts2, width=width, label='arr2', edgecolor='black')

    # 5) Labels and ticks
    ax.set_xlabel('Value')
    ax.set_ylabel('Frequency')
    ax.set_title('Grouped Histogram of arr1 vs. arr2')
    ax.set_xticks(x)
    ax.set_xticklabels(unique_vals)
    ax.legend()
    ax.grid(axis='y', linestyle='--', alpha=0.5)

    plt.tight_layout()
    plt.show()




    super_array = np.concatenate(trace_list)
    unique_vals = np.unique(super_array)

    rev_unique = {v: k for k, v in syscall_dict.items()}

    english_names = []
    for val in unique_vals:
        english_names.append(rev_unique[val])

    for name in english_names:
        print(name)






