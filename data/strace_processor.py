import io
from pathlib import Path
from typing import List

import matplotlib
import numpy as np
import requests

matplotlib.use("Qt5Agg")
import matplotlib.pyplot as plt
plt.ion()



def read_tbl_into_strings(path: Path, file_line_subsample: int | None = None) -> List[str]:
    """
    Reads a .tbl file (or any text file) and returns a list of strings,
    one per row (line), without the trailing newline.
    """
    lines: List[str] = []
    count = 0

    if file_line_subsample is None:
        with path.open('r', encoding='utf-8') as f:
            for line in f:
                # strip only the newline; preserve any other whitespace
                lines.append(line.rstrip('\n'))

    else:
        with path.open('r', encoding='utf-8') as f:
            for line in f:
                # strip only the newline; preserve any other whitespace
                lines.append(line.rstrip('\n'))
                count += 1

                if count >= file_line_subsample:
                    break

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


def find_non_txt_files(root: Path = Path.cwd()) -> list[Path]:
    """Return all files under `root` (recursively) that do NOT have a .txt extension."""
    return [p for p in root.rglob('*') if p.is_file() and p.suffix.lower() != '.txt']


def process_one_file(input_file_path: Path, syscall_dict: dict, file_line_subsample: int | None = None) -> None:
    """
    Read a text file -> parse into a NumPy array -> transform -> write .txt.
    Does not return anything; writes to disk.
    """
    try:
        output_file_path = input_file_path.with_name(input_file_path.name + "_ints.txt")

        syscall_lines = read_tbl_into_strings(input_file_path, file_line_subsample)

        idx = next((i for i, s in enumerate(syscall_lines) if s.startswith("cpus=")), -1) + 1
        syscall_lines = syscall_lines[idx:]
        write_out_syscalls(syscall_dict, syscall_lines, output_file_path)

    except Exception as e:
        # Bubble up with file context to see which file failed
        raise RuntimeError(f"Failed on {input_file_path}") from e

    return


def process_files_in_parallel(files, syscall_dict: dict, n_workers: int | None = None,
                              file_line_subsample: int | None = None) -> None:
    """
    Process each file in parallel using up to n_workers processes.
    files: iterable of paths (str or Path) to input .txt files
    out_dir: directory to write outputs
    """
    paths = [Path(p) for p in files]

    n = n_workers or (os.cpu_count() or 1)
    with ProcessPoolExecutor(max_workers=n) as ex:
        futures = {ex.submit(process_one_file, p, syscall_dict, file_line_subsample): p for p in paths}
        for fut in as_completed(futures):
            p = futures[fut]  # the input file for this future
            try:
                fut.result()  # raises if the worker failed
                print(f"OK: {p}")
            except Exception as e:
                print(f"FAILED: {p} → {e}")

    return


if __name__ == "__main__":
    TRANSLATE_SYSCALL_FILES = False
    SPECIFY_FILES = False
    DATA_DIR = Path.cwd() / "ftrace_results"
    FILE_LINE_SUBSAMPLE = 100_000

    if TRANSLATE_SYSCALL_FILES:

        syscall_dict = form_syscall_dict()

        if SPECIFY_FILES:
            file_list = [
                "ftrace/idle_20_trace_system_timed",

                "ftrace/AES_O_exfil_aws1_system_timed",
                "ftrace/AES_O_exfil_aws2_system_timed",
                "ftrace/AES_O_exfil_sftp1_system_timed",
                "ftrace/AES_O_exfil_sftp2_system_timed",
                "ftrace/gzip_system_timed",
            ]

        else:
            file_list = find_non_txt_files(DATA_DIR)

        # process_one_file(file_list[0], syscall_dict)
        process_files_in_parallel(file_list, syscall_dict, n_workers=10, file_line_subsample=FILE_LINE_SUBSAMPLE)



    cwd = Path.cwd()
    file_list = [
        # "ftrace_results_subsampled_ints/out_exec_parsed/asymm_0_ints.txt",

        # "ftrace_results_subsampled_ints/out_exfil_parsed/compress_gzip_1t_0_ints.txt",



        "pipeline_ints/recon_system_1_ints.txt",
        "pipeline_ints/recon_system_2_ints.txt",

        "pipeline_ints/recon_net_1_ints.txt",
        "pipeline_ints/recon_net_2_ints.txt",

        "pipeline_ints/recon_mount_3_ints.txt",

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


    fig, ax = plt.subplots(5, 1, figsize=(10, 4), sharey=True)
    ax[0].plot(time_list[0], trace_list[0], color="blue", marker='.', linestyle="None", markersize=2.5, markeredgecolor='none')
    ax[1].plot(time_list[1], trace_list[1], color="red", marker='.', linestyle="None", markersize=2.5, markeredgecolor='none')
    ax[2].plot(time_list[2], trace_list[2], color="green", marker='.', linestyle="None", markersize=2.5, markeredgecolor='none')
    ax[3].plot(time_list[3], trace_list[3], color="orange", marker='.', linestyle="None", markersize=2.5, markeredgecolor='none')
    ax[4].plot(time_list[4], trace_list[4], color="purple", marker='.', linestyle="None", markersize=2.5, markeredgecolor='none')
    plt.tight_layout()
    plt.show()


    fig, ax = plt.subplots(5, 1, figsize=(10, 4), sharey=True)
    ax[0].plot(trace_list[0], color="blue", marker='.', linestyle="None", markersize=2.5, markeredgecolor='none')
    ax[1].plot(trace_list[1], color="red", marker='.', linestyle="None", markersize=2.5, markeredgecolor='none')
    ax[2].plot(trace_list[2], color="green", marker='.', linestyle="None", markersize=2.5, markeredgecolor='none')
    ax[3].plot(trace_list[3], color="orange", marker='.', linestyle="None", markersize=2.5, markeredgecolor='none')
    ax[4].plot(trace_list[4], color="purple", marker='.', linestyle="None", markersize=2.5, markeredgecolor='none')
    plt.tight_layout()
    plt.show()

    raise Exception

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






