from pathlib import Path
import network_signals
import syscall_signals


if __name__ == "__main__":
    cwd = Path.cwd()

    window_size_time = 0.1 / 10
    window_stride_time = 0.05 / 10

    syscall_dir = cwd / "../data/ftrace_results_ints/out_exec_parsed"
    syscall_paths = [p for p in syscall_dir.iterdir() if p.is_file()]
    syscall_paths.sort()

    syscall_file_path = syscall_paths[0]
    df = syscall_signals.get_file_df(syscall_file_path)
    syscall_X = syscall_signals.file_df_feature_extraction(df, window_size_time, window_stride_time)

    network_dir = cwd / "../data/v4_results/out_exec"
    network_paths = [p for p in network_dir.iterdir() if p.is_file()]
    network_paths.sort()

    network_file_path = network_paths[0]
    df = network_signals.get_file_df(network_file_path)
    network_X = network_signals.file_df_feature_extraction(df, window_size_time, window_stride_time)



    # TODO
    #  - make sure files are matching between signal sources
