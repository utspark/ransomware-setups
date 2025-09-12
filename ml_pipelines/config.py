from typing import Final

SUBSAMPLE_NETWORK_DATA : Final = 10

SYSCALL_MALWARE_DICT : Final = {
    "asymm_0_ints.txt": 0,
    "asymm_1_ints.txt": 0,
    "asymm_2_ints.txt": 0,
    "asymm_3_ints.txt": 0,
    "asymm_4_ints.txt": 0,

    "symm_AES_128t_0_ints.txt": 1,
    "symm_AES_128t_1_ints.txt": 1,
    "symm_AES_128t_2_ints.txt": 1,
    "symm_AES_128t_3_ints.txt": 1,
    "symm_AES_128t_4_ints.txt": 1,

    "symm_Salsa20_256t_0_ints.txt": 1,
    "symm_Salsa20_256t_1_ints.txt": 1,
    "symm_Salsa20_256t_2_ints.txt": 1,
    "symm_Salsa20_256t_3_ints.txt": 1,
    "symm_Salsa20_256t_4_ints.txt": 1,

    "compress_gzip_1t_0_ints.txt": 2,
    "compress_gzip_1t_1_ints.txt": 2,
    "compress_gzip_1t_2_ints.txt": 2,
    "compress_gzip_1t_3_ints.txt": 2,
    "compress_gzip_1t_4_ints.txt": 2,

    "compress_zstd_1t_0_ints.txt": 2,
    "compress_zstd_1t_1_ints.txt": 2,
    "compress_zstd_1t_2_ints.txt": 2,
    "compress_zstd_1t_3_ints.txt": 2,
    "compress_zstd_1t_4_ints.txt": 2,

    "compress_zstd_8t_0_ints.txt": 2,
    "compress_zstd_8t_1_ints.txt": 2,
    "compress_zstd_8t_2_ints.txt": 2,
    "compress_zstd_8t_3_ints.txt": 2,
    "compress_zstd_8t_4_ints.txt": 2,

    "compress_gzip_8t_0_ints.txt": 3,
    "compress_gzip_8t_1_ints.txt": 3,
    "compress_gzip_8t_2_ints.txt": 3,
    "compress_gzip_8t_3_ints.txt": 3,
    "compress_gzip_8t_4_ints.txt": 3,

    # "compress_zstd_1t_0_ints.txt": 4,
    # "compress_zstd_1t_1_ints.txt": 4,
    # "compress_zstd_1t_2_ints.txt": 4,
    # "compress_zstd_1t_3_ints.txt": 4,
    # "compress_zstd_1t_4_ints.txt": 4,

    # "compress_zstd_8t_0_ints.txt": 5,
    # "compress_zstd_8t_1_ints.txt": 5,
    # "compress_zstd_8t_2_ints.txt": 5,
    # "compress_zstd_8t_3_ints.txt": 5,
    # "compress_zstd_8t_4_ints.txt": 5,

    # "compress_zstd_8t_0_ints.txt": 5,
    # "compress_zstd_8t_1_ints.txt": 5,
    # "compress_zstd_8t_2_ints.txt": 5,
    # "compress_zstd_8t_3_ints.txt": 5,
    # "compress_zstd_8t_4_ints.txt": 5,

    "transfer_aws_1t_0_ints.txt": 4,
    "transfer_aws_1t_1_ints.txt": 4,
    "transfer_aws_1t_2_ints.txt": 4,
    "transfer_aws_1t_3_ints.txt": 4,
    "transfer_aws_1t_4_ints.txt": 4,

    "transfer_aws_8t_0_ints.txt": 4,
    "transfer_aws_8t_1_ints.txt": 4,
    "transfer_aws_8t_2_ints.txt": 4,
    "transfer_aws_8t_3_ints.txt": 4,
    "transfer_aws_8t_4_ints.txt": 4,

    "transfer_sftp_1t_0_ints.txt": 5,
    "transfer_sftp_1t_1_ints.txt": 5,
    "transfer_sftp_1t_2_ints.txt": 5,
    "transfer_sftp_1t_3_ints.txt": 5,
    "transfer_sftp_1t_4_ints.txt": 5,

    "transfer_sftp_8t_0_ints.txt": 5,
    "transfer_sftp_8t_1_ints.txt": 5,
    "transfer_sftp_8t_2_ints.txt": 5,
    "transfer_sftp_8t_3_ints.txt": 5,
    "transfer_sftp_8t_4_ints.txt": 5,

    "recon_mount_1_ints.txt": 6,
    "recon_mount_2_ints.txt": 6,
    "recon_mount_3_ints.txt": 6,
    "recon_mount_4_ints.txt": 6,
    "recon_mount_5_ints.txt": 6,

    "recon_net_1_ints.txt": 7,
    "recon_net_2_ints.txt": 7,
    "recon_net_3_ints.txt": 7,
    "recon_net_4_ints.txt": 7,
    "recon_net_5_ints.txt": 7,

    # "recon_system_1_ints.txt": 8,
    # "recon_system_2_ints.txt": 8,
    # "recon_system_3_ints.txt": 8,
    # "recon_system_4_ints.txt": 8,
    # "recon_system_5_ints.txt": 8,

    "fscan_group_1.txt": 8,
    "fscan_group_2.txt": 8,
    "fscan_group_3.txt": 8,
    "fscan_group_4.txt": 8,
    "fscan_group_5.txt": 8,
}

NETWORK_MALWARE_DICT : Final = {
    "exec_AES_128_O_default_1": 0,
    "exec_AES_128_O_none_1": 0,
    "exec_AES_128_WA_default_1": 0,
    "exec_AES_128_WA_none_1": 0,

    "exec_AES_256_O_default_1": 0,
    "exec_AES_256_O_none_1": 0,
    "exec_AES_256_WA_default_1": 0,
    "exec_AES_256_WA_none_1": 0,

    "exec_Salsa20_128_O_default_1": 0,
    "exec_Salsa20_128_O_none_1": 0,
    "exec_Salsa20_128_WA_default_1": 0,
    "exec_Salsa20_128_WA_none_1": 0,

    "exec_Salsa20_256_O_default_1": 0,
    "exec_Salsa20_256_O_none_1": 0,
    "exec_Salsa20_256_WA_default_1": 0,
    "exec_Salsa20_256_WA_none_1": 0,

    "exfil_gzip_1_aws_1": 1,
    "exfil_gzip_1_aws_2": 1,
    "exfil_gzip_1_aws_3": 1,
    "exfil_gzip_1_aws_4": 1,
    "exfil_gzip_1_aws_5": 1,

    "exfil_gzip_8_aws_1": 1,
    "exfil_gzip_8_aws_2": 1,
    "exfil_gzip_8_aws_3": 1,
    "exfil_gzip_8_aws_4": 1,
    "exfil_gzip_8_aws_5": 1,

    "exfil_gzip_1_sftp_1": 2,
    "exfil_gzip_1_sftp_2": 2,
    "exfil_gzip_1_sftp_3": 2,
    "exfil_gzip_1_sftp_4": 2,
    "exfil_gzip_1_sftp_5": 2,

    "exfil_gzip_8_sftp_1": 2,
    "exfil_gzip_8_sftp_2": 2,
    "exfil_gzip_8_sftp_3": 2,
    "exfil_gzip_8_sftp_4": 2,
    "exfil_gzip_8_sftp_5": 2,

    "exfil_none_1_aws_1": 3,
    "exfil_none_1_aws_2": 3,
    "exfil_none_1_aws_3": 3,
    "exfil_none_1_aws_4": 3,
    "exfil_none_1_aws_5": 3,

    "exfil_none_8_aws_1": 3,
    "exfil_none_8_aws_2": 3,
    "exfil_none_8_aws_3": 3,
    "exfil_none_8_aws_4": 3,
    "exfil_none_8_aws_5": 3,

    "exfil_none_1_sftp_1": 4,
    "exfil_none_1_sftp_2": 4,
    "exfil_none_1_sftp_3": 4,
    "exfil_none_1_sftp_4": 4,
    "exfil_none_1_sftp_5": 4,

    "exfil_none_8_sftp_1": 4,
    "exfil_none_8_sftp_2": 4,
    "exfil_none_8_sftp_3": 4,
    "exfil_none_8_sftp_4": 4,
    "exfil_none_8_sftp_5": 4,

    # "exfil_zstd_1_aws_1": 5,
    # "exfil_zstd_1_aws_2": 5,
    # "exfil_zstd_1_aws_3": 5,
    # "exfil_zstd_1_aws_4": 5,
    # "exfil_zstd_1_aws_5": 5,
    #
    # "exfil_zstd_8_aws_1": 5,
    # "exfil_zstd_8_aws_2": 5,
    # "exfil_zstd_8_aws_3": 5,
    # "exfil_zstd_8_aws_4": 5,
    # "exfil_zstd_8_aws_5": 5,

    "exfil_zstd_1_sftp_1": 6,
    "exfil_zstd_1_sftp_2": 6,
    "exfil_zstd_1_sftp_3": 6,
    "exfil_zstd_1_sftp_4": 6,
    "exfil_zstd_1_sftp_5": 6,

    "exfil_zstd_8_sftp_1": 6,
    "exfil_zstd_8_sftp_2": 6,
    "exfil_zstd_8_sftp_3": 6,
    "exfil_zstd_8_sftp_4": 6,
    "exfil_zstd_8_sftp_5": 6,


    # log entries are so time-sparse that nothing appears in a time-window
    # "recon_mount_1": 3,
    # "recon_mount_2": 3,
    # "recon_mount_3": 3,
    # "recon_mount_4": 3,
    # "recon_mount_5": 3,

    "recon_net_1": 4,
    "recon_net_2": 4,
    "recon_net_3": 4,
    "recon_net_4": 4,
    "recon_net_5": 4,

    # "recon_system_1": 5,
    # "recon_system_2": 5,
    # "recon_system_3": 5,
    # "recon_system_4": 5,
    # "recon_system_5": 5,

}

HPC_MALWARE_DICT : Final = {
    "recon_system_1": 0,
    "recon_system_2": 0,
    "recon_system_3": 0,

    "recon_mount_1": 1,
    "recon_mount_2": 1,
    "recon_mount_3": 1,

    "recon_net_1": 0,
    "recon_net_2": 0,
    "recon_net_3": 0,

    "compress_gzip_1t_0": 2,
    "compress_gzip_1t_1": 2,
    "compress_gzip_1t_2": 2,
    "compress_gzip_1t_3": 2,
    "compress_gzip_1t_4": 2,
    "compress_gzip_1t_5": 2,

    "compress_gzip_8t_0": 2,
    "compress_gzip_8t_1": 2,
    "compress_gzip_8t_2": 2,
    "compress_gzip_8t_3": 2,
    "compress_gzip_8t_4": 2,
    "compress_gzip_8t_5": 2,

    "compress_zstd_1t_0": 3,
    "compress_zstd_1t_1": 3,
    "compress_zstd_1t_2": 3,
    "compress_zstd_1t_3": 3,
    "compress_zstd_1t_4": 3,
    "compress_zstd_1t_5": 3,

    "compress_zstd_8t_0": 3,
    "compress_zstd_8t_1": 3,
    "compress_zstd_8t_2": 3,
    "compress_zstd_8t_3": 3,
    "compress_zstd_8t_4": 3,
    "compress_zstd_8t_5": 3,

    "symm_AES_128b_0": 4,
    "symm_AES_128b_1": 4,
    "symm_AES_128b_2": 4,
    "symm_AES_128b_3": 4,
    "symm_AES_128b_4": 4,

    "symm_AES_256b_0": 4,
    "symm_AES_256b_1": 4,
    "symm_AES_256b_2": 4,
    "symm_AES_256b_3": 4,
    "symm_AES_256b_4": 4,

    "symm_Salsa20_128b_0": 4,
    "symm_Salsa20_128b_1": 4,
    "symm_Salsa20_128b_2": 4,
    "symm_Salsa20_128b_3": 4,
    "symm_Salsa20_128b_4": 4,

    "symm_Salsa20_256b_0": 4,
    "symm_Salsa20_256b_1": 4,
    "symm_Salsa20_256b_2": 4,
    "symm_Salsa20_256b_3": 4,
    "symm_Salsa20_256b_4": 4,
}

HPC_BENIGN_MALWARE_DICT : Final = {
    "browser_hardware_compute_1": 0,
    "browser_hardware_compute_2": 0,
    "browser_hardware_compute_3": 0,
    "browser_hardware_compute_4": 0,
    "browser_hardware_compute_5": 0,

    "browser_hardware_download_1": 1,
    "browser_hardware_download_2": 1,
    "browser_hardware_download_3": 1,
    "browser_hardware_download_4": 1,
    "browser_hardware_download_5": 1,

    "browser_hardware_generic_1": 1,
    "browser_hardware_generic_2": 1,
    "browser_hardware_generic_3": 1,
    "browser_hardware_generic_4": 1,
    "browser_hardware_generic_5": 1,

    "browser_hardware_streaming_1": 1,
    "browser_hardware_streaming_2": 1,
    "browser_hardware_streaming_3": 1,
    "browser_hardware_streaming_4": 1,
    "browser_hardware_streaming_5": 1,

    "browser_hardware_mix_1": 1,
    "browser_hardware_mix_2": 1,
    "browser_hardware_mix_3": 1,
    "browser_hardware_mix_4": 1,
    "browser_hardware_mix_5": 1,

    "filebench_hardware_fileserver_1": 1,
    "filebench_hardware_fileserver_2": 1,
    "filebench_hardware_fileserver_3": 1,

    "filebench_hardware_oltp_1": 1,
    "filebench_hardware_oltp_2": 1,
    "filebench_hardware_oltp_3": 1,

    "filebench_hardware_randomrw_1": 1,
    "filebench_hardware_randomrw_2": 1,
    "filebench_hardware_randomrw_3": 1,

    "filebench_hardware_varmail_1": 1,
    "filebench_hardware_varmail_2": 1,
    "filebench_hardware_varmail_3": 1,

    "filebench_hardware_videoserver_1": 1,
    "filebench_hardware_videoserver_2": 1,
    "filebench_hardware_videoserver_3": 1,

    "browse_hardware_1": 2,
    "browse_hardware_2": 2,
    "browse_hardware_3": 2,
    "browse_hardware_4": 2,
    "browse_hardware_5": 2,

    "index_hardware_1": 3,
    "index_hardware_2": 3,
    "index_hardware_3": 3,
    "index_hardware_4": 3,
    "index_hardware_5": 3,

    "perf_hardware_deepsjeng_1": 4,
    "perf_hardware_deepsjeng_2": 4,
    "perf_hardware_deepsjeng_3": 4,

    "perf_hardware_gcc_1": 5,
    "perf_hardware_gcc_2": 5,
    "perf_hardware_gcc_3": 5,

    "perf_hardware_leela_1": 6,
    "perf_hardware_leela_2": 6,
    "perf_hardware_leela_3": 6,

    "recon_system_1": 7,
    "recon_system_2": 7,
    "recon_system_3": 7,

    "recon_mount_1": 8,
    "recon_mount_2": 8,
    "recon_mount_3": 8,

    "recon_net_1": 7,
    "recon_net_2": 7,
    "recon_net_3": 7,

    "compress_gzip_1t_0": 9,
    "compress_gzip_1t_1": 9,
    "compress_gzip_1t_2": 9,
    "compress_gzip_1t_3": 9,
    "compress_gzip_1t_4": 9,
    "compress_gzip_1t_5": 9,

    "compress_gzip_8t_0": 9,
    "compress_gzip_8t_1": 9,
    "compress_gzip_8t_2": 9,
    "compress_gzip_8t_3": 9,
    "compress_gzip_8t_4": 9,
    "compress_gzip_8t_5": 9,

    "compress_zstd_1t_0": 10,
    "compress_zstd_1t_1": 10,
    "compress_zstd_1t_2": 10,
    "compress_zstd_1t_3": 10,
    "compress_zstd_1t_4": 10,
    "compress_zstd_1t_5": 10,

    "compress_zstd_8t_0": 10,
    "compress_zstd_8t_1": 10,
    "compress_zstd_8t_2": 10,
    "compress_zstd_8t_3": 10,
    "compress_zstd_8t_4": 10,
    "compress_zstd_8t_5": 10,

    "symm_AES_128b_0": 11,
    "symm_AES_128b_1": 11,
    "symm_AES_128b_2": 11,
    "symm_AES_128b_3": 11,
    "symm_AES_128b_4": 11,

    "symm_AES_256b_0": 11,
    "symm_AES_256b_1": 11,
    "symm_AES_256b_2": 11,
    "symm_AES_256b_3": 11,
    "symm_AES_256b_4": 11,

    "symm_Salsa20_128b_0": 11,
    "symm_Salsa20_128b_1": 11,
    "symm_Salsa20_128b_2": 11,
    "symm_Salsa20_128b_3": 11,
    "symm_Salsa20_128b_4": 11,

    "symm_Salsa20_256b_0": 11,
    "symm_Salsa20_256b_1": 11,
    "symm_Salsa20_256b_2": 11,
    "symm_Salsa20_256b_3": 11,
    "symm_Salsa20_256b_4": 11,
}

HPC_MALWARE_DICT_2 : Final = {
    0: [
        "recon_system_",
        "recon_net_",
    ],
    1: [
        "recon_mount_",
    ],
    2: [
        "compress_gzip_1t_",
        "compress_gzip_8t_",
    ],
    3: [
        "compress_zstd_1t_",
        "compress_zstd_8t_",
    ],
    4: [
        "symm_AES_128b_",
        "symm_AES_256_",
        "symm_Salsa20_128b_",
        "symm_Salsa20_256b_",
    ],
}


HPC_MALWARE_CLASS_TRANSLATION: Final = {
    -1: -1,
    0: 0,
    1: 0,
    2: 1,
    3: 1,
    4: 2,
}

HPC_BENIGN_MALWARE_CLASS_TRANSLATION: Final = {
    -1: -1,
    0: -1,
    1: -1,
    2: -1,
    3: -1,
    4: -1,
    5: -1,
    6: -1,
    7: 0,
    8: 0,
    9: 1,
    10: 1,
    11: 2,
}

TTP_DICT: Final = {
    "recon_mount": [
        "recon_mount_1_ints.txt",
        "recon_mount_2_ints.txt",
        "recon_mount_3_ints.txt",
        "recon_mount_4_ints.txt",
        "recon_mount_5_ints.txt",
    ],
    "recon_net": [
        "recon_net_1_ints.txt",
        "recon_net_2_ints.txt",
        "recon_net_3_ints.txt",
        "recon_net_4_ints.txt",
        "recon_net_5_ints.txt",
    ],
    "transfer_aws_1t": [
        "transfer_aws_1t_0_ints.txt",
        "transfer_aws_1t_1_ints.txt",
        "transfer_aws_1t_2_ints.txt",
        "transfer_aws_1t_3_ints.txt",
        "transfer_aws_1t_4_ints.txt",
    ],
    "asymm": [
        "asymm_0_ints.txt",
        "asymm_1_ints.txt",
        "asymm_2_ints.txt",
        "asymm_3_ints.txt",
        "asymm_4_ints.txt",
    ],
}

GENERATION_ATTACK_STAGES: Final = {
    "recon": [
        "recon_mount",
        "recon_net",
    ],
    "exfil": [
        "transfer_aws_1t",
        # "transfer_aws_8t",
        # "transfer_sftp_1t",
        # "transfer_sftp_8t",
        # "fscan_group",
    ],
    "exec": [
        "asymm",
        # "symm_AES_128t",
        # "symm_Salsa20_256t",
        # "compress_gzip_1t",
        # "compress_zstd_1t",
        # "compress_zstd_8t",
        # "compress_gzip_8t_0_ints",
    ],
}

HMM_ATTACK_STAGES: Final = {
    "recon": [
        "recon_mount",
        "recon_net",
    ],
    "exfil": [
        "transfer_aws",
        "transfer_sftp",
        # "fscan_group",
    ],
    "exec": [
        "asymm",
        # "symm_AES_128t",
        # "symm_Salsa20_256t",
        # "compress_gzip_1t",
        # "compress_zstd_1t",
        # "compress_zstd_8t",
        # "compress_gzip_8t_0_ints",
    ],
}

LABEL_NAMES: Final = [
        "asymm",
        "_",
        "_",
        "_",
        "transfer_aws",
        "_",
        "recon_mount",
        "recon_net",
        "fscan",
    ]

