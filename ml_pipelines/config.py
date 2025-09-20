from typing import Final

SUBSAMPLE_NETWORK_DATA : Final = 10

SYSCALL_BENIGN_MALWARE_DICT: Final = {
    0: [
        # "recon_system_",
        "recon_mount_",
        "recon_net_",
    ],
    1: [
        "compress_gzip_1t_",
    ],
    2: [
        "compress_gzip_8t_",
    ],
    3: [
        "compress_zstd_1t_",
        "compress_zstd_8t_",
    ],
    4: [
        "transfer_aws_1t_",
        "transfer_aws_8t_",
    ],
    5: [
        "transfer_sftp_1t_",
        "transfer_sftp_8t_",
    ],
    6: [
        "symm_AES_128t_",
        "symm_AES_256t_",
        "symm_Salsa20_128t_",
        "symm_Salsa20_256t_",
    ],
    7: [
        "browser_syscall_compute_",
    ],
    8: [
        "browser_syscall_download_",
        "browser_syscall_mix_",
        "browser_syscall_generic_",
    ],
    9: [
        "browser_syscall_streaming_",
    ],
}

SYSCALL_MALWARE_DICT: Final = {
    0: [
        # "recon_system_",
        "recon_mount_",
        "recon_net_",
    ],
    1: [
        "compress_gzip_1t_",
    ],
    2: [
        "compress_gzip_8t_",
    ],
    3: [
        "compress_zstd_1t_",
        "compress_zstd_8t_",
    ],
    4: [
        "transfer_aws_1t_",
        "transfer_aws_8t_",
    ],
    5: [
        "transfer_sftp_1t_",
        "transfer_sftp_8t_",
    ],
    6: [
        "symm_AES_128t_",
        "symm_AES_256t_",
        "symm_Salsa20_128t_",
        "symm_Salsa20_256t_",
    ],
}

NETWORK_BENIGN_MALWARE_DICT: Final = {
    0: [
        # "recon_system_",
        "recon_mount_",
    ],
    1: [
        "recon_net_",
    ],
    2: [
        "compress_gzip_1t_",
        "compress_gzip_8t_",
        "compress_zstd_1t_",
        "compress_zstd_8t_"
    ],
    3: [
        "transfer_aws_1t_",
        "transfer_aws_8t_",
        "transfer_sftp_1t_",
        "transfer_sftp_8t_"
    ],
    4: [
        "symm_AES_128b_",
        "symm_AES_256b_",
        "symm_Salsa20_128b_",
        "symm_Salsa20_256b_",
    ],
    5: [
        "browser_netcall_compute_",
        "browser_netcall_streaming_",
        "mediaserver_index_",
        "browser_netcall_generic_",
        "browser_netcall_mix_",
        "browser_netcall_download_",
    ],
    6: [
        "mediaserver_browse_",
    ],
}

NETWORK_MALWARE_DICT : Final = {
    0: [
        # "recon_system_",
        "recon_mount_",
    ],
    1: [
        "recon_net_",
    ],
    2: [
        "compress_gzip_1t_",
        "compress_gzip_8t_",
        "compress_zstd_1t_",
        "compress_zstd_8t_"
    ],
    3: [
        "transfer_aws_1t_",
        "transfer_aws_8t_",
        "transfer_sftp_1t_",
        "transfer_sftp_8t_"
    ],
    4: [
        "symm_AES_128b_",
        "symm_AES_256b_",
        "symm_Salsa20_128b_",
        "symm_Salsa20_256b_",
    ],
}

HPC_MALWARE_DICT : Final = {
    0: [
        # "recon_system_",
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
        "transfer_aws_1t_",
        "transfer_aws_8t_",
        "transfer_sftp_1t_",
        "transfer_sftp_8t_"
    ],
    5: [
        "symm_AES_128b_",
        "symm_AES_256_",
        "symm_Salsa20_128b_",
        "symm_Salsa20_256b_",
    ],
}

HPC_BENIGN_MALWARE_DICT : Final = {
    0: [
        # "recon_system_",
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
        "transfer_aws_1t_",
        "transfer_aws_8t_",
        "transfer_sftp_1t_",
        "transfer_sftp_8t_"
    ],
    5: [
        "symm_AES_128b_",
        "symm_AES_256_",
        "symm_Salsa20_128b_",
        "symm_Salsa20_256b_",
    ],
    6: [
        "browser_hardware_compute_",
    ],
    7: [
        "browser_hardware_download_",
        "browser_hardware_generic_",
        "browser_hardware_streaming_",
        "browser_hardware_mix_",
        "filebench_hardware_fileserver_",
        "filebench_hardware_oltp_",
        "filebench_hardware_randomrw_",
        "filebench_hardware_varmail_",
        "filebench_hardware_videoserver_",
    ],
    8: [
        "browse_hardware_",
    ],
    9: [
        "index_hardware_",
    ],
    10: [
        "perf_hardware_deepsjeng_",
    ],
    11: [
        "perf_hardware_gcc_",
    ],
    12: [
        "perf_hardware_leela_",
    ],
}

SYSCALL_MALWARE_CLASS_TRANSLATION: Final = {
    -1: -1,
    0: 0,
    1: 1,
    2: 1,
    3: 1,
    4: 2,
    5: 2,
    6: 3,
}

SYSCALL_BENIGN_MALWARE_CLASS_TRANSLATION: Final = {
    -1: -1,
    0: 0,
    1: 1,
    2: 1,
    3: 1,
    4: 2,
    5: 2,
    6: 3,
    7: -1,
    8: -1,
    9: -1,
}

NETWORK_MALWARE_CLASS_TRANSLATION: Final = {
    -1: -1,
    0: 0,
    1: 0,
    2: 1,
    3: 2,
    4: 3,
}

NETWORK_BENIGN_MALWARE_CLASS_TRANSLATION: Final = {
    -1: -1,
    0: 0,
    1: 0,
    2: 1,
    3: 2,
    4: 3,
    5: -1,
    6: -1,
}

HPC_MALWARE_CLASS_TRANSLATION: Final = {
    -1: -1,
    0: 0,
    1: 0,
    2: 1,
    3: 1,
    4: 2,
    5: 3,
}

HPC_BENIGN_MALWARE_CLASS_TRANSLATION: Final = {
    -1: -1,
    0: 0,
    1: 0,
    2: 1,
    3: 1,
    4: 2,
    5: 3,
    6: -1,
    7: -1,
    8: -1,
    9: -1,
    10: -1,
    11: -1,
    12: -2,
}

BEHAVIOR_FILES: Final = {
    "browser_compute": {
        "syscall": [
            "browser_syscall_compute_1_ints.txt",
            "browser_syscall_compute_5_ints.txt",
        ],
        "network": [
            "browser_netcall_compute_1",
            "browser_netcall_compute_5",
        ],
        "hpc": [
            "browser_hardware_compute_1",
            "browser_hardware_compute_5",
        ],
    },
    "browser_download": {
        "syscall": [
            "browser_syscall_download_1_ints.txt",
            "browser_syscall_download_5_ints.txt",
        ],
        "network": [
            "browser_netcall_download_1",
            "browser_netcall_download_5",
        ],
        "hpc": [
            "browser_hardware_download_1",
            "browser_hardware_download_5",
        ],
    },
    "browser_generic": {
        "syscall": [
            "browser_syscall_generic_1_ints.txt",
            "browser_syscall_generic_5_ints.txt",
        ],
        "network": [
            "browser_netcall_generic_1",
            "browser_netcall_generic_5",
        ],
        "hpc": [
            "browser_hardware_generic_1",
            "browser_hardware_generic_5",
        ],
    },
    "browser_mix": {
        "syscall": [
            "browser_syscall_mix_1_ints.txt",
            "browser_syscall_mix_5_ints.txt",
        ],
        "network": [
            "browser_netcall_mix_1",
            "browser_netcall_mix_5",
        ],
        "hpc": [
            "browser_hardware_mix_1",
            "browser_hardware_mix_5",
        ],
    },
    "browser_streaming": {
        "syscall": [
            "browser_syscall_streaming_1_ints.txt",
            "browser_syscall_streaming_5_ints.txt",
        ],
        "network": [
            "browser_netcall_streaming_1",
            "browser_netcall_streaming_5",
        ],
        "hpc": [
            "browser_hardware_streaming_1",
            "browser_hardware_streaming_5",
        ],
    },
    # "filebench_fileserver": {
    #     "syscall": [
    #         "filebench_syscall_fileserver_1_ints.txt",
    #         "filebench_syscall_fileserver_3_ints.txt",
    #     ],
    #     "network": [
    #         "",
    #         "",
    #     ],
    #     "hpc": [
    #         "filebench_hardware_fileserver_1",
    #         "filebench_hardware_fileserver_3",
    #     ],
    # },
    "filebench_mediaserver_browse": {
        "syscall": [
            "mediaserver_browse_1_ints.txt",
            "mediaserver_browse_5_ints.txt",
        ],
        "network": [
            "mediaserver_browse_1",
            "mediaserver_browse_5",
        ],
        "hpc": [
            "mediaserver_browse_hardware_1",
            "mediaserver_browse_hardware_5",
        ],
    },
    "filebench_mediaserver_index": {
        "syscall": [
            "mediaserver_index_1_ints.txt",
            "mediaserver_index_5_ints.txt",
        ],
        "network": [
            "mediaserver_index_1",
            "mediaserver_index_5",
        ],
        "hpc": [
            "mediaserver_index_hardware_1",
            "mediaserver_index_hardware_5",
        ],
    },
    # "spec_leela": {
    #     "syscall": [
    #         "filebench_syscall_fileserver_1_ints.txt",
    #         "filebench_syscall_fileserver_3_ints.txt",
    #     ],
    #     "network": [
    #         "",
    #         "",
    #     ],
    #     "hpc": [
    #         "filebench_hardware_fileserver_1",
    #         "filebench_hardware_fileserver_3",
    #     ],
    # },

    "recon_mount": {
        "syscall": [
            "recon_mount_1_ints.txt",
            "recon_mount_5_ints.txt",
        ],
        "network": [
            "recon_mount_1",
            "recon_mount_5",
        ],
        "hpc": [
            "recon_mount_1",
            "recon_mount_3",
        ],
    },
    "recon_net": {
        "syscall": [
            "recon_net_1_ints.txt",
            "recon_net_5_ints.txt",
        ],
        "network": [
            "recon_net_1",
            "recon_net_5",
        ],
        "hpc": [
            "recon_net_1",
            "recon_net_3",
        ],
    },
    # "recon_system": {
    #     "syscall": [
    #         "recon_system_1_ints.txt",
    #         "recon_system_5_ints.txt",
    #     ],
    #     "network": [
    #         "recon_system_1",
    #         "recon_system_5",
    #     ],
    #     "hpc": [
    #         "recon_system_1",
    #     ],
    # },

    "compress_gzip_1t": {
        "syscall": [
            "compress_gzip_1t_0_ints.txt",
            "compress_gzip_1t_9_ints.txt",
        ],
        "network": [
            "compress_gzip_1t_0",
            "compress_gzip_1t_9",
        ],
        "hpc": [
            "compress_gzip_1t_0",
            "compress_gzip_1t_7",
        ],
    },
    "compress_gzip_8t": {
        "syscall": [
            "compress_gzip_8t_0_ints.txt",
            "compress_gzip_8t_9_ints.txt",
        ],
        "network": [
            "compress_gzip_8t_0",
            "compress_gzip_8t_9",
        ],
        "hpc": [
            "compress_gzip_8t_0",
            "compress_gzip_8t_7",
        ],
    },
    "compress_zstd_1t": {
        "syscall": [
            "compress_zstd_1t_0_ints.txt",
            "compress_zstd_1t_9_ints.txt",
        ],
        "network": [
            "compress_zstd_1t_0",
            "compress_zstd_1t_9",
        ],
        "hpc": [
            "compress_zstd_1t_0",
            "compress_zstd_1t_7",
        ],
    },
    "compress_zstd_8t": {
        "syscall": [
            "compress_zstd_8t_0_ints.txt",
            "compress_zstd_8t_9_ints.txt",
        ],
        "network": [
            "compress_zstd_8t_0",
            "compress_zstd_8t_9",
        ],
        "hpc": [
            "compress_zstd_8t_0",
            "compress_zstd_8t_7",
        ],
    },
    "transfer_aws_1t": {
        "syscall": [
            "transfer_aws_1t_0_ints.txt",
            "transfer_aws_1t_11_ints.txt",
        ],
        "network": [
            "transfer_aws_1t_0",
            "transfer_aws_1t_14",
        ],
        "hpc": [
            "transfer_aws_1t_0",
            "transfer_aws_1t_5",
        ],
    },
    "transfer_aws_8t": {
        "syscall": [
            "transfer_aws_8t_0_ints.txt",
            "transfer_aws_8t_11_ints.txt",
        ],
        "network": [
            "transfer_aws_8t_0",
            "transfer_aws_8t_14",
        ],
        "hpc": [
            "transfer_aws_8t_0",
            "transfer_aws_8t_5",
        ],
    },
    "transfer_sftp_1t": {
        "syscall": [
            "transfer_sftp_1t_0_ints.txt",
            "transfer_sftp_1t_11_ints.txt",
        ],
        "network": [
            "transfer_sftp_1t_0",
            "transfer_sftp_1t_14",
        ],
        "hpc": [
            "transfer_sftp_1t_0",
            "transfer_sftp_1t_5",
        ],
    },
    "transfer_sftp_8t": {
        "syscall": [
            "transfer_sftp_8t_0_ints.txt",
            "transfer_sftp_8t_11_ints.txt",
        ],
        "network": [
            "transfer_sftp_8t_0",
            "transfer_sftp_8t_14",
        ],
        "hpc": [
            "transfer_sftp_8t_0",
            "transfer_sftp_8t_5",
        ],
    },

    "symm_AES_128t": {
        "syscall": [
            "symm_AES_128t_0_ints.txt",
            "symm_AES_128t_11_ints.txt",
        ],
        "network": [
            "symm_AES_128b_0",
            "symm_AES_128b_3",
        ],
        "hpc": [
            "symm_AES_128b_0",
            "symm_AES_128b_11",
        ],
    },
    "symm_AES_256t": {
        "syscall": [
            "symm_AES_256t_0_ints.txt",
            "symm_AES_256t_11_ints.txt",
        ],
        "network": [
            "symm_AES_256b_0",
            "symm_AES_256b_3",
        ],
        "hpc": [
            "symm_AES_256b_0",
            "symm_AES_256b_11",
        ],
    },
    "symm_Salsa20_128t": {
        "syscall": [
            "symm_Salsa20_128t_0_ints.txt",
            "symm_Salsa20_128t_11_ints.txt",
        ],
        "network": [
            "symm_Salsa20_128b_0",
            "symm_Salsa20_128b_3",
        ],
        "hpc": [
            "symm_Salsa20_128b_0",
            "symm_Salsa20_128b_11",
        ],
    },
    "symm_Salsa20_256t": {
        "syscall": [
            "symm_Salsa20_256t_0_ints.txt",
            "symm_Salsa20_256t_11_ints.txt",
        ],
        "network": [
            "symm_Salsa20_256b_0",
            "symm_Salsa20_256b_3",
        ],
        "hpc": [
            "symm_Salsa20_256b_0",
            "symm_Salsa20_256b_11",
        ],
    },
}


GENERATION_ATTACK_STAGES: Final = {
    "recon": [
        "recon_mount",
        "recon_net",
        # "recon_system",
    ],
    "exfil_1": [
        # "fscan_group",

        "compress_gzip_1t",
        "compress_gzip_8t",
        "compress_zstd_1t",
        "compress_zstd_8t",
    ],
    "exfil_2": [
        "transfer_aws_1t",
        "transfer_aws_8t",
        "transfer_sftp_1t",
        "transfer_sftp_8t",
    ],
    # "exec_1": [
    #     "asymm",
    #
    # ],
    "exec_2": [
        "symm_AES_128t",
        "symm_AES_256t",
        "symm_Salsa20_128t",
        "symm_Salsa20_256t",
    ],
}

GENERATION_BENIGN: Final = [
    "browser_compute",
    "browser_download",
    "browser_generic",
    "browser_mix",
    "browser_streaming",
    "filebench_mediaserver_browse",
    "filebench_mediaserver_index",
]

# HMM_ATTACK_STAGES: Final = {
#     "recon": [
#         "recon_mount",
#         "recon_net",
#     ],
#     "exfil": [
#         "transfer_aws",
#         "transfer_sftp",
#         # "fscan_group",
#     ],
#     "exec": [
#         "asymm",
#         # "symm_AES_128t",
#         # "symm_Salsa20_256t",
#         # "compress_gzip_1t",
#         # "compress_zstd_1t",
#         # "compress_zstd_8t",
#         # "compress_gzip_8t_0_ints",
#     ],
# }

# LABEL_NAMES: Final = [
#         "asymm",
#         "_",
#         "_",
#         "_",
#         "transfer_aws",
#         "_",
#         "recon_mount",
#         "recon_net",
#         "fscan",
# ]


# TTP_DICT: Final = {
#     "recon_mount": [
#         "recon_mount_1_ints.txt",
#         "recon_mount_2_ints.txt",
#         "recon_mount_3_ints.txt",
#         "recon_mount_4_ints.txt",
#         "recon_mount_5_ints.txt",
#     ],
#     "recon_net": [
#         "recon_net_1_ints.txt",
#         "recon_net_2_ints.txt",
#         "recon_net_3_ints.txt",
#         "recon_net_4_ints.txt",
#         "recon_net_5_ints.txt",
#     ],
#     "transfer_aws_1t": [
#         "transfer_aws_1t_0_ints.txt",
#         "transfer_aws_1t_1_ints.txt",
#         "transfer_aws_1t_2_ints.txt",
#         "transfer_aws_1t_3_ints.txt",
#         "transfer_aws_1t_4_ints.txt",
#     ],
#     "asymm": [
#         "asymm_0_ints.txt",
#         "asymm_1_ints.txt",
#         "asymm_2_ints.txt",
#         "asymm_3_ints.txt",
#         "asymm_4_ints.txt",
#     ],
# }

