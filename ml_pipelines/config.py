from typing import Final

SUBSAMPLE_NETWORK_DATA : Final = 10

SYSCALL_BENIGN_MALWARE_DICT: Final = {
    0: [
        "recon_system_",
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
        "recon_system_",
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
        "recon_system_",
    ],
    1: [
        "recon_mount_",
    ],
    2: [
        "recon_net_",
    ],
    3: [
        "exfil_gzip_1_aws_",
        "exfil_gzip_1_sftp_",
        "exfil_gzip_8_aws_",
        "exfil_gzip_8_sftp_"

        "exfil_zstd_1_aws_",
        "exfil_zstd_1_sftp_",
        "exfil_zstd_8_aws_",
        "exfil_zstd_8_sftp_"

        "exfil_none_1_aws_",
        "exfil_none_1_sftp_",
        "exfil_none_8_aws_",
        "exfil_none_8_sftp_",
    ],
    4: [
        "exec_AES_128_O_default_",
        "exec_AES_128_O_none_",
        "exec_AES_128_WA_default_",
        "exec_AES_128_WA_none_",

        "exec_AES_256_O_default_",
        "exec_AES_256_O_none_",
        "exec_AES_256_WA_default_",
        "exec_AES_256_WA_none_",

        "exec_Salsa20_128_O_default_",
        "exec_Salsa20_128_O_none_",
        "exec_Salsa20_128_WA_default_",
        "exec_Salsa20_128_WA_none_",

        "exec_Salsa20_256_O_default_",
        "exec_Salsa20_256_O_none_",
        "exec_Salsa20_256_WA_default_",
        "exec_Salsa20_256_WA_none_",
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
        "recon_system_",
    ],
    1: [
        "recon_mount_",
    ],
    2: [
        "recon_net_",
    ],
    3: [
        "exfil_gzip_1_aws_",
        "exfil_gzip_1_sftp_",
        "exfil_gzip_8_aws_",
        "exfil_gzip_8_sftp_"
        
        "exfil_zstd_1_aws_",
        "exfil_zstd_1_sftp_",
        "exfil_zstd_8_aws_",
        "exfil_zstd_8_sftp_"
        
        "exfil_none_1_aws_",
        "exfil_none_1_sftp_",
        "exfil_none_8_aws_",
        "exfil_none_8_sftp_",
    ],

    4: [
        "exec_AES_128_O_default_",
        "exec_AES_128_O_none_",
        "exec_AES_128_WA_default_",
        "exec_AES_128_WA_none_",

        "exec_AES_256_O_default_",
        "exec_AES_256_O_none_",
        "exec_AES_256_WA_default_",
        "exec_AES_256_WA_none_",

        "exec_Salsa20_128_O_default_",
        "exec_Salsa20_128_O_none_",
        "exec_Salsa20_128_WA_default_",
        "exec_Salsa20_128_WA_none_",

        "exec_Salsa20_256_O_default_",
        "exec_Salsa20_256_O_none_",
        "exec_Salsa20_256_WA_default_",
        "exec_Salsa20_256_WA_none_",
    ],
}

HPC_MALWARE_DICT : Final = {
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

HPC_BENIGN_MALWARE_DICT : Final = {
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
    5: [
        "browser_hardware_compute_",
    ],
    6: [
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
    7: [
        "browse_hardware_",
    ],
    8: [
        "index_hardware_",
    ],
    9: [
        "perf_hardware_deepsjeng_",
    ],
    10: [
        "perf_hardware_gcc_",
    ],
    11: [
        "perf_hardware_leela_",
    ],
}

SYSCALL_BENIGN_MALWARE_CLASS_TRANSLATION: Final = {
    -1: -1,
    0: 0,
    1: 1,
    2: 1,
    3: 1,
    4: 1,
    5: 1,
    6: 2,
}

SYSCALL_MALWARE_CLASS_TRANSLATION: Final = {
    -1: -1,
    0: 0,
    1: 1,
    2: 1,
    3: 1,
    4: 1,
    5: 1,
    6: 2,
}

NETWORK_MALWARE_CLASS_TRANSLATION: Final = {
    -1: -1,
    0: 0,
    1: 0,
    2: 0,
    3: 1,
    4: 2,
}

NETWORK_BENIGN_MALWARE_CLASS_TRANSLATION: Final = {
    -1: -1,
    0: 0,
    1: 0,
    2: 0,
    3: 1,
    4: 2,
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
}

HPC_BENIGN_MALWARE_CLASS_TRANSLATION: Final = {
    -1: -1,
    0: 0,
    1: 0,
    2: 1,
    3: 1,
    4: 2,
    5: -1,
    6: -1,
    7: -1,
    8: -1,
    9: -1,
    10: -1,
    11: -1,
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

