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
    # "browser_hardware_compute_1": 0,
    # "browser_hardware_compute_2": 0,
    # "browser_hardware_compute_3": 0,
    # "browser_hardware_compute_4": 0,
    # "browser_hardware_compute_5": 0,
    #
    # "browser_hardware_download_1": 1,
    # "browser_hardware_download_2": 1,
    # "browser_hardware_download_3": 1,
    # "browser_hardware_download_4": 1,
    # "browser_hardware_download_5": 1,
    #
    # "browser_hardware_generic_1": 2,
    # "browser_hardware_generic_2": 2,
    # "browser_hardware_generic_3": 2,
    # "browser_hardware_generic_4": 2,
    # "browser_hardware_generic_5": 2,
    #
    # "browser_hardware_mix_1": 3,
    # "browser_hardware_mix_2": 3,
    # "browser_hardware_mix_3": 3,
    # "browser_hardware_mix_4": 3,
    # "browser_hardware_mix_5": 3,
    #
    # "browser_hardware_streaming_1": 4,
    # "browser_hardware_streaming_2": 4,
    # "browser_hardware_streaming_3": 4,
    # "browser_hardware_streaming_4": 4,
    # "browser_hardware_streaming_5": 4,

    "recon_system_1": 0,
    "recon_system_2": 0,
    "recon_system_3": 0,

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

