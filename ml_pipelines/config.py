from typing import Final

MALWARE_DICT : Final = {
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

