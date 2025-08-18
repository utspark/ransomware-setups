from pathlib import Path

import joblib
import numpy as np

from ml_pipelines.timeseries_processing import preproc_transform


def form_lifecycle_sequence(attack_stages: dict, benign=False):
    # TODO benign sequences
    # TODO consider benign states
    #  - (states: list)
    #  - pb-lifecycle/src/classifier.py

    if benign:
        techniques = ["_b_" for _ in attack_stages]

    else:
        techniques = []

        for stage, ttp_choices in attack_stages.items():
            # TODO performance increase when setting replace=True
            ttp = np.random.choice(ttp_choices, size=1)[0]
            techniques.append(ttp)

    # states = np.random.choice(states, size=len(techniques))
    stage_keys = []
    stage_windows = []

    # for state, technique in zip(states, techniques):
    #     stage_keys.append("s" + str(state) + technique)
    #     stage_windows.append(np.random.choice([i for i in range(10, 100, 10)]))

    for technique in techniques:
        stage_keys.append(technique)
        stage_windows.append(np.random.choice([i for i in range(10, 100, 10)]))

    return stage_keys, stage_windows


if __name__ == "__main__":
    cwd = Path.cwd()

    settings_path = "saved_models/multiclass_supervised_windowed_features_decision_tree_settings.json"
    model_settings = joblib.load(settings_path)
    model_settings.model_path = "saved_models/multiclass_supervised_windowed_features_decision_tree.json"
    classifier = joblib.load(model_settings.model_path)

    malware_path = cwd / "pipeline_ints"
    malware_dict = {

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

    malware_list = list(malware_dict.keys())
    malware_list = malware_list[0:4]

    transformed = preproc_transform(model_settings, malware_path, malware_list)

    y_pred_ohe = classifier.predict_proba(transformed)
    label_class = np.argmax(y_pred_ohe, axis=1)
    label_val = y_pred_ohe[np.arange(y_pred_ohe.shape[0]), label_class]




    raise Exception

    attack_stages = {
        "recon": [
            "recon_mount",
            "recon_net",
        ],
        "exfil": [
            "transfer_aws_1t",
            "transfer_aws_8t",
            "transfer_sftp_1t",
            "transfer_sftp_8t",
            "fscan_group",
        ],
        "exec" : [
            "asymm",
            "symm_AES_128t",
            "symm_Salsa20_256t",
            "compress_gzip_1t",
            "compress_zstd_1t",
            "compress_zstd_8t",
            "compress_gzip_8t_0_ints",
        ],

    }

    stage_keys, stage_windows = form_lifecycle_sequence(attack_stages, benign=False)

