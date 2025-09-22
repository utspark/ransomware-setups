from pathlib import Path

import numpy as np
import joblib
from sklearn.metrics import roc_curve, auc

import ml_pipelines
from ml_pipelines import global_detector
import cross_layer_driver as cld
import random

from tqdm import tqdm

import matplotlib
matplotlib.use("Qt5Agg")
import matplotlib.pyplot as plt
plt.ion()


def trace_len_plot(attack_stages_dict: dict, feature_frames_dict: dict, time_choices: list):


    gd = global_detector.LifecycleDetector(
        cwd / "../data/models/syscall_clf.joblib",
        cwd / "../data/models/network_clf.joblib",
        cwd / "../data/models/hpc_clf.joblib",
        lifecycle_awareness=True,
        stage_filter=False,
        density=False,
        propagation=False,
        memory=False,
    )

    length_check = 10
    length_samples = 15
    benign_stages = ml_pipelines.config.GENERATION_BENIGN
    benign_scores = []
    benign_times = []
    for i in range(1, length_check):
        for j in range(length_samples):
            techniques = [random.choice(benign_stages) for _ in range(i)]
            stage_lens = [(technique, random.choice(time_choices)) for technique in techniques]

            attack_X = cld.build_cross_layer_X(feature_frames_dict, stage_lens, window_size_time, window_stride_time, rng)
            cross_layer_X = cld.cross_layer_concatenate(attack_X)

            proba = gd.score_cross_layer(cross_layer_X)
            benign_scores.append(proba)
            benign_times.append(np.sum([item[1] for item in stage_lens]))

    start = 1.5  # 0.5
    stop = 20
    step = 0.2
    time_choices = np.arange(start, stop + step / 2, step, dtype=float).tolist()
    malware_scores = []
    malware_times = []
    for _ in range(length_check * length_samples):
        techniques = [random.choice(ttp_choices) for _, ttp_choices in attack_stages_dict.items()]
        stage_lens = [(technique, random.choice(time_choices)) for technique in techniques]

        attack_X = cld.build_cross_layer_X(feature_frames_dict, stage_lens, window_size_time, window_stride_time, rng)
        cross_layer_X = cld.cross_layer_concatenate(attack_X)

        proba = gd.score_cross_layer(cross_layer_X)
        malware_scores.append(proba)
        malware_times.append(np.sum([item[1] for item in stage_lens]))

    fig, ax = plt.subplots(figsize=(6, 4))
    sc = ax.scatter(benign_times, benign_scores, color="blue", alpha=0.2, edgecolors='none', label="benign")
    sc = ax.scatter(malware_times, malware_scores, color="red", alpha=0.2, edgecolors='none', label="ransomware")

    ax.legend(loc="best")
    ax.set_xlabel("Trace Length (seconds)")
    ax.set_ylabel("Threat Score")
    ax.grid(True, alpha=0.5)
    fig.tight_layout()
    plt.show(block=True)

    return


def model_curves_plot(attack_stages_dict: dict, feature_frames_dict: dict, time_choices: list):
    combos = [((i >> 2) & 1, (i >> 1) & 1, i & 1) for i in range(8)]
    model_curves = []

    model_labels = [
        "LA-***",
        "LA-**D",
        "LA-*P*",
        "LA-*PD",
        "LA-M**",
        "LA-M*D",
        "LA-MP*",
        "LA-MPD",
    ]

    for i in range(8):

        la_components = {
            "density": True if combos[i][0] else False,
            "propagation": True if combos[i][1] else False,
            "memory": True if combos[i][2] else False,
        }

        gd = global_detector.LifecycleDetector(
            **model_paths,
            lifecycle_awareness=True,
            stage_filter=False,
            **la_components
        )

        n_samples = 50
        benign_stages = ml_pipelines.config.GENERATION_BENIGN
        benign_scores = []
        for _ in range(n_samples):
            techniques = [random.choice(benign_stages) for _ in range(len(attack_stages_dict))]
            stage_lens = [(technique, random.choice(time_choices)) for technique in techniques]

            attack_X = cld.build_cross_layer_X(feature_frames_dict, stage_lens, window_size_time, window_stride_time, rng)
            cross_layer_X = cld.cross_layer_concatenate(attack_X)

            proba = gd.score_cross_layer(cross_layer_X)
            benign_scores.append(proba)

        malware_scores = []
        for _ in range(n_samples):
            techniques = [random.choice(ttp_choices) for _, ttp_choices in attack_stages_dict.items()]
            stage_lens = [(technique, random.choice(time_choices)) for technique in techniques]

            attack_X = cld.build_cross_layer_X(feature_frames_dict, stage_lens, window_size_time, window_stride_time, rng)
            cross_layer_X = cld.cross_layer_concatenate(attack_X)

            proba = gd.score_cross_layer(cross_layer_X)
            malware_scores.append(proba)

        y_scores = malware_scores + benign_scores
        y_true = np.zeros(len(y_scores))
        y_true[:len(malware_scores)] = 1

        fpr, tpr, thresholds = roc_curve(y_true, y_scores)
        roc_auc = auc(fpr, tpr)

        model_curves.append((fpr, tpr, roc_auc))

    plt.figure(figsize=(6, 4))
    for i in range(8):
        fpr, tpr, roc_auc = model_curves[i]
        plt.plot(fpr, tpr, lw=2, label=f'{model_labels[i]}: {roc_auc:.3f}')

    plt.plot([0, 1], [0, 1], lw=1, linestyle='--', label='Random guess')
    plt.xlim([-0.01, 1.0])
    plt.ylim([0.0, 1.05])
    plt.xlabel('False Positive Rate')
    plt.ylabel('True Positive Rate')
    plt.legend(loc="lower right", prop={'family': 'monospace'})
    plt.tight_layout()
    plt.grid()
    plt.show(block=True)

    return


def evade_density_plot(attack_stages_dict: dict, feature_frames_dict: dict, time_choices: list):
    model_curves = []

    model_labels = [
        "**-**D",
        "**-*PD",
        "LA-***",
        "LA-MP*",
        "LA-**D",
        "LA-MPD",
    ]

    la_components = [
        {
            "lifecycle_awareness": False,
            "density": True,
            "propagation": False,
            "memory": False,
        },
        {
            "lifecycle_awareness": False,
            "density": True,
            "propagation": True,
            "memory": False,
        },
        {
            "lifecycle_awareness": True,
            "density": False,
            "propagation": False,
            "memory": False,
        },
        {
            "lifecycle_awareness": True,
            "density": False,
            "propagation": True,
            "memory": True,
        },
        {
            "lifecycle_awareness": True,
            "density": True,
            "propagation": False,
            "memory": False,
        },
        {
            "lifecycle_awareness": True,
            "density": True,
            "propagation": True,
            "memory": True,
        },
    ]

    n_samples = 50
    benign_stages = ml_pipelines.config.GENERATION_BENIGN



    b_stage_len_list = []
    for _ in range(n_samples):
        techniques = [random.choice(benign_stages) for _ in range(len(attack_stages_dict))]
        stage_lens = [(technique, random.choice(time_choices)) for technique in techniques]

        for _ in range(10):
            b_techniques = [random.choice(benign_stages) for _ in range(len(attack_stages_dict) + 1)]
            b_stage_lens = [(technique, random.choice(time_choices)) for technique in b_techniques]
            stage_lens.extend(b_stage_lens)

        b_stage_len_list.append(stage_lens)

    m_stage_len_list = []
    for _ in range(n_samples):
        techniques = [random.choice(ttp_choices) for _, ttp_choices in attack_stages_dict.items()]
        stage_lens = [(technique, time_choices[0]) for technique in techniques]

        for _ in range(10):
            b_techniques = [random.choice(benign_stages) for _ in range(len(attack_stages_dict) + 1)]
            b_stage_lens = [(technique, random.choice(time_choices)) for technique in b_techniques]
            stage_lens.extend(b_stage_lens)

        m_stage_len_list.append(stage_lens)

    for i in tqdm(range(len(la_components))):

        gd = global_detector.LifecycleDetector(
            **model_paths,
            stage_filter=False,
            **la_components[i]
        )

        benign_scores = []
        for j in range(n_samples):
            stage_lens = b_stage_len_list[j]
            attack_X = cld.build_cross_layer_X(feature_frames_dict, stage_lens, window_size_time, window_stride_time,
                                               rng)
            cross_layer_X = cld.cross_layer_concatenate(attack_X)

            proba = gd.score_cross_layer(cross_layer_X)
            benign_scores.append(proba)

        malware_scores = []
        for j in range(n_samples):
            stage_lens = m_stage_len_list[j]
            attack_X = cld.build_cross_layer_X(feature_frames_dict, stage_lens, window_size_time, window_stride_time,
                                               rng)
            cross_layer_X = cld.cross_layer_concatenate(attack_X)

            proba = gd.score_cross_layer(cross_layer_X)
            malware_scores.append(proba)

        y_scores = malware_scores + benign_scores
        y_true = np.zeros(len(y_scores))
        y_true[:len(malware_scores)] = 1

        fpr, tpr, thresholds = roc_curve(y_true, y_scores)
        roc_auc = auc(fpr, tpr)

        model_curves.append((fpr, tpr, roc_auc))

    plt.figure(figsize=(6, 4))
    for i in range(len(la_components)):
        fpr, tpr, roc_auc = model_curves[i]
        plt.plot(fpr, tpr, lw=2, label=f'{model_labels[i]}: {roc_auc:.3f}')

    plt.plot([0, 1], [0, 1], lw=1, linestyle='--', label='Random guess')
    plt.xlim([-0.01, 1.0])
    plt.ylim([0.0, 1.05])
    plt.xlabel('False Positive Rate')
    plt.ylabel('True Positive Rate')
    plt.legend(loc="lower right", prop={'family': 'monospace'})
    plt.tight_layout()
    plt.grid()
    plt.show(block=True)


def signal_sample_plot(attack_stages_dict: dict, feature_frames_dict: dict, time_choices: list):
    combos = [((i >> 2) & 1, (i >> 1) & 1, i & 1) for i in range(1, 8)]
    model_curves = []

    model_labels = [
        "***_***_sys",
        "***_net_***",
        "***_net_sys",
        "hpc_***_***",
        "hpc_***_sys",
        "hpc_net_***",
        "hpc_net_sys",
    ]

    gd = global_detector.LifecycleDetector(
        cwd / "../data/models/syscall_clf.joblib",
        cwd / "../data/models/network_clf.joblib",
        cwd / "../data/models/hpc_clf.joblib",
        lifecycle_awareness=True,
        stage_filter=False,
        density=False,
        propagation=False,
        memory=False,
    )

    n_samples = 50
    benign_stages = ml_pipelines.config.GENERATION_BENIGN

    b_stage_len_list = []
    for _ in range(n_samples):
        techniques = [random.choice(benign_stages) for _ in range(len(attack_stages_dict))]
        stage_lens = [(technique, random.choice(time_choices)) for technique in techniques]
        b_stage_len_list.append(stage_lens)

    m_stage_len_list = []
    for _ in range(n_samples):
        techniques = [random.choice(ttp_choices) for _, ttp_choices in attack_stages_dict.items()]
        stage_lens = [(technique, time_choices[0]) for technique in techniques]
        m_stage_len_list.append(stage_lens)

    for i in range(7):

        benign_scores = []
        for j in range(n_samples):
            stage_lens = b_stage_len_list[j]

            attack_X = cld.build_cross_layer_X(feature_frames_dict, stage_lens, window_size_time, window_stride_time, rng)
            cross_layer_X = cld.cross_layer_concatenate(attack_X)

            signal_select = combos[i]
            for k, selection in enumerate(signal_select):
                if selection == 0:
                    cross_layer_X[k][:] = -1

            proba = gd.score_cross_layer(cross_layer_X)
            benign_scores.append(proba)

        malware_scores = []
        for j in range(n_samples):
            stage_lens = m_stage_len_list[j]

            attack_X = cld.build_cross_layer_X(feature_frames_dict, stage_lens, window_size_time, window_stride_time, rng)
            cross_layer_X = cld.cross_layer_concatenate(attack_X)

            signal_select = combos[i]
            for k, selection in enumerate(signal_select):
                if selection == 0:
                    cross_layer_X[k][:] = -1

            proba = gd.score_cross_layer(cross_layer_X)
            malware_scores.append(proba)

        y_scores = malware_scores + benign_scores
        y_true = np.zeros(len(y_scores))
        y_true[:len(malware_scores)] = 1

        fpr, tpr, thresholds = roc_curve(y_true, y_scores)
        roc_auc = auc(fpr, tpr)

        model_curves.append((fpr, tpr, roc_auc))

    plt.figure(figsize=(6, 4))
    for i in range(len(combos)):
        fpr, tpr, roc_auc = model_curves[i]
        plt.plot(fpr, tpr, lw=2, label=f'{model_labels[i]}: {roc_auc:.3f}')

    plt.plot([0, 1], [0, 1], lw=1, linestyle='--', label='Random guess')
    plt.xlim([-0.01, 1.0])
    plt.ylim([0.0, 1.05])
    plt.xlabel('False Positive Rate')
    plt.ylabel('True Positive Rate')
    plt.legend(loc="lower right", prop={'family': 'monospace'})
    plt.tight_layout()
    plt.grid()
    plt.show(block=True)

    return


def flow_variations(attack_stages_dict: dict, feature_frames_dict: dict, time_choices: list):
    preserve_stages = [
        ["recon", "exfil_1", "exfil_2", "exec_2"],
        ["recon", "exfil_2", "exec_2"],
        ["exfil_1", "exfil_2", "exec_2"],
        ["exfil_2", "exec_2"],
        ["recon", "exec_2"],
        ["exec_2"],
    ]

    flow_labels=[
        "RE_F1_F2_EX",
        "RE_**_F2_EX",
        "**_F1_F2_EX",
        "**_**_F2_EX",
        "RE_**_**_EX",
        "**_**_**_EX",
    ]

    n_samples = 100
    benign_stages = ml_pipelines.config.GENERATION_BENIGN

    b_flows = []
    m_flows = []
    for preserve_stage_list in preserve_stages:
        tmp_attack_stages = attack_stages_dict.copy()

        drop_list = []
        for stage in tmp_attack_stages:
            if stage not in preserve_stage_list:
                drop_list.append(stage)

        for key in drop_list:
            del tmp_attack_stages[key]

        b_stage_len_list = []
        for _ in range(n_samples):
            techniques = [random.choice(benign_stages) for _ in range(len(tmp_attack_stages))]
            stage_lens = [(technique, random.choice(time_choices)) for technique in techniques]
            b_stage_len_list.append(stage_lens)
        b_flows.append(b_stage_len_list)

        m_stage_len_list = []
        for _ in range(n_samples):
            techniques = [random.choice(ttp_choices) for _, ttp_choices in tmp_attack_stages.items()]
            stage_lens = [(technique, time_choices[0]) for technique in techniques]
            m_stage_len_list.append(stage_lens)
        m_flows.append(m_stage_len_list)


    gd = global_detector.LifecycleDetector(
        cwd / "../data/models/syscall_clf.joblib",
        cwd / "../data/models/network_clf.joblib",
        cwd / "../data/models/hpc_clf.joblib",
        lifecycle_awareness=True,
        stage_filter=False,
        density=False,
        propagation=False,
        memory=False,
    )

    flow_scores = []
    for i in range(len(preserve_stages)):
        benign_scores = []
        for stage_lens in b_flows[i]:
            attack_X = cld.build_cross_layer_X(feature_frames_dict, stage_lens, window_size_time, window_stride_time, rng)
            cross_layer_X = cld.cross_layer_concatenate(attack_X)

            proba = gd.score_cross_layer(cross_layer_X)
            benign_scores.append(proba)

        malware_scores = []
        for stage_lens in m_flows[i]:
            attack_X = cld.build_cross_layer_X(feature_frames_dict, stage_lens, window_size_time, window_stride_time, rng)
            cross_layer_X = cld.cross_layer_concatenate(attack_X)

            proba = gd.score_cross_layer(cross_layer_X)
            malware_scores.append(proba)

        y_scores = malware_scores + benign_scores
        y_true = np.zeros(len(y_scores))
        y_true[:len(malware_scores)] = 1

        fpr, tpr, thresholds = roc_curve(y_true, y_scores)
        roc_auc = auc(fpr, tpr)
        flow_scores.append((fpr, tpr, roc_auc))

    plt.figure(figsize=(6, 4))
    for i in range(len(preserve_stages)):
        fpr, tpr, roc_auc = flow_scores[i]

        plt.plot(fpr, tpr, lw=2, label=f'{flow_labels[i]}: {roc_auc:.3f}')

    plt.plot([0, 1], [0, 1], lw=1, linestyle='--', label='Random guess')
    plt.xlim([-0.01, 1.0])
    plt.ylim([0.0, 1.05])
    plt.xlabel('False Positive Rate')
    plt.ylabel('True Positive Rate')
    plt.legend(loc="lower right", prop={'family': 'monospace'})
    plt.tight_layout()
    plt.grid()
    plt.show(block=True)

    return

def benign_app_scores(attack_stages_dict: dict, feature_frames_dict: dict, time_choices: list):
    gds = [
        global_detector.LifecycleDetector(
            cwd / "../data/models/syscall_clf.joblib",
            cwd / "../data/models/network_clf.joblib",
            cwd / "../data/models/hpc_clf.joblib",
            lifecycle_awareness=True,
            stage_filter=False,
            density=False,
            propagation=False,
            memory=False,
        ),
        global_detector.LifecycleDetector(
            cwd / "../data/models/syscall_clf.joblib",
            cwd / "../data/models/network_clf.joblib",
            cwd / "../data/models/hpc_clf.joblib",
            lifecycle_awareness=True,
            stage_filter=False,
            density=True,
            propagation=True,
            memory=True,
        ),
    ]

    n_samples = 50


    malware_model_scores = [[] for _ in gds]
    for _ in range(n_samples):
        techniques = [random.choice(ttp_choices) for _, ttp_choices in attack_stages_dict.items()]
        stage_lens = [(technique, random.choice(time_choices)) for technique in techniques]

        attack_X = cld.build_cross_layer_X(feature_frames_dict, stage_lens, window_size_time, window_stride_time, rng)
        cross_layer_X = cld.cross_layer_concatenate(attack_X)

        for i, gd in enumerate(gds):
            malware_model_scores[i].append(gd.score_cross_layer(cross_layer_X))

    benign_stages = ml_pipelines.config.GENERATION_BENIGN
    benign_app_scores = []

    for i in range(len(benign_stages)):
        benign_scores = []
        benign_model_scores = [[] for _ in gds]
        for _ in range(n_samples):
            techniques = [benign_stages[i] for _ in range(len(attack_stages_dict))]
            stage_lens = [(technique, random.choice(time_choices)) for technique in techniques]

            attack_X = cld.build_cross_layer_X(feature_frames_dict, stage_lens, window_size_time, window_stride_time, rng)
            cross_layer_X = cld.cross_layer_concatenate(attack_X)

            for i, gd in enumerate(gds):
                benign_model_scores[i].append(gd.score_cross_layer(cross_layer_X))

        benign_app_scores.append(benign_model_scores)

    bars = []
    for i, app in enumerate(benign_stages):
        tmp_roc = []
        for j in range(len(gds)):
            malware_scores = malware_model_scores[j]
            benign_scores = benign_app_scores[i][j]

            y_scores = malware_scores + benign_scores
            y_true = np.zeros(len(y_scores))
            y_true[:len(malware_scores)] = 1

            fpr, tpr, thresholds = roc_curve(y_true, y_scores)
            roc_auc = auc(fpr, tpr)
            tmp_roc.append(roc_auc)
        bars.append(tmp_roc)

    bars = np.array(bars)

    x = np.arange(bars.shape[0])  # group positions: 0..9
    w = 0.4  # bar width

    fig, ax = plt.subplots()
    ax.bar(x - w / 2, bars[:, 0], width=w, label="gd_1", color="#4C78A8")
    ax.bar(x + w / 2, bars[:, 1], width=w, label="gd_2", color="#F58518")

    ax.set_xticks(x)
    ax.set_xticklabels([f"{benign_stages[i]}" for i in x], rotation=90)  # optional group labels
    ax.set_xlim(-0.5, x[-1] + 0.5)
    ax.set_ylim(0.85, 1.05)
    ax.set_ylabel("ROC-AUC")
    ax.set_xlabel("Benign Application")
    ax.legend(loc="lower right")
    plt.tight_layout()
    plt.show(block=True)

    return

def score_over_time(attack_stages_dict: dict, feature_frames_dict: dict, time_choices: list):
    gd = global_detector.LifecycleDetector(
        cwd / "../data/models/syscall_clf.joblib",
        cwd / "../data/models/network_clf.joblib",
        cwd / "../data/models/hpc_clf.joblib",
        lifecycle_awareness=True,
        stage_filter=False,
        density=True,
        propagation=True,
        memory=True,
    )

    n_samples = 50
    benign_stages = ml_pipelines.config.GENERATION_BENIGN

    benign_scores = []
    for _ in tqdm(range(n_samples)):
        techniques = [random.choice(benign_stages) for _ in range(len(attack_stages_dict))]
        stage_lens = [(technique, random.choice(time_choices)) for technique in techniques]

        attack_X = cld.build_cross_layer_X(feature_frames_dict, stage_lens, window_size_time, window_stride_time,
                                           rng)
        cross_layer_X = cld.cross_layer_concatenate(attack_X)
        progressive_scores = []
        for i in range(1, len(cross_layer_X[0])):
            tmp_X = (cross_layer_X[0][:i], cross_layer_X[1][:i], cross_layer_X[2][:i],)
            proba = gd.score_cross_layer(tmp_X)
            progressive_scores.append(proba)

        benign_scores.append(progressive_scores)

    malware_scores = []
    for _ in tqdm(range(n_samples)):
        techniques = [random.choice(ttp_choices) for _, ttp_choices in attack_stages_dict.items()]
        stage_lens = [(technique, random.choice(time_choices)) for technique in techniques]

        attack_X = cld.build_cross_layer_X(feature_frames_dict, stage_lens, window_size_time, window_stride_time,
                                           rng)
        cross_layer_X = cld.cross_layer_concatenate(attack_X)
        progressive_scores = []
        for i in range(1, len(cross_layer_X[0])):
            tmp_X = (cross_layer_X[0][:i], cross_layer_X[1][:i], cross_layer_X[2][:i],)
            proba = gd.score_cross_layer(tmp_X)
            progressive_scores.append(proba)

        malware_scores.append(progressive_scores)

    plt.figure(figsize=(6, 4))
    for i in range(len(benign_scores)):
        if i == 0:
            plt.plot(benign_scores[i], color="blue", alpha=0.2, label="benign")
        else:
            plt.plot(benign_scores[i], color="blue", alpha=0.2)

    for i in range(len(malware_scores)):
        if i ==0:
            plt.plot(malware_scores[i], color="red", alpha=0.2, label="malware")
        else:
            plt.plot(malware_scores[i], color="red", alpha=0.2)

    plt.xlabel("Time")
    plt.ylabel("Threat Score")
    plt.grid(True, alpha=0.3)
    plt.legend()
    plt.tight_layout()
    plt.show()

    b_scores = [scores[-1] for scores in benign_scores]
    m_scores = [scores[-1] for scores in malware_scores]

    y_scores = np.concatenate([m_scores, b_scores])
    y_true = np.zeros(len(y_scores))
    y_true[:len(malware_scores)] = 1

    fpr, tpr, thresholds = roc_curve(y_true, y_scores)
    roc_auc = auc(fpr, tpr)
    print(roc_auc)

    return



if __name__ == "__main__":
    plt.rcParams['font.size'] = 12

    cwd = Path.cwd()

    TRACE_LENS = True
    MODEL_CURVES = True
    EVADE_DENSITY = True
    SIGNAL_SAMPLES = True
    FLOW_VARIATIONS = True
    BENIGN_APP_SCORES = True
    SCORE_OVER_TIME = False

    window_size_time = 0.5
    window_stride_time = 0.2
    rng = np.random.default_rng(seed=1337)  # optional seed

    start = 1.5  # 0.5
    stop = 10
    step = 0.2
    time_choice_list = np.arange(start, stop + step / 2, step, dtype=float).tolist()

    model_paths = {
        "syscall_clf_path": cwd / "../data/models/syscall_clf.joblib",
        "network_clf_path": cwd / "../data/models/network_clf.joblib",
        "hpc_clf_path": cwd / "../data/models/hpc_clf.joblib",
    }

    feature_frames_path = cwd / "../data/feature_frames.joblib"
    feature_frames = joblib.load(feature_frames_path)
    attack_stages = ml_pipelines.config.GENERATION_ATTACK_STAGES

    attack_stages_dict = attack_stages
    feature_frames_dict = feature_frames
    time_choices = time_choice_list

    if TRACE_LENS:
        trace_len_plot(attack_stages, feature_frames, time_choice_list)

    if MODEL_CURVES:
        model_curves_plot(attack_stages, feature_frames, time_choice_list)

    if EVADE_DENSITY:
        evade_density_plot(attack_stages, feature_frames, time_choice_list)

    if SIGNAL_SAMPLES:
        signal_sample_plot(attack_stages, feature_frames, time_choice_list)

    if FLOW_VARIATIONS:
        flow_variations(attack_stages, feature_frames, time_choice_list)

    if BENIGN_APP_SCORES:
        benign_app_scores(attack_stages, feature_frames, time_choice_list)

    if SCORE_OVER_TIME:
        score_over_time(attack_stages, feature_frames, time_choice_list)






