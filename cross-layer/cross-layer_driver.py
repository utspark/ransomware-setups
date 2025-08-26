from pathlib import Path

from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier

import network_signals
import syscall_signals
import ml_pipelines.config
import numpy as np
import pandas as pd
import seaborn as sns

from sklearn.utils import compute_class_weight, compute_sample_weight
from sklearn.preprocessing import LabelBinarizer

from sklearn.metrics import roc_auc_score, confusion_matrix, roc_curve, classification_report, log_loss

import matplotlib
matplotlib.use("Qt5Agg")
import matplotlib.pyplot as plt
plt.ion()


if __name__ == "__main__":
    cwd = Path.cwd()

    window_size_time = 0.1 / 10
    window_stride_time = 0.05 / 10

    syscall_dir = cwd / "../data/syscall_ints"
    syscall_paths = [p for p in syscall_dir.iterdir() if p.is_file()]
    syscall_paths.sort()

    MALWARE_DICT = ml_pipelines.config.MALWARE_DICT
    file_set = set(MALWARE_DICT.keys())
    filtered = [path for path in syscall_paths if path.name in file_set]
    syscall_paths = filtered

    syscall_data_list = []
    syscall_label_list = []

    for file_path in syscall_paths:
        label = MALWARE_DICT[file_path.name]

        syscall_df = syscall_signals.get_file_df(file_path)
        syscall_X = syscall_signals.file_df_feature_extraction(syscall_df, window_size_time, window_stride_time)
        y = np.zeros(len(syscall_X)) + label

        syscall_data_list.append(syscall_X)
        syscall_label_list.append(y)

    X = np.concatenate(syscall_data_list, axis=0)
    y = np.concatenate(syscall_label_list, axis=0).astype(int)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.3, random_state=42, stratify=y
    )

    class_weights = compute_class_weight('balanced', classes=np.unique(y_train), y=y_train)
    weight_dict = {label: weight for label, weight in zip(np.unique(y_train), class_weights)}

    train_sample_weights = compute_sample_weight(class_weight=weight_dict, y=y_train)
    test_sample_weights = compute_sample_weight(class_weight=weight_dict, y=y_test)

    lb = LabelBinarizer()
    lb.fit(y_train)
    y_train_ohe = lb.transform(y_train)
    y_test_ohe = lb.transform(y_test)

    dtree_model = DecisionTreeClassifier(max_depth=7).fit(X_train, y_train, sample_weight=train_sample_weights)
    y_pred_ohe = dtree_model.predict_proba(X_test)

    loss_ohe = log_loss(y_test_ohe, y_pred_ohe, sample_weight=test_sample_weights)
    print(f"Log Loss Score: {loss_ohe:.3f}")

    y_pred = lb.inverse_transform(y_pred_ohe)
    print(classification_report(y_test, y_pred, sample_weight=test_sample_weights))

    cm = confusion_matrix(y_test, y_pred, sample_weight=test_sample_weights, normalize='true')
    cm_df = pd.DataFrame(cm)

    # 4) Plot with seaborn
    plt.figure(figsize=(8, 6))
    sns.heatmap(
        cm_df,
        annot=True,  # write the counts (or rates) in each cell
        fmt='.2f',  # integer format; use '.2f' if you normalized
        cmap='Blues',  # color map
        cbar_kws={'label': 'Normalized Count'}
    )
    plt.ylabel('Actual')
    plt.xlabel('Predicted')
    plt.title('Confusion Matrix')
    plt.tight_layout()
    plt.show(block=True)

    # network_dir = cwd / "../data/v4_results/out_exec"
    # network_paths = [p for p in network_dir.iterdir() if p.is_file()]
    # network_paths.sort()
    #
    # network_file_path = network_paths[0]
    # network_df = network_signals.get_file_df(network_file_path)
    # network_X = network_signals.file_df_feature_extraction(network_df, window_size_time, window_stride_time)



    # TODO
    #  - make sure files are matching between signal sources


