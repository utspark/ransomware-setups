import matplotlib
from xgboost import XGBClassifier

matplotlib.use("Qt5Agg")
import matplotlib.pyplot as plt
plt.ion()

import os
import io

from pathlib import Path

import numpy as np
from sklearn.metrics import roc_auc_score, confusion_matrix, roc_curve, classification_report
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.utils import compute_class_weight

import tensorflow as tf
from tensorflow.keras.datasets import imdb
from tensorflow.keras.models import Sequential, load_model
from tensorflow.keras.layers import Dense
from tensorflow.keras.layers import LSTM, Reshape, Input
from tensorflow.keras.layers import Embedding
from tensorflow.keras.callbacks import EarlyStopping
from tensorflow.keras.preprocessing import sequence



def form_array_from_files(child_path, file_subsample=-1) -> np.array:
    if file_subsample == -1:
        file_subsample = 40

    files = [p for p in child_path.iterdir() if p.is_file()]
    files.sort()

    trace_list = []
    # TODO use all files
    for file_name in files[0:file_subsample]:
        print(file_name.name)
        file_path = str(file_name)

        with open(file_path, "r", newline="") as f:
            arr = np.loadtxt(f, dtype=int)
            trace_list.append(arr)

    # trace_list = trace_list[50]
    max_len = max(a.shape[0] for a in trace_list)

    # TODO think of proper padding approach
    padded = [
        np.pad(a,
               pad_width=(0, max_len - a.shape[0]),
               mode='constant',
               constant_values=0)
        for a in trace_list
    ]

    padded_matrix = np.vstack(padded)

    return padded_matrix


def form_one_hot_encoder(benign_array: np.array) -> OneHotEncoder:
    max_syscall = np.max(benign_array)
    one_hot_array = np.array(range(max_syscall))
    one_hot_array = one_hot_array.reshape(-1, 1)
    enc = OneHotEncoder(handle_unknown='ignore')
    enc.fit(one_hot_array)

    return enc


def increase_padding(pad_target, max_len) -> np.array:
    pad_len = max_len - pad_target.shape[1]
    pad_array = np.zeros((pad_target.shape[0], pad_len))
    padded = np.concatenate((pad_target, pad_array), axis=1)

    return padded


def unsupervised_preproc(mode: str) -> (np.array, np.array, np.array):
    benign, malware = preproc_transform(mode)

    X = benign
    y = np.zeros(len(X)) + 1

    X_train, X_test, _, y_test = train_test_split(
        X, y, test_size=0.3, random_state=42, stratify=y
    )

    X_test = np.concatenate((X_test, malware))

    malware_labels = np.zeros((len(malware))) - 1
    y_test = np.concatenate((y_test, malware_labels))

    return X_train, X_test, y_test







