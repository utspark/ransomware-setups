from itertools import groupby

import joblib
import numpy as np
from hmmlearn import hmm

from ml_pipelines import config


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


class LifecycleDetector:
    def __init__(self, syscall_clf_path, network_clf_path, hpc_clf_path):
        self.hmm = self._get_markov()
        self.syscall_clf = joblib.load(syscall_clf_path)[0]
        self.network_clf = joblib.load(network_clf_path)[0]
        self.hpc_clf = joblib.load(hpc_clf_path)[0]

    @staticmethod
    def _get_markov() -> hmm.CategoricalHMM:
        s_c = 0.6  # start confidence, confidence that sequence will start at first stage
        alternate_start_weights = [i * 1.5 for i in range(1, 4)][::-1]
        alternate_start_weights = np.array(alternate_start_weights) / np.sum(alternate_start_weights) * (1 - s_c)
        alternate_start_weights = alternate_start_weights.tolist()
        alternate_start_weights.insert(0, s_c)

        start_matrix = alternate_start_weights

        f_b_ratio = 2  # ratio of confidence of forward transition over backward transition
        t_f0 = 1 / (4 * f_b_ratio + 0) * f_b_ratio
        t_f1 = 1 / (3 * f_b_ratio + 1) * f_b_ratio
        t_f2 = 1 / (2 * f_b_ratio + 2) * f_b_ratio
        t_f3 = 1 / (1 * f_b_ratio + 3) * f_b_ratio

        t_b1 = 1 / (3 * f_b_ratio + 1)
        t_b2 = 1 / (2 * f_b_ratio + 2)
        t_b3 = 1 / (1 * f_b_ratio + 3)

        transition_matrix = [
            [t_f0, t_f0, t_f0, t_f0],
            [t_b1, t_f1, t_f1, t_f1],
            [t_b2, t_b2, t_f2, t_f2],
            [t_b3, t_b3, t_b3, t_f3],
        ]

        e0 = 1  # 0.7  # confidence in detection at this stage 1
        e1 = 1  # 0.7
        e2 = 1  # 0.7
        e3 = 1  # 0.7

        emission_matrix = [
            [e0, 0, 0, 0],
            [0, e1, 0, 0],
            [0, 0, e2, 0],
            [0, 0, 0, e3],
        ]

        model = hmm.CategoricalHMM(n_components=4, n_features=4)
        model.startprob_ = np.array(start_matrix)
        model.transmat_ = np.array(transition_matrix)
        model.emissionprob_ = np.array(emission_matrix)

        return model

    def cross_layer_class_preds(self, cross_layer_X: tuple):
        cross_layer_classes = []

        clfs = [self.syscall_clf, self.network_clf, self.hpc_clf]
        translations = [
            config.SYSCALL_BENIGN_MALWARE_CLASS_TRANSLATION,
            config.NETWORK_BENIGN_MALWARE_CLASS_TRANSLATION,
            config.HPC_BENIGN_MALWARE_CLASS_TRANSLATION,
        ]

        for clf, layer_data, translation in zip(clfs, cross_layer_X, translations):
            preds = clf.predict_proba(layer_data)
            probas = np.max(preds, axis=1)
            classes = np.argmax(preds, axis=1)
            classes[probas < 0.7] = -1

            # Vectorized translation
            vectorized_translate = np.vectorize(translation.get)
            classes = vectorized_translate(classes)
            cross_layer_classes.append(classes)

        cross_layer_classes = np.stack(cross_layer_classes).T

        return cross_layer_classes

    @staticmethod
    def collate_preds(preds: np.ndarray) -> list:
        predictions = []

        for row in preds:
            row = row[row != -1]
            if len(row) == 0:
                continue
            elif len(row) == 1:
                predictions.append(row[0])
                continue

            uniques, counts = np.unique(row, return_counts=True)
            max_count = counts.max()
            # Check if there is a tie for the highest count
            if np.sum(counts == max_count) == 1:
                most_common = uniques[counts.argmax()]
                predictions.append(most_common)

        return predictions

    def score_cross_layer(self, cross_layer_X: tuple[np.ndarray, np.ndarray, np.ndarray]) -> float:
        clf_predictions = self.cross_layer_class_preds(cross_layer_X)
        predictions = self.collate_preds(clf_predictions)

        if len(predictions) > 0:
            proba = np.exp(self.hmm.score(np.array(predictions).reshape(-1, 1)))
            proba = np.power(proba, 1 / len(predictions))  # normalization
        else:
            proba = 0

        return proba



    def score_sequence_old(self, seq_classes: np.array, seq_values: np.array) -> float:
        var_classifier_conf = 0.6
        var_uniform_subseq_len = 2

        # *** filter confidence
        confidence_mask = np.nonzero(seq_values > var_classifier_conf)[0]
        seq_classes = seq_classes[confidence_mask]

        # *** filter classifications
        new_sequence = []
        for key, group in groupby(seq_classes):
            emission_len = len([_ for _ in group])
            new_sequence.append((key, emission_len))

        prune_list = []

        for i, technique in enumerate(new_sequence):
            if technique[1] < var_uniform_subseq_len:
                prune_list.append(i)

        new_sequence = np.array(new_sequence)
        new_sequence = np.delete(new_sequence, prune_list, axis=0)

        # techniques = []
        # for key, group in groupby(new_sequence, lambda row: row[0]):
        #     data = np.sum(np.array([item[1] for item in group]))
        #     techniques.append((key, data))
        techniques = new_sequence

        # *** get emissions
        human_techniques = [config.LABEL_NAMES[technique[0]] for technique in techniques]

        emissions = []
        for technique in human_techniques:
            for i, stage in enumerate(config.HMM_ATTACK_STAGES):
                if technique in config.HMM_ATTACK_STAGES[stage]:
                    emissions.append(i)
                    break

        # *** hmm score
        x = np.array(emissions).reshape(-1, 1)

        proba = np.exp(self.hmm.score(np.array(x)))
        proba = np.power(proba, 1 / len(x))  # normalization

        # TODO punish longer stage sequences
        # proba = np.power(proba, 1 / len(x) * 0.2)

        return proba


