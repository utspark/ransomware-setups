from itertools import groupby, combinations

import joblib
import numpy as np
from hmmlearn import hmm

from ml_pipelines import config


var_uniform_subseq_len = 2  # 3
var_density_scaler = 0.5
var_propagation_scaler = 0.5


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
    def __init__(self, syscall_clf_path, network_clf_path, hpc_clf_path,
                 lifecycle_awareness=True,
                 stage_filter=False,
                 density=False,
                 propagation=False,
                 memory=False
                 ):
        self.hmm = self._get_markov()
        self.syscall_clf = joblib.load(syscall_clf_path)[0]
        self.network_clf = joblib.load(network_clf_path)[0]
        self.hpc_clf = joblib.load(hpc_clf_path)[0]
        self.lifecycle_awareness = lifecycle_awareness
        self.stage_filter = stage_filter
        self.density = density
        self.propagation = propagation
        self.memory = memory

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
            if np.all(layer_data == -1):
                classes = layer_data[:, 0]
            else:
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
    def _stage_filter(class_sequence) -> np.ndarray:
        # multiclass -> sequence_processor
        global var_uniform_subseq_len

        new_sequence = []
        for key, group in groupby(class_sequence):
            emission_len = len([_ for _ in group])
            new_sequence.append((key, emission_len))

        prune_list = []

        for i, technique in enumerate(new_sequence):
            if technique[1] < var_uniform_subseq_len:
                prune_list.append(i)

        new_sequence = np.array(new_sequence)
        new_sequence = np.delete(new_sequence, prune_list, axis=0)

        if len(new_sequence) < 1:
            return new_sequence

        else:
            values = new_sequence[:, 0]
            counts = new_sequence[:, 1]
            out = np.repeat(values, counts)

            return out

    @staticmethod
    def _collate_preds(preds: np.ndarray) -> np.ndarray:
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

        return np.array(predictions)


    @staticmethod
    def _all_subseq(s: np.ndarray):
        def is_in_alphabetical_order(word):
            return word == ''.join(sorted(word))

        s = [str(i) for i in s]

        # Start with the empty subsequence
        results = []
        alphabetical_results = []

        # Generate combinations of lengths 1 to n
        for r in range(1, len(s) + 1):
            # Add all combinations of length r to result
            results.extend([', '.join(comb) for comb in combinations(s, r)])

        results = set(results)
        results = list(results)
        results.sort()

        results = [s.replace(", ", "") for s in results]
        remove_list = []

        for i in results:
            if not is_in_alphabetical_order(i):
                remove_list.append(i)

        for subseq in remove_list:
            results.remove(subseq)

        for subseq in results:
            subseq = [int(i) for i in subseq]
            alphabetical_results.append(subseq)

        return alphabetical_results

    def score_stage_sequence(self, stage_sequence: np.ndarray, clf_predictions: np.ndarray) -> float:
        global var_density_scaler
        global var_propagation_scaler
        proba = 0

        if self.density:
            density_penalty = len(stage_sequence) / len(clf_predictions) * var_density_scaler
            proba += density_penalty

        if self.propagation:
            stage_propagation_penalty = (len(np.unique(stage_sequence)) - 1) * var_propagation_scaler
            proba += stage_propagation_penalty

        if self.stage_filter:
            stage_sequence = self._stage_filter(stage_sequence)

        if len(stage_sequence) > 0 and self.lifecycle_awareness:

            if not self.memory:
                hmm_proba = np.exp(self.hmm.score(np.array(stage_sequence).reshape(-1, 1)))
                hmm_proba = np.power(hmm_proba, 1 / len(stage_sequence))  # normalization
                proba += hmm_proba

            else:
                new_sequence = []
                for key, group in groupby(stage_sequence):
                    new_sequence.append(key)

                proba_list = []
                subsequences = self._all_subseq(np.array(new_sequence))

                for subseq in subsequences:
                    hmm_proba = np.exp(self.hmm.score(np.array(subseq).reshape(-1, 1)))
                    hmm_proba = np.power(hmm_proba, 1 / len(stage_sequence))  # normalization
                    proba_list.append(hmm_proba)

                proba = np.max(proba_list, axis=0)

        return proba

    def score_cross_layer(self, cross_layer_X: tuple[np.ndarray, np.ndarray, np.ndarray]) -> float:
        clf_predictions = self.cross_layer_class_preds(cross_layer_X)
        predictions = self._collate_preds(clf_predictions)

        proba = self.score_stage_sequence(predictions, clf_predictions)

        return proba



