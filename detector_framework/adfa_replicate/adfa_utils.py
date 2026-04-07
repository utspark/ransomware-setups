import os
import multiprocessing
import random
import itertools
from functools import partial
from pathlib import Path
from collections import Counter
from typing import Dict, List, Tuple, Any, Callable, Iterable, Mapping
from types import ModuleType

import joblib
import numpy as np
import matplotlib.pyplot as plt
from tqdm import tqdm
from sklearn.metrics import roc_auc_score, classification_report, roc_curve

def sliding_window_sampling(array: np.ndarray, window_size: int = 3, window_stride: int = 1) -> np.ndarray:
    """
    Takes a 1D numpy array of integers and returns the sliding window sampling of the given array.
    """
    if array.ndim != 1:
        raise ValueError("Input array must be 1D")
    
    if len(array) < window_size:
        return np.empty((0, window_size), dtype=array.dtype)
    
    num_windows = (len(array) - window_size) // window_stride + 1
    
    shape = (num_windows, window_size)
    strides = (array.strides[0] * window_stride, array.strides[0])
    
    return np.lib.stride_tricks.as_strided(array, shape=shape, strides=strides)


def build_ngram_vocabulary(sequences: List[np.ndarray], word_length: int, unique: bool = True) -> Tuple[np.ndarray, Counter]:
    """
    Builds an n-gram vocabulary from a list of sequences.
    
    Returns:
        tuple: (array_n, counts) where array_n is a sorted numpy array of n-grams 
               and counts is a Counter object of n-gram frequencies.
    """
    print(f"Building vocabulary from sequences (word_length={word_length})...")
    
    counts = Counter()
    for seq in sequences:
        windows = sliding_window_sampling(seq, window_size=word_length, window_stride=1)
        if windows.size > 0:
            counts.update(map(tuple, windows))
    
    if not counts:
        return np.empty((0, word_length), dtype=int), Counter()

    sorted_vocab = [np.array(item[0]) for item in counts.most_common()]
    array_n = np.array(sorted_vocab)

    if unique:
        unique_indices = [i for i, array in enumerate(array_n) if np.unique(array).size > 1]
        
        for i in range(len(array_n)):
            if i not in unique_indices:
                counts.pop(tuple(array_n[i]))
                
        array_n = array_n[unique_indices]
        
    print(f"Vocabulary size ({word_length}-grams): {len(array_n)}")
    if len(array_n) > 0:
        print(f"Most frequent {word_length}-gram: {array_n[0]} (count: {counts[tuple(array_n[0])]})")
        
    return array_n, counts


def create_phrases(n: int, word_list: np.ndarray) -> np.ndarray:
    """
    Takes a size n and creates all possible n-tuples from the word list.
    word_list is expected to be a 2D numpy array where each row is a 'word'.
    Returns a numpy array of shape (len(word_list)**n, n, word_size).
    """
    if n <= 0:
        return np.empty((0, n, word_list.shape[1]), dtype=word_list.dtype)
    
    phrases = list(itertools.product(word_list, repeat=n))
    return np.array(phrases)


def _count_phrases_single(seq: np.ndarray, word_to_phrase_pos: dict, phrase_len: int, num_phrases: int, word_length: int, return_all_counts: bool = False) -> float | np.ndarray:
    """
    Helper function to process a single sequence for count_phrases.
    """
    windows = sliding_window_sampling(seq, window_size=word_length, window_stride=1)
    if windows.size == 0:
        return np.zeros(num_phrases) if return_all_counts else 0.0
        
    window_tuples = [tuple(w) for w in windows]
    
    state = [Counter() for _ in range(phrase_len)]
    phrase_matches = np.zeros(num_phrases, dtype=int)
    
    for w in window_tuples:
        if w in word_to_phrase_pos:
            p_idx_to_best_pos = {}
            for p_idx, pos in word_to_phrase_pos[w]:
                if pos == 0:
                    if p_idx not in p_idx_to_best_pos:
                        p_idx_to_best_pos[p_idx] = 0
                elif state[pos][p_idx] > 0:
                    if p_idx not in p_idx_to_best_pos or pos > p_idx_to_best_pos[p_idx]:
                        p_idx_to_best_pos[p_idx] = pos
            
            for p_idx, pos in p_idx_to_best_pos.items():
                if pos == 0:
                    if phrase_len == 1:
                        phrase_matches[p_idx] += 1
                    else:
                        state[1][p_idx] += 1
                else:
                    state[pos][p_idx] -= 1
                    if pos == phrase_len - 1:
                        phrase_matches[p_idx] += 1
                    else:
                        state[pos+1][p_idx] += 1
    
    if return_all_counts:
        return phrase_matches
    return np.sum(phrase_matches) / len(seq) if len(seq) > 0 else 0.0


def _count_phrases_chunk(chunk, word_to_phrase_pos, phrase_len, num_phrases, word_length, return_all_counts=False):
    """
    Helper function to process a chunk of sequences for count_phrases.
    """
    results = []
    for seq in chunk:
        results.append(_count_phrases_single(seq, word_to_phrase_pos, phrase_len, num_phrases, word_length, return_all_counts))
    return results


def count_phrases(data_list: List[np.ndarray], phrases_vocab: np.ndarray, word_length: int, num_processes: int = None, return_all_counts: bool = False) -> np.ndarray:
    """
    Given a list of sequences and a set of phrases (size 1-5), count for each sequence the
    number of discontiguous phrases it contains that are in the phrases_vocab.
    """
    if phrases_vocab.size == 0:
        return np.zeros((len(data_list), 0)) if return_all_counts else np.zeros(len(data_list))
    
    phrase_len = phrases_vocab.shape[1]
    
    word_to_phrase_pos = {}
    for p_idx, phrase in enumerate(phrases_vocab):
        for pos, word in enumerate(phrase):
            w_tuple = tuple(word)
            if w_tuple not in word_to_phrase_pos:
                word_to_phrase_pos[w_tuple] = []
            word_to_phrase_pos[w_tuple].append((p_idx, pos))

    if num_processes is None or num_processes <= 1:
        if return_all_counts:
            counts = np.zeros((len(data_list), len(phrases_vocab)))
        else:
            counts = np.zeros(len(data_list))
            
        for i, seq in enumerate(data_list):
            counts[i] = _count_phrases_single(seq, word_to_phrase_pos, phrase_len, len(phrases_vocab), word_length, return_all_counts)
    else:
        num_sequences = len(data_list)
        chunk_size = max(1, num_sequences // (num_processes * 4))
        chunks = [data_list[i:i + chunk_size] for i in range(0, num_sequences, chunk_size)]

        worker = partial(_count_phrases_chunk, 
                         word_to_phrase_pos=word_to_phrase_pos, 
                         phrase_len=phrase_len, 
                         num_phrases=len(phrases_vocab),
                         word_length=word_length,
                         return_all_counts=return_all_counts)
        
        with multiprocessing.Pool(processes=num_processes) as pool:
            chunk_results = list(pool.imap(worker, chunks))
            
            if return_all_counts:
                counts = np.vstack([res for chunk in chunk_results for res in chunk])
            else:
                counts = np.array([res for chunk in chunk_results for res in chunk])

    return counts


def get_phrase_frequencies(data_list: List[np.ndarray], phrases_vocab: np.ndarray, word_length: int, num_processes: int = None) -> List[Tuple[np.ndarray, float]]:
    """
    Returns the phrases in the phrases_vocab sorted by their total frequency across all sequences in data_list.
    """
    counts = count_phrases(data_list, phrases_vocab, word_length, num_processes=num_processes, return_all_counts=True)
    total_counts = np.sum(counts, axis=0)
    
    phrase_freqs = []
    for i, count in enumerate(total_counts):
        phrase_freqs.append((phrases_vocab[i], count))
        
    phrase_freqs.sort(key=lambda x: x[1], reverse=True)
    return phrase_freqs


def generate_multigram_phrases(train_subset: List[np.ndarray], array_n: np.ndarray, word_length: int, n_workers: int, max_length: int = 6) -> List[np.ndarray]:
    """
    Generates top phrases for lengths 1 through max_length.
    """
    all_phrases = []
    configs = {
        1: (100, 200),
        2: (50, 200),
        3: (30, 100),
        4: (15, 100),
        5: (15, 100),
        6: (5, 100)
    }
    
    for i in range(1, max_length + 1):
        print(f"Generating {i}-word phrases...")
        n_slice, top_k = configs.get(i, (5, 100))
        
        phrases = create_phrases(i, array_n[0:n_slice])
        phrase_freqs = get_phrase_frequencies(train_subset, phrases, word_length, n_workers)
        top_phrases = np.array([phrase for phrase, _ in phrase_freqs[:top_k]])
        all_phrases.append(top_phrases)
        
    return all_phrases


def get_features(data_list: List[np.ndarray], all_phrases: List[np.ndarray], word_length: int, n_workers: int, name: str = "data") -> np.ndarray:
    """Calculates phrase counts for each sequence in data_list as features."""
    print(f"Calculating features for {name}...")
    feats = []
    for phrases in all_phrases:
        feat = count_phrases(data_list, phrases, word_length, num_processes=n_workers)
        feats.append(feat)
    return np.stack(feats, axis=1)


def evaluate(model, name: str, classifier_type: str, X_test: np.ndarray, y_test: np.ndarray, plot: bool = True) -> Tuple[np.ndarray, np.ndarray, float]:
    """Evaluates the model and optionally plots/saves the ROC curve."""
    print(f"\n--- Evaluation: {name} ---")

    if classifier_type in ["one_class_svm", "isolation_forest"]:
        y_pred_raw = model.predict(X_test)
        y_pred = np.where(y_pred_raw == 1, 1, 0)
        y_prob = model.score_samples(X_test)
    else:
        y_pred = model.predict(X_test)
        y_prob = model.predict_proba(X_test)[:, 1]

    print(classification_report(y_test, y_pred, target_names=['Attack', 'Benign'], labels=[0, 1]))

    auc = float(roc_auc_score(y_test, y_prob))
    print(f"ROC AUC Score: {auc:.4f}")

    fpr, tpr, _ = roc_curve(y_test, y_prob)

    if plot:
        plt.figure(figsize=(8, 6))
        plt.plot(fpr, tpr, color='darkorange', lw=2, label=f'ROC curve (area = {auc:.2f})')
        plt.plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--')
        plt.xlim([0.0, 1.0])
        plt.ylim([0.0, 1.05])
        plt.xlabel('False Positive Rate')
        plt.ylabel('True Positive Rate')
        plt.title(f'Receiver Operating Characteristic - {name}')
        plt.legend(loc="lower right")

        file_name = f"roc_auc_{name.lower().replace(' ', '_')}.png"
        plt.savefig(file_name)
        print(f"ROC curve saved to {file_name}")

    return (fpr, tpr, auc)
