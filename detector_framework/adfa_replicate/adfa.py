import argparse
import os
import numpy as np
import itertools
import multiprocessing
from functools import partial
from pathlib import Path
from collections import Counter

from sklearn.model_selection import train_test_split
from tqdm import tqdm
from sklearn.preprocessing import StandardScaler
from sklearn.svm import OneClassSVM, SVC
from sklearn.ensemble import IsolationForest
from sklearn.tree import DecisionTreeClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.metrics import roc_auc_score, classification_report, roc_curve
import matplotlib.pyplot as plt
from detector_framework import config


def load_data(base_path: str, recursive: bool = False) -> list | dict:
    """
    Loads syscall sequences from a directory.
    
    If recursive=False, it loads all .txt files from the base_path and returns a list of numpy arrays.
    If recursive=True, it traverses subdirectories and returns a dictionary where keys are 
    category names and values are lists of numpy arrays.
    """
    cwd = Path.cwd()
    data_path = cwd / base_path
    
    if not data_path.exists():
        # Try relative to the script location
        script_dir = Path(__file__).resolve().parent.parent.parent
        data_path = script_dir / base_path
        
    if not data_path.exists():
        raise FileNotFoundError(f"Could not find data at {data_path}")

    if recursive:
        data_dict = {}
        for category_dir in sorted(data_path.iterdir()):
            if category_dir.is_dir():
                category_name = category_dir.name
                sequences = []
                for file_path in sorted(category_dir.glob("*.txt")):
                    try:
                        with open(file_path, "r") as f:
                            content = f.read().strip()
                            if content:
                                seq = np.fromstring(content, dtype=int, sep=' ')
                                sequences.append(seq)
                    except Exception as e:
                        print(f"Error loading {file_path}: {e}")
                if sequences:
                    data_dict[category_name] = sequences
        return data_dict
    else:
        sequences = []
        for file_path in sorted(data_path.glob("*.txt")):
            try:
                with open(file_path, "r") as f:
                    content = f.read().strip()
                    if content:
                        seq = np.fromstring(content, dtype=int, sep=' ')
                        sequences.append(seq)
            except Exception as e:
                print(f"Error loading {file_path}: {e}")
        return sequences


def load_attack_data(base_path: str = "data/ADFA-IDS_DATASETS/ADFA-LD/Attack_Data_Master") -> dict:
    """Loads Attack_Data_Master (recursive)."""
    return load_data(base_path, recursive=True)


def load_training_data(base_path: str = "data/ADFA-IDS_DATASETS/ADFA-LD/Training_Data_Master") -> list:
    """Loads Training_Data_Master (non-recursive)."""
    return load_data(base_path, recursive=False)


def load_validation_data(base_path: str = "data/ADFA-IDS_DATASETS/ADFA-LD/Validation_Data_Master") -> list:
    """Loads Validation_Data_Master (non-recursive)."""
    return load_data(base_path, recursive=False)


def sliding_window_sampling(array: np.ndarray, window_size: int = 3, window_stride: int = 1) -> np.ndarray:
    """
    Takes a 1D numpy array of integers and returns the sliding window sampling of the given array.
    """
    if array.ndim != 1:
        raise ValueError("Input array must be 1D")
    
    # Calculate the number of windows
    if len(array) < window_size:
        return np.empty((0, window_size), dtype=array.dtype)
    
    num_windows = (len(array) - window_size) // window_stride + 1
    
    # Use stride_tricks for efficient sliding window
    shape = (num_windows, window_size)
    strides = (array.strides[0] * window_stride, array.strides[0])
    
    return np.lib.stride_tricks.as_strided(array, shape=shape, strides=strides)


def get_unique_windows(windows: np.ndarray) -> np.ndarray:
    """
    Takes a 2D numpy array of windows and returns the unique windows.
    """
    if windows.size == 0:
        return windows
    
    return np.unique(windows, axis=0)


def count_ngram_occurrences(ngram: np.ndarray, array: np.ndarray) -> int:
    """
    Finds the number of occurrences of an n-gram in a 1D numpy array.
    """
    if len(ngram) == 0:
        return 0
    
    if len(array) < len(ngram):
        return 0
    
    # Use sliding_window_sampling to get all windows of the same size as the n-gram
    windows = sliding_window_sampling(array, window_size=len(ngram), window_stride=1)
    
    if windows.size == 0:
        return 0
    
    # Count how many windows match the n-gram
    matches = np.all(windows == ngram, axis=1)
    return np.sum(matches)


def convert_data_to_list(data: dict) -> list:
    data_list = []

    for cat, seqs in data.items():
        for seq in seqs:
            data_list.append(seq)

    return data_list


def create_phrases(n: int, word_list: np.ndarray) -> np.ndarray:
    """
    Takes a size n and creates all possible n-tuples from the word list.
    word_list is expected to be a 2D numpy array where each row is a 'word'.
    Returns a numpy array of shape (len(word_list)**n, n, word_size).
    """
    if n <= 0:
        return np.empty((0, n, word_list.shape[1]), dtype=word_list.dtype)
    
    # itertools.product generates all possible combinations with replacement (cartesian product)
    # which corresponds to all possible n-tuples.
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
    
    # Prepare phrase structures for this sequence
    # state[k][p_idx] = count of partial matches of phrase p_idx that have reached length k
    state = [Counter() for _ in range(phrase_len)]
    phrase_matches = np.zeros(num_phrases, dtype=int)
    
    for w in window_tuples:
        if w in word_to_phrase_pos:
            # A word can advance multiple phrases.
            # For a SINGLE phrase, it can only advance ONE partial match.
            # We prioritize advancing the match closest to completion.
            
            p_idx_to_best_pos = {}
            for p_idx, pos in word_to_phrase_pos[w]:
                if pos == 0:
                    if p_idx not in p_idx_to_best_pos:
                        p_idx_to_best_pos[p_idx] = 0
                elif state[pos][p_idx] > 0:
                    if p_idx not in p_idx_to_best_pos or pos > p_idx_to_best_pos[p_idx]:
                        p_idx_to_best_pos[p_idx] = pos
            
            # Group phrases by their best position to process them efficiently
            # and ensure we don't let one 'w' satisfy multiple positions in the SAME phrase.
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


def count_phrases(data_list: list, phrases_vocab: np.ndarray, word_length: int, num_processes: int = None, return_all_counts: bool = False) -> np.ndarray:
    """
    Given a list of sequences and a set of phrases (size 1-5), count for each sequence the
    number of discontiguous phrases it contains that are in the phrases_vocab.
    
    A discontiguous phrase (w1, w2, ..., wn) is counted using a "sliding scan" interpretation:
    The function now counts the maximum number of disjoint n-tuples $(i_1, i_2, ..., i_n)$ 
    with $i_1 < i_2 < ... < i_n$ for each phrase. This ensures that each count uses 
    unique items from the sequence for each position in the phrase match.

    If return_all_counts is True, it returns a 2D array of shape (len(data_list), len(phrases_vocab))
    containing individual phrase counts. Otherwise, it returns a 1D array of shape (len(data_list),)
    containing normalized sums of all phrase counts.

    If num_processes is set (e.g. to os.cpu_count()), it will use multiple processes 
    to speed up calculation.
    """
    if phrases_vocab.size == 0:
        return np.zeros((len(data_list), 0)) if return_all_counts else np.zeros(len(data_list))
    
    phrase_len = phrases_vocab.shape[1]
    
    # phrase_dict mapping: word_tuple -> list of (phrase_index, position_in_phrase)
    word_to_phrase_pos = {}
    for p_idx, phrase in enumerate(tqdm(phrases_vocab, desc="Building phrase dictionary")):
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
            
        for i, seq in tqdm(enumerate(data_list), total=len(data_list), desc=f"Calculating phrase counts (n={phrase_len})"):
            counts[i] = _count_phrases_single(seq, word_to_phrase_pos, phrase_len, len(phrases_vocab), word_length, return_all_counts)
    else:
        # Split data_list into chunks to reduce serialization overhead
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
            # We wrap the map in tqdm to show progress by chunks
            chunk_results = list(tqdm(pool.imap(worker, chunks), 
                                     total=len(chunks), 
                                     desc=f"Calculating phrase counts (n={phrase_len}, parallel)"))
            
            # Flatten results
            if return_all_counts:
                # Flat list of 1D arrays -> 2D array
                counts = np.vstack([res for chunk in chunk_results for res in chunk])
            else:
                counts = np.array([res for chunk in chunk_results for res in chunk])

    return counts


def get_phrase_frequencies(data_list: list, phrases_vocab: np.ndarray, word_length: int, num_processes: int = None) -> list:
    """
    Returns the phrases in the phrases_vocab sorted by their total frequency across all sequences in data_list.
    Returns a list of tuples: (phrase_as_array, total_frequency)
    """
    # Get individual phrase counts for each sequence (not normalized)
    counts = count_phrases(data_list, phrases_vocab, word_length, num_processes=num_processes, return_all_counts=True)
    
    # Sum across all sequences
    total_counts = np.sum(counts, axis=0)
    
    # Pair with phrases and sort
    phrase_freqs = []
    for i, count in enumerate(total_counts):
        phrase_freqs.append((phrases_vocab[i], count))
        
    # Sort by frequency descending
    phrase_freqs.sort(key=lambda x: x[1], reverse=True)
    
    return phrase_freqs




if __name__ == "__main__":
    # --- Constants ---
    WORD_LENGTH = 7  # Length of the system call word (range: 3-7)
    CLASSIFIER = "mlp"  # Classifier to use: "decision_tree", "svm", "mlp", "one_class_svm", or "isolation_forest"

    if WORD_LENGTH < 3 or WORD_LENGTH > 7:
        print(f"Warning: WORD_LENGTH {WORD_LENGTH} is outside the typical range [3, 7].")

    config.set_seed()

    n_workers = os.cpu_count() - 4

    try:
        train_data = load_training_data()
        print(f"Loaded {len(train_data)} training sequences.")
        
        val_data = load_validation_data()
        print(f"Loaded {len(val_data)} validation sequences.")
        
        attack_dict = load_attack_data()
        attack_data = convert_data_to_list(attack_dict)
        print(f"Loaded {len(attack_data)} attack sequences from {len(attack_dict)} categories.")
    except Exception as e:
        print(f"Failed to load data: {e}")
        exit(1)

    # Use a subset for faster demonstration if needed, but here we'll try to use a reasonable amount
    # To keep it fast for this environment, let's use a subset of training data to build vocab
    train_subset = train_data
    val_subset = val_data[:500]
    attack_subset = attack_data

    print(f"Building vocabulary from training subset (word_length={WORD_LENGTH})...")
    # n-call word dictionary
    all_ngrams = []
    for seq in train_subset:
        windows = sliding_window_sampling(seq, window_size=WORD_LENGTH, window_stride=1)
        if windows.size > 0:
            all_ngrams.append(windows)
    
    if all_ngrams:
        all_ngrams = np.concatenate(all_ngrams, axis=0)
        
        # Count frequencies for sorting
        counts = Counter(map(tuple, all_ngrams))
        
        # Get unique windows sorted by frequency
        # most_common() returns a list of ((n-gram tuple), count) sorted by count descending
        sorted_vocab = [np.array(item[0]) for item in counts.most_common()]
        array_n = np.array(sorted_vocab)
    else:
        array_n = np.empty((0, WORD_LENGTH), dtype=int)
        
    print(f"Vocabulary size ({WORD_LENGTH}-grams): {len(array_n)}")
    if len(array_n) > 0:
        print(f"Most frequent {WORD_LENGTH}-gram: {array_n[0]} (count: {counts[tuple(array_n[0])]})")

    array_1 = array_n[0:100]
    array_2 = array_n[0:50]
    array_3 = array_n[0:30]
    array_4 = array_n[0:15]
    array_5 = array_n[0:15]
    array_6 = array_n[0:5]

    # 1-word phrase
    print("Generating 1-word phrases...")
    phrases_1 = create_phrases(1, array_1)
    phrase_freqs = get_phrase_frequencies(train_subset, phrases_1, WORD_LENGTH, n_workers)
    phrases_1 = np.array([phrase for phrase, _ in phrase_freqs[:200]])

    print("Generating 2-word phrases...")
    phrases_2 = create_phrases(2, array_2)
    phrase_freqs = get_phrase_frequencies(train_subset, phrases_2, WORD_LENGTH, n_workers)
    phrases_2 = np.array([phrase for phrase, _ in phrase_freqs[:200]])

    print("Generating 3-word phrases...")
    phrases_3 = create_phrases(3, array_3)
    phrase_freqs = get_phrase_frequencies(train_subset, phrases_3, WORD_LENGTH, n_workers)
    phrases_3 = np.array([phrase for phrase, _ in phrase_freqs[:100]])

    print("Generating 4-word phrases...")
    phrases_4 = create_phrases(4, array_4)
    phrase_freqs = get_phrase_frequencies(train_subset, phrases_4, WORD_LENGTH, n_workers)
    phrases_4 = np.array([phrase for phrase, _ in phrase_freqs[:100]])

    print("Generating 5-word phrases...")
    phrases_5 = create_phrases(5, array_5)
    phrase_freqs = get_phrase_frequencies(train_subset, phrases_5, WORD_LENGTH, n_workers)
    phrases_5 = np.array([phrase for phrase, _ in phrase_freqs[:100]])

    print("Generating 6-word phrases...")
    phrases_6 = create_phrases(6, array_6)
    phrase_freqs = get_phrase_frequencies(train_subset, phrases_6, WORD_LENGTH, n_workers)
    phrases_6 = np.array([phrase for phrase, _ in phrase_freqs[:100]])
    
    def get_features(data_list, name="data"):
        print(f"Calculating features for {name}...")
        feat1 = count_phrases(data_list, phrases_1, WORD_LENGTH, num_processes=n_workers)
        feat2 = count_phrases(data_list, phrases_2, WORD_LENGTH, num_processes=n_workers)
        feat3 = count_phrases(data_list, phrases_3, WORD_LENGTH, num_processes=n_workers)
        feat4 = count_phrases(data_list, phrases_4, WORD_LENGTH, num_processes=n_workers)
        feat5 = count_phrases(data_list, phrases_5, WORD_LENGTH, num_processes=n_workers)
        feat6 = count_phrases(data_list, phrases_6, WORD_LENGTH, num_processes=n_workers)
        return np.stack([feat1, feat2, feat3, feat4, feat5, feat6], axis=1)

    X_train = get_features(train_subset, "training data")
    X_val = get_features(val_subset, "validation data")
    X_attack = get_features(attack_subset, "attack data")

    # --- Normalize ---
    print("Normalizing features...")
    scaler = StandardScaler()
    X_train_norm = scaler.fit_transform(X_train)
    X_val_norm = scaler.transform(X_val)
    X_attack_norm = scaler.transform(X_attack)

    X = np.concatenate([X_train_norm, X_attack_norm])
    y = np.concatenate([np.ones(len(X_train_norm)), np.zeros(len(X_attack_norm))])

    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2)

    # --- Binary Classification ---

    if CLASSIFIER == "decision_tree":
        print(f"\nTraining Decision Tree Classifier on {len(X_train)} samples...")
        clf = DecisionTreeClassifier(random_state=42)
    elif CLASSIFIER == "svm":
        print(f"\nTraining SVM Classifier on {len(X_train)} samples...")
        clf = SVC(probability=True, random_state=42)
    elif CLASSIFIER == "mlp":
        print(f"\nTraining MLP Classifier on {len(X_train)} samples...")
        clf = MLPClassifier(hidden_layer_sizes=(100, 50), max_iter=1000, random_state=42)
    elif CLASSIFIER == "one_class_svm":
        print(f"\nTraining One-Class SVM on benign samples...")
        clf = OneClassSVM(kernel='rbf', gamma='auto')
        # Train only on benign samples (y_train == 1)
        X_train = X_train[y_train == 1]
    elif CLASSIFIER == "isolation_forest":
        print(f"\nTraining Isolation Forest on benign samples...")
        clf = IsolationForest(random_state=42)
        # Train only on benign samples (y_train == 1)
        X_train = X_train[y_train == 1]

    clf.fit(X_train, y_train)

    # --- Evaluation ---
    def evaluate(model, name):
        print(f"\n--- Evaluation: {name} ---")

        if CLASSIFIER in ["one_class_svm", "isolation_forest"]:
            # These models return 1 for inliers (benign) and -1 for outliers (attack)
            y_pred_raw = model.predict(X_test)
            y_pred = np.where(y_pred_raw == 1, 1, 0)
            y_prob = model.score_samples(X_test)
        else:
            y_pred = model.predict(X_test)
            y_prob = model.predict_proba(X_test)[:, 1]

        print(classification_report(y_test, y_pred, target_names=['Attack', 'Benign']))

        auc = roc_auc_score(y_test, y_prob)
        print(f"ROC AUC Score: {auc:.4f}")

        fpr, tpr, _ = roc_curve(y_test, y_prob)

        # Plot ROC Curve
        plt.figure(figsize=(8, 6))
        plt.plot(fpr, tpr, color='darkorange', lw=2, label=f'ROC curve (area = {auc:.2f})')
        plt.plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--')
        plt.xlim([0.0, 1.0])
        plt.ylim([0.0, 1.05])
        plt.xlabel('False Positive Rate')
        plt.ylabel('True Positive Rate')
        plt.title(f'Receiver Operating Characteristic - {name}')
        plt.legend(loc="lower right")

        # Save the plot
        file_name = f"roc_auc_{name.lower().replace(' ', '_')}.png"
        plt.savefig(file_name)
        print(f"ROC curve saved to {file_name}")

        plt.show(block=True)

    evaluate(clf, CLASSIFIER.replace("_", " ").title())













