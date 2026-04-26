from pathlib import Path

import numpy as np
import pandas as pd
from sklearn import feature_extraction as sklearn_feature_extraction

from detector_framework.cross_layer import feature_extraction

from concurrent.futures import ProcessPoolExecutor
from itertools import islice
from typing import Iterable, List, Tuple, Optional


def get_file_df(filepath: Path) -> pd.DataFrame:
    sep = ","

    df = pd.read_csv(
        filepath,
        sep=sep,
        # engine="python",  # needed for callable on_bad_lines
        # on_bad_lines=fix_bad_line  # normalize bad rows on the fly
    )

    cols = [
        'time', 'instructions', 'LLC-load-misses', 'avx_insts.all', 'block:block_rq_issue',
        'br_inst_retired.all_branches', 'cache-references', 'mem-loads', 'mem-stores', 'uops_executed_port.port_0',
        'uops_executed_port.port_1', 'uops_executed_port.port_2', 'uops_executed_port.port_3',
        'uops_executed_port.port_4', 'uops_executed_port.port_5', 'uops_executed_port.port_6',
        'uops_executed_port.port_7',
    ]

    df = df[cols]
    df["time"] = df.time.astype(float)
    df["time"] = df["time"] - df["time"][0]

    df = df.fillna(0)

    return df


_G = {}

def _init_worker(instructions, LLC_load_misses, avx_insts_all, br_inst_retired):
    """Runs once per worker process; stash read-only arrays in module globals."""
    global _G
    _G = {
        "instructions": instructions,
        "LLC_load_misses": LLC_load_misses,
        "avx_insts_all": avx_insts_all,
        "br_inst_retired": br_inst_retired,
    }

def _features_one(pair: Tuple[int, int]) -> Optional[List[float]]:
    """Compute features for a single [i:j) window using globals set by _init_worker."""
    i, j = pair
    if j <= i:
        return None

    means = [
        np.mean(_G["instructions"][i:j]),
        np.mean(_G["LLC_load_misses"][i:j]),
        np.mean(_G["avx_insts_all"][i:j]),
        np.mean(_G["br_inst_retired"][i:j]),
    ]

    # normalize by instruction count
    instr_count = means[0]
    if instr_count > 0:
        normalized_means = [mean / instr_count for mean in means[1:]]
    else:
        normalized_means = [0.0] * (len(means) - 1)

    return [instr_count] + normalized_means

def _features_batch(pairs: List[Tuple[int, int]]) -> List[List[float]]:
    return feature_extraction.features_batch(pairs, _features_one)


# ---------- parallelized main function ----------
def file_df_feature_extraction_parallel(
    df: pd.DataFrame,
    window_size_time: float,
    window_stride_time: float,
    *,
    n_workers: Optional[int] = None,
    chunksize: int = 512,   # number of windows per task to reduce overhead
    preserve_time: bool = False,
) -> pd.DataFrame:
    # Build windows on the main process
    left_idx, right_idx = feature_extraction.get_time_windows(
        df["time"], window_size_time, window_stride_time
    )
    pairs = list(zip(left_idx, right_idx))

    # Extract needed columns as arrays (far cheaper to slice than DataFrame in workers)
    instructions  = df["instructions"].to_numpy(dtype=float, copy=False)
    LLC_load_misses = df["LLC-load-misses"].to_numpy(dtype=float, copy=False)
    avx_insts_all = df["avx_insts.all"].to_numpy(dtype=float, copy=False)
    br_inst_retired = df["br_inst_retired.all_branches"].to_numpy(dtype=float, copy=False)

    # Spin up the pool; each worker gets arrays once via initializer
    with ProcessPoolExecutor(
        max_workers=n_workers,
        initializer=_init_worker,
        initargs=(instructions, LLC_load_misses, avx_insts_all, br_inst_retired)
    ) as ex:
        # Map in batches to reduce per-task overhead
        results = ex.map(_features_batch, feature_extraction.chunked(pairs, chunksize))
        rows = [row for batch in results for row in batch]

    cols = [
        "instructions",
        "LLC_load_misses",
        "avx_insts_all",
        "br_inst_retired",
    ]

    X = pd.DataFrame(rows, columns=cols)

    if preserve_time:
        X["time"] = df["time"].iloc[right_idx].reset_index(drop=True)
        X.insert(0, "time", X.pop("time"))

    return X

