from pathlib import Path

import numpy as np
import pandas as pd
from sklearn import feature_extraction

import feature_extraction

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

def _init_worker(
    instructions, LLC_load_misses, avx_insts_all, block_rq_issue, br_inst_retired,
    cache_references, mem_loads, mem_stores, port_0, port_1, port_2, port_3, port_4, port_5,
    port_6, port_7
):
    """Runs once per worker process; stash read-only arrays in module globals."""
    global _G
    _G = {
        "instructions": instructions,
        "LLC_load_misses": LLC_load_misses,
        "avx_insts_all": avx_insts_all,
        "block_rq_issue": block_rq_issue,
        "br_inst_retired": br_inst_retired,
        "cache_references": cache_references,
        "mem_loads": mem_loads,
        "mem_stores": mem_stores,
        "port_0": port_0,
        "port_1": port_1,
        "port_2": port_2,
        "port_3": port_3,
        "port_4": port_4,
        "port_5": port_5,
        "port_6": port_6,
        "port_7": port_7,
    }

def _features_one(pair: Tuple[int, int]) -> Optional[List[float]]:
    """Compute features for a single [i:j) window using globals set by _init_worker."""
    i, j = pair
    if j <= i:
        return None

    return [
        np.mean(_G["instructions"][i:j]),
        np.mean(_G["LLC_load_misses"][i:j]),
        np.mean(_G["avx_insts_all"][i:j]),
        np.mean(_G["block_rq_issue"][i:j]),
        np.mean(_G["br_inst_retired"][i:j]),
        np.mean(_G["cache_references"][i:j]),
        np.mean(_G["mem_loads"][i:j]),
        np.mean(_G["mem_stores"][i:j]),
        np.mean(_G["port_0"][i:j]),
        np.mean(_G["port_1"][i:j]),
        np.mean(_G["port_2"][i:j]),
        np.mean(_G["port_3"][i:j]),
        np.mean(_G["port_4"][i:j]),
        np.mean(_G["port_5"][i:j]),
        np.mean(_G["port_6"][i:j]),
        np.mean(_G["port_7"][i:j]),
    ]

def _chunked(it: Iterable, n: int):
    """Yield lists of up to n items from iterable it."""
    it = iter(it)
    while True:
        chunk = list(islice(it, n))
        if not chunk:
            return
        yield chunk

def _features_batch(pairs: List[Tuple[int, int]]) -> List[List[float]]:
    out = []
    for p in pairs:
        row = _features_one(p)
        if row is not None and row[0] != 0:
            out.append(row)
    return out

# ---------- parallelized main function ----------
def file_df_feature_extraction_parallel(
    df: pd.DataFrame,
    window_size_time: float,
    window_stride_time: float,
    *,
    n_workers: Optional[int] = None,
    chunksize: int = 512,   # number of windows per task to reduce overhead
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
    block_rq_issue  = df["block:block_rq_issue"].to_numpy(dtype=float, copy=False)
    br_inst_retired = df["br_inst_retired.all_branches"].to_numpy(dtype=float, copy=False)
    cache_references = df["cache-references"].to_numpy(dtype=float, copy=False)
    mem_loads = df["mem-loads"].to_numpy(dtype=float, copy=False)
    mem_stores = df["mem-stores"].to_numpy(dtype=float, copy=False)
    port_0 = df["uops_executed_port.port_0"].to_numpy(dtype=float, copy=False)
    port_1= df["uops_executed_port.port_1"].to_numpy(dtype=float, copy=False)
    port_2 = df["uops_executed_port.port_2"].to_numpy(dtype=float, copy=False)
    port_3 = df["uops_executed_port.port_3"].to_numpy(dtype=float, copy=False)
    port_4 = df["uops_executed_port.port_4"].to_numpy(dtype=float, copy=False)
    port_5 = df["uops_executed_port.port_5"].to_numpy(dtype=float, copy=False)
    port_6 = df["uops_executed_port.port_6"].to_numpy(dtype=float, copy=False)
    port_7 = df["uops_executed_port.port_7"].to_numpy(dtype=float, copy=False)

    # Spin up the pool; each worker gets arrays once via initializer
    with ProcessPoolExecutor(
        max_workers=n_workers,
        initializer=_init_worker,
        initargs=(
            instructions, LLC_load_misses, avx_insts_all, block_rq_issue, br_inst_retired,
            cache_references, mem_loads, mem_stores, port_0, port_1, port_2, port_3, port_4, port_5,
            port_6, port_7
        ),
    ) as ex:
        # Map in batches to reduce per-task overhead
        results = ex.map(_features_batch, _chunked(pairs, chunksize))
        rows = [row for batch in results for row in batch]

    cols = [
        "instructions",
        "LLC_load_misses",
        "avx_insts_all",
        "block_rq_issue",
        "br_inst_retired",
        "cache_references",
        "mem-loads",
        "mem-stores",
        "port_0",
        "port_1",
        "port_2",
        "port_3",
        "port_4",
        "port_5",
        "port_6",
        "port_7",
    ]

    return pd.DataFrame(rows, columns=cols)

