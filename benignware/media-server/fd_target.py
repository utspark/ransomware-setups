#!/usr/bin/python3

import os
import time

def main():
    print(f"[Target] PID={os.getpid()} started.")
    # Open a file to test fd duplication
    with open("shared.out", "a", buffering=1) as f:
        print(f"[Target] Opened file shared_output.txt (fd={f.fileno()}).")
        print(f"[Target] Sleeping. Use this PID in the other script.")
        while True:
            time.sleep(1)

if __name__ == "__main__":
    main()
