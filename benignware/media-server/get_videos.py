#!/usr/bin/python3
from datasets import load_dataset
import random

dataset = load_dataset("dm-petrov/youtube-commons-small")
sampled_dataset = dataset['train'].shuffle(seed=42).select(range(100))

cc_by_videos = [item['video_link'] for item in sampled_dataset if item['license'] == 'Creative Commons Attribution license (reuse allowed)']
selected_videos = random.sample(cc_by_videos, 10)

with open('videos_dl.txt', 'w') as f:
    for url in selected_videos:
        f.write(f"{url}\n")
