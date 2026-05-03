#!/bin/bash

echo "This should run on the machine that serves as a workload generator (node-1)"
sudo apt update
sudo apt install -y wrk python3 python3-pip
pip install requests

# Download videos
#./process_videos.py
echo "we assume a predefined list of youtube videos in videos_dl.txt"
echo "if this does not exist, please create a list of videos by running ./get_videos.py"
mkdir -p ~/shared/home/media

# Download youtube downloader
sudo wget https://github.com/yt-dlp/yt-dlp/releases/latest/download/yt-dlp_linux -O yt-dlp
sudo chmod a+rx yt-dlp
./yt-dlp -f bestvideo+bestaudio --merge-output-format mp4 --concurrent-fragments 16 -o '~/shared/home/media/%(title)s.%(ext)s' -a videos_dl.txt

# Copy some photos over
cp ~/shared/home/000/*.png ~/shared/home/media/
cp ~/shared/home/000/*.jpg ~/shared/home/media/