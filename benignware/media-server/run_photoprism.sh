#!/bin/bash
sudo apt install -y ffmpeg yt-dlp libvips-dev libimage-exiftool-perl sqlite3
sudo apt update
sudo apt install -y ffmpeg yt-dlp libvips-dev libimage-exiftool-perl sqlite3
sudo apt install -y tshark
pip3 install -r requirements.txt

# Download videos
#./process_videos.py
#mkdir -p ~/shared/home/media
#yt-dlp -f bestvideo+bestaudio --merge-output-format mp4 --concurrent-fragments 16 -o '~/shared/home/media/%(title)s.%(ext)s' -a videos_dl.txt
#cp ~/shared/home/000/*.png ~/shared/home/media/
#cp ~/shared/home/000/*.jpg ~/shared/home/media/

## Install photoprism
curl -sLO https://dl.photoprism.app/pkg/linux/deb/amd64.deb
sudo dpkg -i amd64.deb

sudo sed -i '/OriginalsPath/c\OriginalsPath: \"/mnt/home/media\"' /etc/photoprism/defaults.yml
sudo sed -i '/ImportPath/c\ImportPath: \"/mnt/home/import\"' /etc/photoprism/defaults.yml
sudo sed -i '/AdminPassword/c\AdminPassword: \"secret123\"' /etc/photoprism/defaults.yml
sudo sed -i '/HttpHost/c\HttpHost: \"0.0.0.0\"' /etc/photoprism/defaults.yml

photoprism start



