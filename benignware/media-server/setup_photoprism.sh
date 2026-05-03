#!/bin/bash

echo "This script runs on the client/machine which is tracing benign workloads"
sudo apt update
sudo apt install -y ffmpeg libvips-dev libimage-exiftool-perl sqlite3 python3 python3-pip
pip3 install -r requirements.txt

## Install photoprism
curl -sLO https://dl.photoprism.app/pkg/linux/deb/amd64.deb
sudo dpkg -i amd64.deb
rm amd64.deb

sudo sed -i '/OriginalsPath/c\OriginalsPath: \"/mnt/home/media\"' /etc/photoprism/defaults.yml
sudo sed -i '/ImportPath/c\ImportPath: \"/mnt/home/import\"' /etc/photoprism/defaults.yml
sudo sed -i '/AdminPassword/c\AdminPassword: \"secret123\"' /etc/photoprism/defaults.yml
sudo sed -i '/HttpHost/c\HttpHost: \"0.0.0.0\"' /etc/photoprism/defaults.yml