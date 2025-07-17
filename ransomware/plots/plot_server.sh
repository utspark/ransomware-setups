#!/bin/bash

sudo apt install -y python3 python3-pip libgl1-mesa-dev
pip3 install notebook pandas matplotlib PyQt5 PySide2
#pip3 install -r requirements.txt

nohup bash -c 'python3 -m notebook --port 9999 --no-browser' &> server.out &
