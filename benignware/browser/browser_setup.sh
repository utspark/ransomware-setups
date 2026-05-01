#!/bin/bash
pip install playwright
sudo apt-get install -y libx11-xcb1 libnss3 libatk-bridge2.0-0 libxcomposite1 libxdamage1 libxrandr2 libgbm1 libasound2
python -m playwright install --with-deps
