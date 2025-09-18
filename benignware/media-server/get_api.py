#!/usr/bin/python3
import requests
import random
import argparse

def format(width):
    buckets = [720, 1280, 1920, 2560, 4096, 5120, 7680]
    if width <= buckets[0]:
        return buckets[0]

    for i in range(1, len(buckets)):
        if width < buckets[i]:
            return buckets[i - 1]

    return buckets[-1]
#    if width < 1280:
#        width = 720
#    elif width < 1920:
#        width = 1280
#    elif width < 2560:
#        width = 1920
#    elif width < 4096:
#        width = 2560
#    elif width < 5120:
#        width = 4096
#    elif width < 7680:
#        width = 5120
#    else:
#        width = 7680
#    return width

def login(host):
    # Step 1: login and get access token
    login_url = host+"/api/v1/session"
    login_data = {"username": "admin", "password": "secret123"}

    resp = requests.post(login_url, json=login_data)
    resp.raise_for_status()

    token = resp.json()["access_token"]
    return token

def index(host, token):
    url = host+"/api/v1/index"

    headers = {
            "X-Auth-Token": token,
            "Content-Type": "application/json"
            }
    payload = {
            "path": "/",
            "rescan":True,
            "cleanup":False
            }

    resp = requests.post(url, headers=headers, json=payload)
    print(f"{resp.status_code}: {resp.text}")

def get_api(host, token):
    # Step 2: use Bearer token to query photos
    photos_url = host+"/api/v1/photos?count=110"

    headers = {"X-Auth-Token": token}
    
    resp = requests.get(photos_url, headers=headers)
    resp.raise_for_status()
    
    photos = resp.json()
    url_exts = []
    for photo in photos:
        file_hash = photo["Hash"]
        file_name = photo["FileName"]
        file_root = photo["FileRoot"]
        if photo["Type"] == "video":
            width = photo["Width"]
            if file_root == "sidecar":
                width = format(int(width))
                url_ext = f"/api/v1/t/{file_hash}/pbuhhmb9/fit_{width}"
            elif file_root == "/":
                url_ext = f"/api/v1/videos/{file_hash}/pbuhhmb9/avc"
        elif photo["Type"].startswith("image"):
            url_ext = f"/api/v1/dl/{file_hash}?t=jhtw6p95"
        url_exts.append(url_ext)
    
    url_exts.append("/api/v1/photos?count=20")
    url_exts.append("/api/v1/photos?count=110")
    url_exts.append("/api/v1/folders/originals/?files=true&count=999&q=&all=")
    
    #for url in url_exts:
    #    resp = requests.get(f"{host}{url}", headers=headers)
    #    print(f"Status for {url}: {resp.status_code}")
    
    with open("photoprism.url","w") as f:
        for url in url_exts:
            f.write(url+'\n')

def get_parser():
    parser = argparse.ArgumentParser(description="Media Server Access")
    parser.add_argument('-s', '--server', help='Photoprism server host', default='localhost')
    parser.add_argument('-t', '--token', help='Authorization token', default=None)
    parser.add_argument('-l', '--login', help='Call Login', action="store_true")
    parser.add_argument('-i', '--index', help='Rescan/Index', action="store_true")
    parser.add_argument('-api', '--api-list', help='Get API List', action="store_true")
    return parser

def main():
    parser = get_parser()
    args = vars(parser.parse_args())

    host = f"http://{args['server']}:2342"
    token = args['token']
    authenticate = args['login']
    scan = args['index']
    fetch = args['api_list']

    if authenticate:
        token = login(host)
        print(token)

    if index or fetch:
        if token == None:
            token = login(host)

        if scan:
            index(host, token)

        if fetch:
            get_api(host, token)
        
if __name__=="__main__":
    main()
