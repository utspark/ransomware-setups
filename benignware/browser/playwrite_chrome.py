#!/usr/bin/python3
from playwright.sync_api import sync_playwright
import os
import time
import argparse
import threading
import random
from concurrent.futures import ThreadPoolExecutor, as_completed

dl_path = "playwright_download"

def handle_download(page, pgid, category, urls):
    for site, link in urls:
        print(f"[{pgid}] {category}: {link}")
        page.goto(site)

        try:
            page.click("button:has-text('Accept')", timeout=3000)
            print("Clicked Accept")
        except:
            print("No consent popup")
        with page.expect_download() as download_info:
            page.click(f"a[href='{link}']")
        download = download_info.value

        suggested_name = download.suggested_filename
        output_path = os.path.join(dl_path, suggested_name)
        download.save_as(output_path)

def handle_streaming(page, pgid, category, urls):
    for url in urls:
        print(f"[{pgid}] {category}: {url}")
        page.goto(url, wait_until="networkidle")  # wait for network activity to settle

        # For YouTube, try to auto-play the video via JS
        try:
            page.evaluate("""
                () => {
                    const video = document.querySelector('video');
                    if (video) video.play().catch(e => console.log('Play failed', e));
                    return !!video;
                }
            """)
        except Exception as e:
            print("Error triggering play:", e)

        # Wait for a few seconds to simulate streaming load
        print("Streaming for 15 seconds...")
        time.sleep(15)

        is_playing = page.evaluate("""
            () => {
                const video = document.querySelector('video');
                return video ? (!video.paused && !video.ended && video.currentTime > 0) : false;
            }
        """)
        playtime = page.evaluate("""
            () => {
                const video = document.querySelector('video');
                return video ? video.currentTime : 0;
            }
        """)
        print(f"Video is playing({is_playing}) with time: {playtime}")

def handle_compute(page, pgid, category, urls, wait_time=5):
    for url in urls:
        print(f"[{pgid}] {category}: {url}")
        page.goto(url, wait_until="load")

        def handle_dialog(dialog):
            print("Dialog type:", dialog.type)
            print("Message:", dialog.message)
            if dialog.type == "prompt":
                dialog.accept("mySecretPassword")  # enter password here
            else:
                dialog.accept()

        page.on("dialog", handle_dialog)

        if page.query_selector("button:has-text('Encrypt')"):
            page.fill("#data", "This can be some long text file")
            page.click("button:has-text('Encrypt')")
            time.sleep(1)
            page.click("button:has-text('Decrypt')")
            time.sleep(1)

        elif page.query_selector('input[name="start"][type="button"][value="Start Benchmark"]'):
            button_selector = 'input[name="start"][type="button"][value="Start Benchmark"]'
            page.click(button_selector)

            status_selector = ".status"
            try:
                page.wait_for_function(
                        """selector => {
                        const el = document.querySelector(selector);
                        return el && el.textContent.includes("Completed");
                    }""",
                    arg=status_selector,
                    timeout=200000  # adjust timeout as needed
                    )
            except:
                print("Timedout waiting for computation.")
                pass
        else:
            print(f"No buttons found. Waiting {wait_time}s for computation to complete.")
            time.sleep(wait_time)

        #page.screenshot(path=f"wasm_{url.split('/')[-1]}.png", full_page=True)
        try:
            perf = page.evaluate("() => performance.now()")
            print(f"Page evaluated: {perf:.2f} ms")
        except:
            pass

def handle_generic(page, pgid, category, urls):
    for url in urls:
        print(f"[{pgid}] {category}: {url}")
        page.goto(url, wait_until="load")
        time.sleep(1)
        #page.screenshot(path=f"{url}.png", animations="disabled", full_page=True, caret="hide",  omit_background=False, timeout=0)

# Dispatch table
handlers = {
        "download": handle_download,
        "streaming": handle_streaming,
        "compute": handle_compute,
        "generic": handle_generic,
        }
dl_urls = [
        ("https://nbg1-speed.hetzner.com","100MB.bin"),
        ("https://www.thinkbroadband.com/download","http://ipv4.download.thinkbroadband.com/10MB.zip"),
        ("https://www.thinkbroadband.com/download","http://ipv4.download.thinkbroadband.com/20MB.zip"),
        ("https://www.thinkbroadband.com/download","http://ipv4.download.thinkbroadband.com:8080/50MB.zip"),
        ("https://www.thinkbroadband.com/download","http://ipv4.download.thinkbroadband.com/200MB.zip"),
        ("https://nbg1-speed.hetzner.com","1GB.bin"),
        ]
vid_urls = [
        "https://www.youtube.com/watch?v=Gs2riblDG5A&list=RDGs2riblDG5A",
        "https://www.youtube.com/watch?v=AB-I3vsUk6g&list=RDAB-I3vsUk6g",
        "https://www.youtube.com/watch?v=AMuRRXCuy-4&list=RDAMuRRXCuy-4",
        ]
wasm_urls = [
        "https://bradyjoslin.github.io/webcrypto-example",
        "https://diafygi.github.io/webcrypto-examples",
        "https://mayfield.github.io/webbench/pages/bench.html",
        ]
gen_urls = [
        "https://www.amazon.com",
        "https://scholar.google.com/citations?user=ua5NN3YAAAAJ&hl=en",
        "https://en.wikipedia.org/wiki/Homi_J._Bhabha",
        ]
urls_by_class = {
        "download": dl_urls,
        "streaming": vid_urls,
        "compute": wasm_urls,
        "generic": gen_urls,
        }

def run_tab(page, user_id, tab_id=1):
    page_id = f"User{user_id}-Tab{tab_id}"

    chosen_class = random.choice(list(urls_by_class.keys()))
    #chosen_urls = random.sample(urls_by_class[chosen_class], k=3)
    chosen_urls = urls_by_class[chosen_class]

    handler = handlers[chosen_class]
    handler(page, page_id, chosen_class, chosen_urls)

# ==== User worker (spawns T tabs) ====
def run_user(user_id, T):
    with sync_playwright() as playwright:
        print(f"User {user_id}: starting browser")
        browser = playwright.chromium.launch(headless=True, args=["--mute-audio","--autoplay-policy=no-user-gesture-required",])
        context = browser.new_context()

        #with ThreadPoolExecutor(max_workers=T) as tabs_pool:
        #    futures = []
        #    for t in range(T):
        #        page = context.new_page()
        #        futures.append(
        #                tabs_pool.submit(run_tab, page, list(URLS.keys()))
        #                )
        #    for f in futures:
        #        f.result()  # wait all tabs

        #threads = []
        #for tab_id in range(T):
        #    page = context.new_page()
        #    t = threading.Thread(target=run_tab, args=(page, user_id, tab_id))
        #    t.start()
        #    threads.append(t)

        ## Wait for all tabs of this user
        #for t in threads:
        #    t.join()
       
        for tab_id in range(T):
            page = context.new_page()
            run_tab(page, user_id)
            page.close()

        context.close()
        browser.close()
        print(f"User {user_id} finished all tabs")

def get_parser():
    parser = argparse.ArgumentParser(description="Browsing activity")
    parser.add_argument('-u', '--users', help='Users/Instances to simulate', default=1)
    parser.add_argument('-t', '--tabs', help='Tabs/Multi-pages to simulate', default=1)
    parser.add_argument('-wl', '--workload', help='Workload Type [download, streaming, compute, generic, mix', default="mix")
    parser.add_argument('-d', '--duration', help='Simulation time in s (Default 30s)', default=30)
    return parser

def main():
    parser = get_parser()
    args = vars(parser.parse_args())

    users = int(args['users'])
    tabs = int(args['tabs'])
    load_type = args['workload']
    duration = int(args['duration'])
    os.makedirs(dl_path, exist_ok=True)
    global urls_by_class

    if load_type != "mix":
        urls_by_class = {load_type: urls_by_class[load_type]}
    #with sync_playwright() as p:
    #    with ThreadPoolExecutor(max_workers=users) as users_pool:
    #        futures = [users_pool.submit(run_user, p, u, tabs) for u in range(users)]
    #        for f in futures:
    #            f.result()
    user_threads = []
    for user_id in range(users):
        t = threading.Thread(target=run_user, args=(user_id, tabs), daemon=True)
        t.start()
        user_threads.append(t)

    for t in user_threads:
        t.join()

    browse_type = None

if __name__=="__main__":
    main()
