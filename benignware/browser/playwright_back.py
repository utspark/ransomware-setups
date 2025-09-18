#!/usr/bin/python3
from playwright.sync_api import sync_playwright
import os
import time

dl_urls = [
        ("https://nbg1-speed.hetzner.com","100MB.bin"),
        ("https://www.thinkbroadband.com/download","http://ipv4.download.thinkbroadband.com/10MB.zip"),
        ("https://www.thinkbroadband.com/download","http://ipv4.download.thinkbroadband.com/20MB.zip"),
        ("https://www.thinkbroadband.com/download","http://ipv4.download.thinkbroadband.com:8080/50MB.zip"),
        ("https://www.thinkbroadband.com/download","http://ipv4.download.thinkbroadband.com/200MB.zip"),
        ("https://nbg1-speed.hetzner.com","1GB.bin"),
        #"https://webassembly.org/demo/crypto/",  # crypto wasm demo
        ]

def download(dl_path):
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(accept_downloads=True)

        #pages = [context.new_page() for _ in range(5)]  # simulate multi-user
        page = context.new_page()

        #for page in pages:
        for site,link in dl_urls:
            print(link)
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

        #    # For video pages, simulate playback
        #    if url.endswith(".mp4"):
        #        page.evaluate("document.querySelector('video').play()")

        browser.close()

vid_urls = [
        "https://www.youtube.com/watch?v=Gs2riblDG5A&list=RDGs2riblDG5A",
        "https://www.youtube.com/watch?v=AB-I3vsUk6g&list=RDAB-I3vsUk6g",
        "https://www.youtube.com/watch?v=AMuRRXCuy-4&list=RDAMuRRXCuy-4",
        ]

def stream_benchmark():
    with sync_playwright() as p:
        browser = p.chromium.launch(
                headless=True,
                args=[
                    "--mute-audio",  # disable audio to avoid device issues
                    "--autoplay-policy=no-user-gesture-required",
                    ],
                )
        context = browser.new_context()
        page = context.new_page()

        for url in vid_urls:
            print(f"Navigating to {url}")
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

            # Optional: check if video element exists and is playing
            is_playing = page.evaluate("""
                () => {
                        const video = document.querySelector('video');
                    return video ? (!video.paused && !video.ended && video.currentTime > 0) : false;
                }
            """)
            print(f"Video is playing: {is_playing}")
            playtime = page.evaluate("""
                () => {
                    const video = document.querySelector('video');
                    return video ? video.currentTime : 0;
                }
            """)
            print(f"Video time: {playtime}")

        browser.close()

wasm_urls = [
        "https://bradyjoslin.github.io/webcrypto-example",
        "https://diafygi.github.io/webcrypto-examples",
        "https://mayfield.github.io/webbench/pages/bench.html",
        ]

def wasm_crypto_benchmark(wait_time=5):
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context()
        page = context.new_page()

        for url in wasm_urls:
            print(f"Visiting: {url}")
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

        browser.close()

gen_urls = [
        "https://www.amazon.com",
        "https://scholar.google.com/citations?user=ua5NN3YAAAAJ&hl=en",
        "https://en.wikipedia.org/wiki/Homi_J._Bhabha",
        ]

def browse_general():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context()
        page = context.new_page()
        
        for url in gen_urls:
            print(url)
            page.goto(url, wait_until="load")
            time.sleep(1)
            #page.screenshot(path=f"{url}.png", animations="disabled", full_page=True, caret="hide",  omit_background=False, timeout=0)

        browser.close()

browse_type = None

if browse_type == "download":
    DOWNLOAD_DIR = "playwright_download"
    os.makedirs(DOWNLOAD_DIR, exist_ok=True)
    download(DOWNLOAD_DIR)
elif browse_type == "stream":
    stream_benchmark()
elif browse_type == "wasm":
    wasm_crypto_benchmark()
else:
    browse_general()
