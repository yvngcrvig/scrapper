import subprocess
import sys

packages = [
    "requests",
    "beautifulsoup4",
    "lxml",
    "esprima",
    "playwright"
]

for p in packages:
    print(f"[+] Instaluji {p}")
    subprocess.check_call([sys.executable, "-m", "pip", "install", p])

print("[+] Instaluji Playwright Chromium")
subprocess.check_call([sys.executable, "-m", "playwright", "install", "chromium"])

print("Hotovo :-DDD rdy to use")
