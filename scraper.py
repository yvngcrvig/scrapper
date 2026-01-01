import requests
import esprima
from bs4 import BeautifulSoup
import json
import re
from urllib.parse import urljoin, urlparse

from playwright.sync_api import sync_playwright

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
}

API_REGEX = re.compile(
    r'(/api/[a-zA-Z0-9/_\-]+|/auth/[a-zA-Z0-9/_\-]+|/graphql)',
    re.IGNORECASE
)


def is_same_domain(base, url):
    return urlparse(base).netloc == urlparse(url).netloc


def fetch(url):
    try:
        r = requests.get(url, headers=HEADERS, timeout=10)
        if r.status_code == 200:
            return r.text
    except:
        pass
    return None


def extract_links(html, base_url):
    soup = BeautifulSoup(html, "lxml")
    links = set()

    for a in soup.find_all("a", href=True):
        full = urljoin(base_url, a["href"])
        if is_same_domain(base_url, full):
            links.add(full)

    return links, soup


def extract_js_sources(soup, base_url):
    js_files = set()
    for script in soup.find_all("script", src=True):
        js_files.add(urljoin(base_url, script["src"]))
    return js_files


def extract_api_paths(text):
    return set(API_REGEX.findall(text))


def extract_api_from_ast(js_text):
    api = set()
    try:
        ast = esprima.parseScript(js_text, tolerant=True).toDict()
    except:
        return api

    def walk(node):
        if isinstance(node, dict):
            if node.get("type") == "CallExpression":
                callee = node.get("callee")
                args = node.get("arguments", [])

                if callee and callee.get("name") == "fetch":
                    if args and args[0].get("type") == "Literal":
                        api.add(str(args[0]["value"]))

                if callee and callee.get("type") == "MemberExpression":
                    if callee.get("object", {}).get("name") == "axios":
                        if args and args[0].get("type") == "Literal":
                            api.add(str(args[0]["value"]))

            for v in node.values():
                walk(v)

        elif isinstance(node, list):
            for i in node:
                walk(i)

    walk(ast)
    return api


def playwright_network_scan(url, found_api):
    print("\n[Playwright] Network scan start")

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context()
        page = context.new_page()

        def handle_request(req):
            u = req.url
            if any(x in u for x in ["/api/", "/auth/", "/graphql"]):
                parsed = urlparse(u)
                found_api.add(parsed.path)

        page.on("request", handle_request)

        try:
            page.goto(url, wait_until="networkidle", timeout=15000)
        except:
            pass

        browser.close()

    print("[Playwright] Network scan done")


def build_backend_tree(api_set):
    tree = {}
    for path in api_set:
        if not path.startswith("/"):
            continue
        parts = [p for p in path.split("/") if p]
        cur = tree
        for part in parts:
            cur = cur.setdefault(part, {})
    return tree


def classify_api(api_set):
    out = {
        "auth": [],
        "user": [],
        "data": [],
        "graphql": [],
        "other": []
    }

    for api in api_set:
        low = api.lower()
        if "graphql" in low:
            out["graphql"].append(api)
        elif any(x in low for x in ["login", "logout", "auth", "token", "register"]):
            out["auth"].append(api)
        elif any(x in low for x in ["user", "profile", "account", "me"]):
            out["user"].append(api)
        elif any(x in low for x in ["list", "get", "fetch", "data"]):
            out["data"].append(api)
        else:
            out["other"].append(api)

    return out


def main():
    print("=" * 50)
    print("Simple Scrap :-DD")
    print("=" * 50)

    start_url = input("Sem napis URL: ").strip()

    if not start_url.startswith("http"):
        print("Zkus to znovu a lepe, bartard...")
        return

    visited = set()
    to_visit = {start_url}

    found_pages = set()
    found_js = set()
    found_api = set()

    while to_visit and len(visited) < 10:
        url = to_visit.pop()
        if url in visited:
            continue

        print(f"Hledam: {url}")
        visited.add(url)

        html = fetch(url)
        if not html:
            continue

        found_pages.add(url)

        links, soup = extract_links(html, url)
        to_visit.update(links)

        found_js.update(extract_js_sources(soup, url))
        found_api.update(extract_api_paths(html))

    for js in found_js:
        js_text = fetch(js)
        if not js_text:
            continue
        found_api.update(extract_api_paths(js_text))
        found_api.update(extract_api_from_ast(js_text))

    # 🔥 PLAYWRIGHT NETWORK
    playwright_network_scan(start_url, found_api)

    backend_tree = build_backend_tree(found_api)
    classified = classify_api(found_api)

    backend_map = {
        "start_url": start_url,
        "stats": {
            "pages": len(found_pages),
            "js_files": len(found_js),
            "api_total": len(found_api)
        },
        "api_tree": backend_tree,
        "api_groups": classified
    }

    with open("scraped_web_lmfao.json", "w", encoding="utf-8") as f:
        json.dump({
            "pages_scanned": list(found_pages),
            "js_files": list(found_js),
            "api_candidates": sorted(found_api)
        }, f, ensure_ascii=False, indent=2)

    with open("backend_map.json", "w", encoding="utf-8") as f:
        json.dump(backend_map, f, ensure_ascii=False, indent=2)

    print("\nHotovo")
    print(f"Nalezeno API: {len(found_api)}")


if __name__ == "__main__":
    main()
