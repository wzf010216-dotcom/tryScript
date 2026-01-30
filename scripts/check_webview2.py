import os
import re
import urllib.parse
import urllib.request
import hashlib
import subprocess
import html as html_lib

WEBVIEW2_DOWNLOAD_PAGES = [
    "https://developer.microsoft.com/microsoft-edge/webview2",
    "https://developer.microsoft.com/en-us/microsoft-edge/webview2",
]
WEBVIEW2_USER_AGENT = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/120.0.0.0 Safari/537.36"
)

ARCHES = ["x86", "x64", "arm64"]

FIXED_REGEX = re.compile(
    r"fixedversionruntime\.(\d+\.\d+\.\d+\.\d+)\.(x86|x64|arm64)\.cab$",
    re.IGNORECASE,
)
EVERGREEN_FWLINKS = {
    "x86": "https://go.microsoft.com/fwlink/?linkid=2099617",
    "x64": "https://go.microsoft.com/fwlink/?linkid=2124701",
    "arm64": "https://go.microsoft.com/fwlink/?linkid=2099616",
}


def version_key(value):
    return [int(x) for x in value.split(".")]


def normalize_arch(value):
    if not value:
        return None
    value = value.lower()
    if value in ARCHES:
        return value
    return None


def get_latest_tag_version():
    try:
        output = subprocess.check_output(
            ["git", "tag", "--list", "v*", "--sort=-version:refname"],
            text=True,
        )
    except Exception:
        return None

    for line in output.splitlines():
        match = re.match(r"^v(\d+\.\d+\.\d+\.\d+)$", line.strip())
        if match:
            return match.group(1)
    return None


def extract_fixed_urls(html):
    normalized = html
    normalized = normalized.replace("\\u002F", "/").replace("\\u003A", ":")
    normalized = normalized.replace("\\u002f", "/").replace("\\u003a", ":")
    normalized = normalized.replace("\\/", "/")
    normalized = html_lib.unescape(normalized)
    fixed = {}
    urls = re.findall(r"https?://[^\"'\\s<>]+", normalized)
    urls += re.findall(
        r"//msedge\\.sf\\.dl\\.delivery\\.mp\\.microsoft\\.com/filestreamingservice/files/[^\"'\\s<>]+",
        normalized,
    )
    for match in urls:
        url = match.rstrip("\\")
        if url.startswith("//"):
            url = "https:" + url
        filename = filename_from_url(url)
        fixed_match = FIXED_REGEX.search(filename)
        if not fixed_match:
            continue
        version = fixed_match.group(1)
        arch = normalize_arch(fixed_match.group(2))
        if version and arch:
            fixed.setdefault(version, {})[arch] = url
    return fixed


def get_latest_release_artifacts():
    fixed = {}
    for page in WEBVIEW2_DOWNLOAD_PAGES:
        html = fetch_text(page)
        fixed = extract_fixed_urls(html)
        if fixed:
            break

    if not fixed:
        raise RuntimeError("No fixed version artifacts found on WebView2 download page")

    candidates = [
        version
        for version in fixed
        if all(arch in fixed.get(version, {}) for arch in ARCHES)
    ]

    if not candidates:
        raise RuntimeError("No fixed version has artifacts for all arches")

    latest = sorted(candidates, key=version_key)[-1]
    return latest, fixed[latest], EVERGREEN_FWLINKS.copy()


def resolve_url(url):
    try:
        req = urllib.request.Request(url, method="HEAD", headers=default_headers())
        with urllib.request.urlopen(req) as resp:
            return resp.geturl(), resp.headers.get("Content-Disposition")
    except Exception:
        req = urllib.request.Request(url, method="GET", headers=default_headers())
        with urllib.request.urlopen(req) as resp:
            return resp.geturl(), resp.headers.get("Content-Disposition")


def download(url, path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    print(f"Downloading {path}")
    urllib.request.urlretrieve(url, path)


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def set_output(name, value):
    output_path = os.environ.get("GITHUB_OUTPUT")
    if not output_path:
        return
    with open(output_path, "a", encoding="utf-8") as f:
        f.write(f"{name}={value}\n")


def filename_from_headers(url, content_disposition):
    if content_disposition:
        match = re.search(r"filename\\*=UTF-8''([^;]+)", content_disposition)
        if match:
            return os.path.basename(urllib.parse.unquote(match.group(1)))
        match = re.search(r'filename=\"?([^\";]+)\"?', content_disposition)
        if match:
            return os.path.basename(match.group(1))
    return filename_from_url(url)


def filename_from_url(url):
    parsed = urllib.parse.urlparse(url)
    base = os.path.basename(parsed.path)
    return base or "download.bin"


def default_headers():
    return {
        "User-Agent": WEBVIEW2_USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Accept-Encoding": "identity",
    }


def fetch_text(url):
    req = urllib.request.Request(url, headers=default_headers())
    with urllib.request.urlopen(req) as resp:
        content = resp.read()
        encoding = (resp.headers.get("Content-Encoding") or "").lower()
        if encoding in ("gzip", "x-gzip"):
            import gzip

            content = gzip.decompress(content)
        elif encoding == "deflate":
            import zlib

            content = zlib.decompress(content)
        elif encoding == "br":
            try:
                import brotli  # type: ignore

                content = brotli.decompress(content)
            except Exception:
                pass
        if os.environ.get("WEBVIEW2_DEBUG"):
            print(
                "Fetched",
                resp.geturl(),
                "status",
                getattr(resp, "status", "unknown"),
                "bytes",
                len(content),
                "content-type",
                resp.headers.get("Content-Type"),
            )
        text = content.decode("utf-8", errors="ignore")
        if os.environ.get("WEBVIEW2_DUMP_HTML"):
            os.makedirs("dist", exist_ok=True)
            with open("dist/webview2.html", "w", encoding="utf-8") as f:
                f.write(text)
        return text


def main():
    latest, fixed_urls, evergreen_urls = get_latest_release_artifacts()
    print(f"Latest WebView2 fixed version: {latest}")

    current_tag = get_latest_tag_version()
    print(f"Latest git tag version: {current_tag}")

    set_output("version", latest)

    if latest == current_tag:
        print("Version unchanged; exiting.")
        set_output("updated", "false")
        return

    checksums = []

    # Fixed Version (from WebView2 download page)
    for arch in ARCHES:
        url = fixed_urls[arch]
        final_url, content_disposition = resolve_url(url)
        filename = filename_from_headers(final_url, content_disposition)
        path = os.path.join("dist", filename)
        download(final_url, path)
        checksums.append((os.path.basename(path), sha256(path)))

    # Evergreen Installer (from WebView2 fwlinks)
    for arch in ARCHES:
        url = evergreen_urls[arch]
        final_url, content_disposition = resolve_url(url)
        filename = filename_from_headers(final_url, content_disposition)
        path = os.path.join("dist", filename)
        download(final_url, path)
        checksums.append((os.path.basename(path), sha256(path)))

    with open("dist/SHA256SUMS.txt", "w", encoding="utf-8") as f:
        for name, sumv in checksums:
            f.write(f"{sumv}  {name}\n")

    set_output("updated", "true")


if __name__ == "__main__":
    main()
