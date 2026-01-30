import os
import re
import urllib.parse
import urllib.request
import hashlib
import subprocess

WEBVIEW2_DOWNLOAD_PAGE = "https://developer.microsoft.com/microsoft-edge/webview2"

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
    fixed = {}
    for match in re.findall(r"https?://[^\"'\\s<>]+", html):
        url = match.rstrip("\\")
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
    with urllib.request.urlopen(WEBVIEW2_DOWNLOAD_PAGE) as resp:
        html = resp.read().decode("utf-8", errors="ignore")

    fixed = extract_fixed_urls(html)

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
        req = urllib.request.Request(url, method="HEAD")
        with urllib.request.urlopen(req) as resp:
            return resp.geturl(), resp.headers.get("Content-Disposition")
    except Exception:
        req = urllib.request.Request(url, method="GET")
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
