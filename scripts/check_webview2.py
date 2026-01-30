import json
import os
import re
import urllib.parse
import urllib.request
import hashlib
import subprocess

EDGE_PRODUCTS_API = "https://edgeupdates.microsoft.com/api/products"

ARCHES = ["x86", "x64", "arm64"]

FIXED_REGEX = re.compile(
    r"fixedversionruntime\.(\d+\.\d+\.\d+\.\d+)\.(x86|x64|arm64)\.cab$",
    re.IGNORECASE,
)
EVERGREEN_REGEX = re.compile(
    r"webview2runtimeinstaller(arm64|x64|x86)\.exe$",
    re.IGNORECASE,
)


def parse_version(value):
    if not value:
        return None
    match = re.search(r"\d+\.\d+\.\d+\.\d+", str(value))
    return match.group(0) if match else None


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


def get_latest_release_artifacts():
    with urllib.request.urlopen(EDGE_PRODUCTS_API) as resp:
        data = json.load(resp)

    fixed = {}
    evergreen = {}

    for product in data:
        product_name = (product.get("Product") or "").lower()
        if "webview2" not in product_name:
            continue

        for release in product.get("Releases", []):
            platform = release.get("Platform")
            if platform and platform != "Windows":
                continue

            channel = release.get("Channel")
            if channel and channel != "Stable":
                continue

            release_arch = normalize_arch(release.get("Architecture") or release.get("Arch"))
            release_version = (
                parse_version(release.get("ProductVersion"))
                or parse_version(release.get("Version"))
            )

            for artifact in release.get("Artifacts", []):
                location = artifact.get("Location")
                if not location:
                    continue

                filename = filename_from_url(location)

                fixed_match = FIXED_REGEX.search(filename)
                if fixed_match:
                    version = fixed_match.group(1)
                    arch = normalize_arch(fixed_match.group(2))
                    if version and arch:
                        fixed.setdefault(version, {})[arch] = location
                    continue

                evergreen_match = EVERGREEN_REGEX.search(filename)
                if evergreen_match:
                    arch = normalize_arch(evergreen_match.group(1)) or release_arch
                    version = parse_version(artifact.get("Version")) or release_version
                    if version and arch:
                        evergreen.setdefault(version, {})[arch] = location
                    continue

    if not fixed:
        raise RuntimeError("No fixed version artifacts found from edgeupdates API")

    candidates = [
        version
        for version in fixed
        if all(arch in fixed.get(version, {}) for arch in ARCHES)
        and all(arch in evergreen.get(version, {}) for arch in ARCHES)
    ]

    if not candidates:
        raise RuntimeError("No release has complete fixed + evergreen artifacts for all arches")

    latest = sorted(candidates, key=version_key)[-1]
    return latest, fixed[latest], evergreen[latest]


def head_check(url):
    req = urllib.request.Request(url, method="HEAD")
    urllib.request.urlopen(req)


def download(url, path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    head_check(url)
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

    # Fixed Version (from edgeupdates artifacts)
    for arch in ARCHES:
        url = fixed_urls[arch]
        filename = filename_from_url(url)
        path = os.path.join("dist", filename)
        download(url, path)
        checksums.append((os.path.basename(path), sha256(path)))

    # Evergreen Installer (from edgeupdates artifacts)
    for arch in ARCHES:
        url = evergreen_urls[arch]
        filename = filename_from_url(url)
        path = os.path.join("dist", filename)
        download(url, path)
        checksums.append((os.path.basename(path), sha256(path)))

    with open("dist/SHA256SUMS.txt", "w", encoding="utf-8") as f:
        for name, sumv in checksums:
            f.write(f"{sumv}  {name}\n")

    set_output("updated", "true")


if __name__ == "__main__":
    main()
