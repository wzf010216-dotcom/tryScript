import json
import os
import re
import urllib.request
import hashlib

EDGE_PRODUCTS_API = "https://edgeupdates.microsoft.com/api/products"

ARCHES = ["x86", "x64", "arm64"]

EVERGREEN_MSI = {
    "x86": "https://go.microsoft.com/fwlink/?linkid=2124707",
    "x64": "https://go.microsoft.com/fwlink/?linkid=2124708",
    "arm64": "https://go.microsoft.com/fwlink/?linkid=2124709",
}


def get_latest_fixed_version():
    with urllib.request.urlopen(EDGE_PRODUCTS_API) as resp:
        data = json.load(resp)

    for product in data:
        if product.get("Product") == "WebView2":
            for release in product.get("Releases", []):
                if release.get("Channel") == "Stable":
                    version = release.get("ProductVersion")
                    if not re.match(r"^\d+\.\d+\.\d+\.\d+$", version):
                        raise RuntimeError(f"非法版本号: {version}")
                    return version

    raise RuntimeError("未找到 WebView2 Stable")


def head_check(url):
    req = urllib.request.Request(url, method="HEAD")
    urllib.request.urlopen(req)


def download(url, path):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    head_check(url)
    print(f"下载 {path}")
    urllib.request.urlretrieve(url, path)


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    latest = get_latest_fixed_version()
    print(f"最新版本: {latest}")

    current = None
    if os.path.exists("latest_version.txt"):
        current = open("latest_version.txt").read().strip()

    print(f"当前版本: {current}")

    if latest == current:
        print("版本未变化，退出")
        return

    checksums = []

    # Fixed Version
    for arch in ARCHES:
        url = (
            "https://msedge.sf.dl.delivery.mp.microsoft.com/"
            "filestreamingservice/files/"
            f"WebView2.Fixed.{latest}.{arch}.cab"
        )
        path = f"dist/WebView2.Fixed.{latest}.{arch}.cab"
        download(url, path)
        checksums.append((os.path.basename(path), sha256(path)))

    # Evergreen MSI
    for arch, url in EVERGREEN_MSI.items():
        path = f"dist/WebView2.Evergreen.{arch}.msi"
        download(url, path)
        checksums.append((os.path.basename(path), sha256(path)))

    with open("dist/SHA256SUMS.txt", "w") as f:
        for name, sumv in checksums:
            f.write(f"{sumv}  {name}\n")

    with open("latest_version.txt", "w") as f:
        f.write(latest)


if __name__ == "__main__":
    main()
