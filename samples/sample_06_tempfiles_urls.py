import urllib.request


def download(url):
    with urllib.request.urlopen(url) as response:
        return response.read()


def save_cache(data):
    cache_path = "/tmp/app_cache.bin"
    with open(cache_path, "wb") as handle:
        handle.write(data)
    return cache_path


def scratch_dir():
    return "/tmp/app_scratch"


if __name__ == "__main__":
    print(save_cache(b"example"))
