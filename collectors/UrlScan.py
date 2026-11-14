import requests
from termcolor import colored
from urllib.parse import urlparse
from time import sleep

# urlscan.io public search API. Anonymous access: 1 request/second.
BASE_URL = "https://urlscan.io/api/v1/search/"
HEADERS = {"user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:88.0) Gecko/20100101 Firefox/88.0"}
MAX_PAGES = 10


def extract_hostnames(result):
    hostnames = set()

    for key in ("domain",):
        value = result.get("task", {}).get(key)
        if value:
            hostnames.add(value.lower().rstrip("."))

    page = result.get("page", {})
    for key in ("domain",):
        value = page.get(key)
        if value:
            hostnames.add(value.lower().rstrip("."))

    value = page.get("url")
    if value:
        hostnames.add(urlparse(value).netloc.lower().rstrip("."))

    return hostnames


def init(domain):
    US = set()

    print(colored("[*]-Searching urlscan.io...", "yellow"))

    try:
        cursor = None
        pages = 0

        while pages < MAX_PAGES:
            params = {"q": "domain:{0}".format(domain), "size": 100}
            if cursor:
                params["cursor"] = cursor

            response = requests.get(BASE_URL, params=params, headers=HEADERS, timeout=30)

            if response.status_code == 429:
                print(colored("  \\__ Rate limited, stopping early.", "red"))
                break

            if response.status_code != 200:
                print(colored("  \\__ Error: {0}".format(response.status_code), "red"))
                return US

            data = response.json()

            for result in data.get("results", []):
                US |= extract_hostnames(result)

            pages += 1

            if not data.get("more_results_available"):
                break
            if not data.get("cursor"):
                break

            cursor = data["cursor"]
            sleep(1.2)  # anonymous rate limit is 1 request/second

    except requests.exceptions.RequestException as err:
        print(colored("  \\__ Error: {0}".format(err), "red"))
        return US

    except Exception:
        print(colored("  \\__ Something went wrong!", "red"))
        return US

    print(colored("  \\__ Subdomains found", "cyan") + ": " + colored(len(US), "yellow"))
    return US
