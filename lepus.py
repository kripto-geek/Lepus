#!/usr/bin/env python3

from argparse import ArgumentParser, FileType
from warnings import simplefilter
from termcolor import colored
from time import sleep, time
from gc import collect
import asyncio
import importlib
import pkgutil
import sys
import collectors
import submodules.Permutations
import submodules.PortScan
import submodules.ReverseLookups
import submodules.TakeOver
import submodules.Markov
import submodules.TechnologyProfiler
import submodules.VulnerabilityScanner
import submodules.InterestingSubdomainDetector
import submodules.SensitiveFileScanner
import submodules.DirectoryBruteforcer
import submodules.Intelligence
import utilities.DatabaseHelpers
import utilities.Reporting
import utilities.MiscHelpers
import utilities.ScanHelpers
import threading

simplefilter("ignore")
version = "3.6.1"


class _ThreadLocalStdout:
    """Thread-safe stdout wrapper: prefixes worker-thread output with the
    collector's name and serializes writes so concurrent collectors don't
    garble each other's lines."""

    def __init__(self, original):
        self._original = original
        self._lock = threading.Lock()
        self._local = threading.local()

    def set_label(self, label):
        self._local.label = label
        self._local.at_line_start = True

    def clear_label(self):
        self._local.label = None

    def write(self, data):
        label = getattr(self._local, "label", None)
        with self._lock:
            if not label:
                return self._original.write(data)
            for part in data.splitlines(keepends=True):
                if self._local.at_line_start and part and part != "\n":
                    self._original.write(colored(f"[{label}] ", "cyan"))
                self._original.write(part)
                if part.endswith("\n") or part == "":
                    self._local.at_line_start = True
                else:
                    self._local.at_line_start = False
            self._original.flush()

    def flush(self):
        self._original.flush()

    def fileno(self):
        return self._original.fileno()

    def isatty(self):
        return self._original.isatty()


_saved_stdout = sys.stdout
_thread_stdout = _ThreadLocalStdout(sys.stdout)
sys.stdout = _thread_stdout


def printBanner():
    print(colored("         ______  _____           ______", "yellow"))
    print(colored(" |      |______ |_____) |     | (_____ ", "yellow"))
    print(colored(" |_____ |______ |       |_____| ______)", "yellow"))
    print(colored("                                v{0}".format(version), "cyan"))
    sleep(0.5)


def discover_collectors():
    collector_modules = []
    for importer, modname, ispkg in pkgutil.iter_modules(collectors.__path__):
        if modname.startswith("_"):
            continue
        try:
            mod = importlib.import_module(f"collectors.{modname}")
            if hasattr(mod, "init"):
                collector_modules.append(mod)
        except Exception as e:
            print(colored(f"  \\__ Failed to load collector {modname}: {e}", "red"))
    return collector_modules


_collector_stats = {}
_collector_lock = threading.Lock()


def run_collector_sync(collector_mod, domain):
    name = collector_mod.__name__.split(".")[-1]
    sys.stdout.set_label(name)
    try:
        results = collector_mod.init(domain)
        count = len(results) if results else 0
        error = None
    except Exception as e:
        print(colored(f"  \\__ error: {e}", "red"))
        count, results, error = 0, [], e
    finally:
        sys.stdout.clear_label()

    with _collector_lock:
        _collector_stats[name] = {"count": count, "error": error}

    return list(results) if results else []


async def run_collectors_concurrent(domain, timeout):
    global _collector_stats
    _collector_stats = {}

    collector_list = discover_collectors()
    print(colored(f"  \\__ Running {len(collector_list)} collectors concurrently (timeout: {timeout}s)...", "cyan"))

    loop = asyncio.get_event_loop()
    tasks = {}
    for cm in collector_list:
        fut = loop.run_in_executor(None, run_collector_sync, cm, domain)
        tasks[cm.__name__.split(".")[-1]] = fut

    all_subdomains = []
    deadline = time() + timeout
    while tasks:
        remaining = deadline - time()
        if remaining <= 0:
            break
        done, _ = await asyncio.wait(tasks.values(), timeout=remaining, return_when="FIRST_COMPLETED")
        if not done:
            break
        for fut in done:
            name = next(n for n, f in tasks.items() if f == fut)
            del tasks[name]
            try:
                r = fut.result()
                if isinstance(r, list):
                    all_subdomains.extend(r)
            except Exception:
                pass
            pending = len(tasks)
            if pending > 0:
                print(colored(f"    \\__ {name}: done ({pending} remaining)", "cyan"))

    if tasks:
        for fut in tasks.values():
            fut.cancel()
        for name in list(tasks):
            with _collector_lock:
                _collector_stats[name] = {"count": 0, "error": "timed out"}
        print(colored(f"    \\__ {len(tasks)} collectors timed out after {timeout}s and were skipped", "red"))

    print()
    # Print summary table in module order
    if _collector_stats:
        print(colored("  \\__ Collector Summary:", "cyan"))
        found_any = [(n, s["count"]) for n, s in _collector_stats.items() if s["error"] is None and s["count"] > 0]
        found_none = [n for n, s in _collector_stats.items() if s["error"] is None and s["count"] == 0]
        failed = [(n, s["error"]) for n, s in _collector_stats.items() if s["error"] is not None]
        for name, count in found_any:
            print(f"      {colored('OK', 'green'):>6}  {name:<20} {colored(str(count), 'yellow'):>5} subdomains")
        for name in found_none:
            print(f"      {colored('--', 'yellow'):>6}  {name:<20} {colored('0', 'red'):>5} subdomains")
        for name, error in failed:
            print(f"      {colored('!!', 'red'):>6}  {name:<20} {colored(str(error), 'red'):>5}")

    return all_subdomains


if __name__ == "__main__":
    parser = ArgumentParser(prog="lepus.py", description="Infrastructure OSINT")
    parser.add_argument("domain", help="domain to search")
    parser.add_argument("-w", "--wordlist", action="store", dest="wordlist", help="wordlist with subdomains", type=FileType("r"))
    parser.add_argument("-hw", "--hide-wildcards", action="store_true", dest="hideWildcards", help="hide wildcard resolutions", default=False)
    parser.add_argument("-t", "--threads", action="store", dest="threads", help="number of threads [default is 200]", type=int, default=200)
    parser.add_argument("-nc", "--no-collectors", action="store_true", dest="noCollectors", help="skip passive subdomain enumeration", default=False)
    parser.add_argument("--collector-timeout", action="store", dest="collector_timeout", help="max seconds to wait for all collectors [default is 300]", type=int, default=300)
    parser.add_argument("-zt", "--zone-transfer", action="store_true", dest="zoneTransfer", help="attempt to zone transfer from identified name servers", default=False)
    parser.add_argument("--permutate", action="store_true", dest="permutate", help="perform permutations on resolved domains", default=False)
    parser.add_argument("-pw", "--permutation-wordlist", dest="permutation_wordlist", help="wordlist to perform permutations with [default is lists/words.txt]", type=FileType("r"), default="lists/words.txt")
    parser.add_argument("--reverse", action="store_true", dest="reverse", help="perform reverse dns lookups on resolved public IP addresses", default=False)
    parser.add_argument("-ripe", "--ripe", action="store_true", dest="ripe", help="query ripe database with the 2nd level domain for networks to be used for reverse lookups", default=False)
    parser.add_argument("-r", "--ranges", action="store", dest="ranges", help="comma separated ip ranges to perform reverse dns lookups on", type=str, default=None)
    parser.add_argument("-or", "--only-ranges", action="store_true", dest="only_ranges", help="use only ranges provided with -r or -ripe and not all previously identified IPs", default=False)
    parser.add_argument("--portscan", action="store_true", dest="portscan", help="scan resolved public IP addresses for open ports", default=False)
    parser.add_argument("-p", "--ports", action="store", dest="ports", help="set of ports to be used by the portscan module [default is medium]", type=str)
    parser.add_argument("--takeover", action="store_true", dest="takeover", help="check identified hosts for potential subdomain take-overs", default=False)
    parser.add_argument("--tech-profile", action="store_true", dest="tech_profile", help="perform technology profiling on resolved domains", default=False)
    parser.add_argument("--vuln-scan", action="store_true", dest="vuln_scan", help="perform vulnerability scanning on resolved domains", default=False)
    parser.add_argument("--interesting", action="store_true", dest="interesting", help="detect interesting subdomains", default=False)
    parser.add_argument("--sensitive-scan", action="store_true", dest="sensitive_scan", help="scan for sensitive files", default=False)
    parser.add_argument("--dir-brute", action="store_true", dest="dir_brute", help="perform directory and file brute-forcing", default=False)
    parser.add_argument("--intelligence", action="store_true", dest="intelligence", help="run intelligence module to correlate findings", default=False)
    parser.add_argument("--markovify", action="store_true", dest="markovify", help="use markov chains to identify more subdomains", default=False)
    parser.add_argument("-ms", "--markov-state", action="store", dest="markov_state", help="markov state size [default is 3]", type=int, default=3)
    parser.add_argument("-ml", "--markov-length", action="store", dest="markov_length", help="max length of markov substitutions [default is 5]", type=int, default=5)
    parser.add_argument("-mq", "--markov-quantity", action="store", dest="markov_quantity", help="max quantity of markov results per candidate length [default is 5]", type=int, default=5)
    parser.add_argument("-f", "--flush", action="store_true", dest="doFlush", help="purge all records of the specified domain from the database", default=False)
    parser.add_argument("--json-report", action="store_true", dest="json_report", help="generate JSON report", default=False)
    parser.add_argument("--html-report", action="store_true", dest="html_report", help="generate HTML report", default=False)
    parser.add_argument("--diff", action="store_true", dest="diff", help="show changes compared to previous scan", default=False)
    parser.add_argument("--telegram-token", action="store", dest="telegram_token", help="Telegram bot token for notifications", default=None)
    parser.add_argument("--telegram-chat", action="store", dest="telegram_chat_id", help="Telegram chat ID for notifications", default=None)
    parser.add_argument("--slack-token", action="store", dest="slack_token", help="Slack API token for notifications", default=None)
    parser.add_argument("--slack-channel", action="store", dest="slack_channel", help="Slack channel for notifications", default=None)
    parser.add_argument("-v", "--version", action="version", version="Lepus v{0}".format(version))
    args = parser.parse_args()

    if not utilities.MiscHelpers.checkArgumentValidity(parser, args):
        exit(1)

    printBanner()
    db = utilities.DatabaseHelpers.init()

    if args.doFlush:
        utilities.MiscHelpers.purgeOldFindings(db, args.domain)
        print("{0} {1} {2}".format(colored("\n[*]-Flushed", "yellow"), colored(args.domain, "cyan"), colored("from the database", "yellow")))
        exit(0)

    print("{0} {1}".format(colored("\n[*]-Running against:", "yellow"), colored(args.domain, "cyan")))

    old_resolved, old_unresolved, old_takeovers = utilities.MiscHelpers.loadOldFindings(db, args.domain)
    utilities.MiscHelpers.purgeOldFindings(db, args.domain)

    try:
        utilities.ScanHelpers.retrieveDNSRecords(db, args.domain)

        zt_subdomains = None
        if args.zoneTransfer:
            zt_subdomains = utilities.ScanHelpers.zoneTransfer(db, args.domain)

        collector_subdomains = None
        if not args.noCollectors:
            print()
            collector_subdomains = asyncio.run(run_collectors_concurrent(args.domain, args.collector_timeout))
            print(colored(f"  \\__ Total unique subdomains from collectors: {len(set(collector_subdomains))}", "green"))

        wordlist_subdomains = None
        if args.wordlist:
            wordlist_subdomains = utilities.MiscHelpers.loadWordlist(args.domain, args.wordlist)

        findings = utilities.MiscHelpers.cleanupFindings(
            args.domain, old_resolved, old_unresolved,
            zt_subdomains, collector_subdomains, wordlist_subdomains
        )

        del old_unresolved
        del zt_subdomains
        del collector_subdomains
        del wordlist_subdomains

        if findings:
            if len(findings) > 20000:
                print(colored(f"\n[!] WARNING: {len(findings)} candidate hostnames collected. A scan this large takes a long time to resolve.", "red"))
                print(colored("    If this looks wrong (e.g. junk from a misbehaving data source such as a bad subfinder", "red"))
                print(colored("    config), re-run with -nc / --no-collectors and clean up the offending source.", "red"))

            utilities.ScanHelpers.identifyWildcards(db, findings, args.domain, args.threads)
            utilities.ScanHelpers.massResolve(db, findings, args.domain, args.hideWildcards, args.threads)

            del findings

            if args.permutate:
                submodules.Permutations.init(db, args.domain, args.permutation_wordlist, args.hideWildcards, args.threads)

            if args.reverse:
                submodules.ReverseLookups.init(db, args.domain, args.ripe, args.ranges, args.only_ranges, args.threads)

            if args.markovify:
                submodules.Markov.init(db, args.domain, args.markov_state, args.markov_length, args.markov_quantity, args.hideWildcards, args.threads)

            utilities.ScanHelpers.massRDAP(db, args.domain, args.threads)

            if args.portscan:
                submodules.PortScan.init(db, args.domain, args.ports, args.threads)

            if args.takeover:
                submodules.TakeOver.init(db, args.domain, old_takeovers, args.threads)

            if args.tech_profile:
                submodules.TechnologyProfiler.init(db, args.domain, args.threads)

            if args.vuln_scan:
                submodules.VulnerabilityScanner.init(db, args.domain)

            if args.interesting:
                submodules.InterestingSubdomainDetector.init(db, args.domain)

            if args.sensitive_scan:
                asyncio.run(submodules.SensitiveFileScanner.init(db, args.domain))

            if args.dir_brute:
                submodules.DirectoryBruteforcer.init(db, args.domain)

            if args.intelligence:
                submodules.Intelligence.init(args.domain)

            if args.json_report:
                utilities.Reporting.generate_json_report(db, args.domain)

            if args.html_report:
                utilities.Reporting.generate_html_report(db, args.domain)

        utilities.MiscHelpers.exportFindings(db, args.domain, old_resolved, False)

        scan_timestamp = int(time())
        new_res, new_ports, new_tkos = utilities.MiscHelpers.compute_scan_diff(db, args.domain, scan_timestamp)

        if args.diff:
            print(colored("\n[*]-Scan Changes Since Last Run:", "yellow"))
            if new_res:
                for item in new_res:
                    print(colored(item, "green"))
            if new_ports:
                for item in new_ports:
                    print(colored(item, "green"))
            if new_tkos:
                for item in new_tkos:
                    print(colored(item, "red"))
            if not new_res and not new_ports and not new_tkos:
                print(colored("  \\__ No changes detected.", "cyan"))

        if new_tkos and args.telegram_token and args.telegram_chat_id:
            text = f"*Lepus Alert: New Takeover Vulnerabilities for {args.domain}*\n\n"
            for t in new_tkos:
                text += f"{t}\n"
            utilities.MiscHelpers.telegram_notification(args.telegram_token, args.telegram_chat_id, text)

    except KeyboardInterrupt:
        print(colored("\n[*]-Received keyboard interrupt! Shutting down...", "red"))
        utilities.MiscHelpers.exportFindings(db, args.domain, old_resolved, True)
        exit(-1)
